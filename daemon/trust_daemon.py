#!/usr/bin/env python3
"""
Kernel-Level Zero-Trust Traffic Isolation Engine — Dynamic Trust Decay Daemon (Phase 2)

Control Plane Daemon:
- Consumes wire-speed flow telemetry from eBPF ring buffer (BPF_RINGBUF_OUTPUT).
- Evaluates 1.0-second sliding-window behavioral heuristics (PPS, TCP SYNs, Port Entropy).
- Computes multi-tier trust score decay and autonomous self-healing (+6.0 pts/sec).
- Atomically mutates kernel policy_map in 15-45 microseconds (T_isolate).
- Automatically detects and attaches to bridge member ports (veth-*-br).
"""

import os
import sys
import time
import signal
import socket
import struct
import ctypes
from collections import deque
from bcc import BPF

# Linux Kernel XDP Attachment Flags (<linux/if_link.h>)
# 1 << 1 (value = 2) specifies Generic / SKB mode, required for virtual interfaces
XDP_FLAGS_SKB_MODE = getattr(BPF, "XDP_FLAGS_SKB_MODE", 1 << 1)

# Security States
STATE_TRUSTED = 0
STATE_SUSPECT = 1
STATE_QUARANTINED = 2

STATE_NAMES = {
    STATE_TRUSTED: "TRUSTED",
    STATE_SUSPECT: "SUSPECT",
    STATE_QUARANTINED: "QUARANTINED",
}

# Known Testbed IP Aliases
KNOWN_NODES = {
    "10.10.0.10": "Node A (Victim)",
    "10.10.0.20": "Node B (Legit)",
    "10.10.0.30": "Node C (Attacker)",
    "10.10.0.1":  "Bridge (br-xdp)",
}

# C Structure for Flow Telemetry Event (32 bytes, 8-byte aligned)
class FlowEvent(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("tcp_flags", ctypes.c_uint8),
        ("pkt_len", ctypes.c_uint16),
        ("state", ctypes.c_uint32),
        ("pad", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
    ]

def ip_to_u32(ip_str):
    return struct.unpack("I", socket.inet_aton(ip_str))[0]

def u32_to_ip(ip_u32):
    return socket.inet_ntoa(struct.pack("I", ip_u32))

def get_target_interfaces(iface_arg):
    """
    Returns the target member interfaces (veth-*-br) where inter-container traffic flows.
    Attaching directly to the veth endpoints intercepts packets at raw ingress before
    entering the bridge switch fabric.
    """
    interfaces = set()
    # Discover known testbed veth host endpoints
    for veth in ("veth-victim-br", "veth-legit-br", "veth-attack-br"):
        if os.path.exists(f"/sys/class/net/{veth}"):
            interfaces.add(veth)

    # Check bridge member directory
    brif_path = f"/sys/class/net/{iface_arg}/brif"
    if os.path.exists(brif_path):
        for port in os.listdir(brif_path):
            interfaces.add(port)

    # Fallback to bridge interface only if no member interfaces exist
    if not interfaces and os.path.exists(f"/sys/class/net/{iface_arg}"):
        interfaces.add(iface_arg)

    return sorted(list(interfaces))

def force_detach_interface(iface):
    """
    Guarantees a clean slate by removing any existing XDP programs (generic, driver, or offloaded)
    from the interface before attaching a new program. Prevents kernel EEXIST (File exists) errors.
    """
    for flags in (XDP_FLAGS_SKB_MODE, getattr(BPF, "XDP_FLAGS_DRV_MODE", 1 << 2), 0):
        try:
            BPF.remove_xdp(iface, flags)
        except Exception:
            pass
    os.system(f"ip link set dev {iface} xdpgeneric off 2>/dev/null")
    os.system(f"ip link set dev {iface} xdpdrv off 2>/dev/null")
    os.system(f"ip link set dev {iface} xdp off 2>/dev/null")

class WorkloadProfile:
    def __init__(self, ip_str):
        self.ip_str = ip_str
        self.trust_score = 100.0
        self.state = STATE_TRUSTED
        self.last_state_change = time.time()
        self.last_isolate_lat_us = 0.0

        # Current window statistics
        self.current_window_packets = 0
        self.current_window_syns = 0
        self.current_window_ports = set()

        # Cumulative counters
        self.total_packets_seen = 0
        self.last_pps = 0.0
        self.last_syn_pps = 0.0
        self.last_unique_ports = 0
        self.last_penalty = 0.0

    def record_event(self, event):
        # Sampled quarantined packets represent 64 raw frames
        pkt_weight = 64 if event.state == STATE_QUARANTINED else 1
        self.current_window_packets += pkt_weight
        self.total_packets_seen += pkt_weight

        # Check TCP SYN flag (0x02)
        if event.protocol == 6 and (event.tcp_flags & 0x02):
            self.current_window_syns += pkt_weight

        if event.dst_port != 0:
            self.current_window_ports.add(event.dst_port)

    def evaluate_window(self, dt):
        """
        Sliding-window evaluation: calculates PPS, SYN rate, port entropy,
        and applies mathematical trust decay or self-healing (+6.0 pts/sec).
        """
        self.last_pps = self.current_window_packets / dt if dt > 0 else 0.0
        self.last_syn_pps = self.current_window_syns / dt if dt > 0 else 0.0
        self.last_unique_ports = len(self.current_window_ports)

        # 1. Volumetric Flood Penalty: P_pps = min(45.0, max(0, PPS - 80) * 0.15)
        p_pps = min(45.0, max(0.0, self.last_pps - 80.0) * 0.15)

        # 2. TCP SYN Flood Penalty: P_syn = min(50.0, max(0, SYN - 25) * 0.45)
        p_syn = min(50.0, max(0.0, self.last_syn_pps - 25.0) * 0.45)

        # 3. Port Scan Penalty: P_scan = min(60.0, max(0, Ports - 6) * 4.50)
        p_scan = min(60.0, max(0.0, float(self.last_unique_ports - 6)) * 4.50)

        total_penalty = p_pps + p_syn + p_scan
        self.last_penalty = total_penalty

        # Self-Healing & Decay Update
        if total_penalty > 0:
            self.trust_score = max(0.0, self.trust_score - total_penalty)
        else:
            # Peaceful window: self-heal by +6.0 points/sec
            self.trust_score = min(100.0, self.trust_score + (6.0 * dt))

        # Reset current window metrics
        self.current_window_packets = 0
        self.current_window_syns = 0
        self.current_window_ports.clear()

        # Multi-Tier State Machine
        new_state = self.state
        if self.trust_score >= 70.0:
            new_state = STATE_TRUSTED
        elif self.trust_score >= 30.0:
            new_state = STATE_SUSPECT
        else:
            new_state = STATE_QUARANTINED

        return new_state

class DynamicTrustDaemon:
    def __init__(self, target_arg="br-xdp"):
        self.target_arg = target_arg
        self.running = True
        self.bpf = None
        self.fn = None
        self.attached_ifaces = []
        self.workloads = {}
        self.policy_map = None
        self.drop_map = None
        self.pass_map = None
        self.diag_map = None
        self.event_log = deque(maxlen=6)

        # Pre-register testbed nodes so they appear on dashboard immediately
        for ip in ("10.10.0.10", "10.10.0.20", "10.10.0.30"):
            self.workloads[ip] = WorkloadProfile(ip)

    def sync_interfaces(self):
        """
        Dynamically detects newly created bridge member ports and attaches XDP.
        """
        current_targets = get_target_interfaces(self.target_arg)
        for iface in current_targets:
            if iface not in self.attached_ifaces:
                try:
                    # Clean any existing or stale XDP attachment from interface first
                    force_detach_interface(iface)
                    self.bpf.attach_xdp(iface, self.fn, XDP_FLAGS_SKB_MODE)
                    self.attached_ifaces.append(iface)
                    ts = time.strftime("%H:%M:%S")
                    self.event_log.append(f"[{ts}] [+] Attached XDP to interface '{iface}'")
                except Exception as e:
                    ts = time.strftime("%H:%M:%S")
                    self.event_log.append(f"[{ts}] [-] Failed to attach to '{iface}': {e}")

    def load_and_attach(self):
        c_file = os.path.join(os.path.dirname(__file__), "../kernel/xdp_isolation_p2.c")
        if not os.path.exists(c_file):
            raise FileNotFoundError(f"Kernel C file not found: {c_file}")

        print(f"[*] Compiling Phase 2 Dynamic XDP filter: {c_file}...")
        self.bpf = BPF(src_file=c_file)
        self.fn = self.bpf.load_func("xdp_dynamic_filter", BPF.XDP)

        self.policy_map = self.bpf.get_table("policy_map")
        self.drop_map = self.bpf.get_table("drop_counter_map")
        self.pass_map = self.bpf.get_table("pass_counter_map")
        self.diag_map = self.bpf.get_table("diagnostic_counters")

        # Pre-clean all candidate devices before loading to guarantee clean slate
        for dev in ("veth-victim-br", "veth-legit-br", "veth-attack-br", "br-xdp"):
            if os.path.exists(f"/sys/class/net/{dev}"):
                force_detach_interface(dev)

        # Attach to available interfaces
        self.sync_interfaces()

        if not self.attached_ifaces:
            raise RuntimeError(f"Failed to attach XDP to any network interface for '{self.target_arg}'.")

        # Open eBPF Ring Buffer
        print("[*] Opening eBPF Ring Buffer telemetry stream...")
        self.bpf["telemetry_ringbuf"].open_ring_buffer(self._ringbuf_callback)
        print(f"[✓] Dynamic Trust Decay Engine initialized on: {', '.join(self.attached_ifaces)}")

    def _ringbuf_callback(self, ctx, data, size):
        event = ctypes.cast(data, ctypes.POINTER(FlowEvent)).contents
        ip_str = u32_to_ip(event.src_ip)

        # Ignore loopback/broadcast
        if ip_str.startswith("127.") or ip_str == "0.0.0.0" or ip_str == "255.255.255.255":
            return 0

        if ip_str not in self.workloads:
            self.workloads[ip_str] = WorkloadProfile(ip_str)

        self.workloads[ip_str].record_event(event)
        return 0

    def mutate_kernel_policy(self, profile, new_state):
        ip_int = ip_to_u32(profile.ip_str)
        ip_key = ctypes.c_uint32(ip_int)
        val = ctypes.c_uint32(new_state)

        # Measure mutation latency T_isolate in microseconds
        t0 = time.perf_counter_ns()
        self.policy_map[ip_key] = val
        t1 = time.perf_counter_ns()

        isolate_us = (t1 - t0) / 1000.0
        profile.last_isolate_lat_us = isolate_us
        old_state_str = STATE_NAMES.get(profile.state, "UNKNOWN")
        new_state_str = STATE_NAMES.get(new_state, "UNKNOWN")
        profile.state = new_state
        profile.last_state_change = time.time()

        alias = KNOWN_NODES.get(profile.ip_str, profile.ip_str)
        ts = time.strftime("%H:%M:%S")

        if new_state == STATE_QUARANTINED:
            log_msg = f"[{ts}] 🚨 QUARANTINED: {alias} ({profile.ip_str}) | T_iso: {isolate_us:.2f}µs | Score: {profile.trust_score:.1f} | Penalty: {profile.last_penalty:.1f}"
            self.event_log.append(log_msg)
        elif new_state == STATE_SUSPECT:
            log_msg = f"[{ts}] ⚠️ SUSPECT: {alias} ({profile.ip_str}) | T_iso: {isolate_us:.2f}µs | Score: {profile.trust_score:.1f} (Throttling Engaged)"
            self.event_log.append(log_msg)
        elif new_state == STATE_TRUSTED:
            log_msg = f"[{ts}] 💚 HEALED: {alias} ({profile.ip_str}) | T_iso: {isolate_us:.2f}µs | Score: {profile.trust_score:.1f} (Restored line-rate)"
            self.event_log.append(log_msg)

    def print_telemetry_dashboard(self):
        # Use ANSI home escape to avoid terminal flicker
        print("\033[H\033[J", end="")
        print("==========================================================================================")
        print("     KERNEL-LEVEL ZERO-TRUST ISOLATION ENGINE — DYNAMIC TELEMETRY DASHBOARD (PHASE 2)     ")
        print("==========================================================================================")
        ifaces_str = ", ".join(self.attached_ifaces) if self.attached_ifaces else "None"
        print(f" Interfaces Attached : {ifaces_str}")
        if len(self.attached_ifaces) <= 1:
            print(" \033[93m[!] WARNING: Only br-xdp attached! Ensure setup_netns.sh is active for veth-*-br.\033[0m")

        c_total = self.diag_map[ctypes.c_int(0)].value
        c_ipv4 = self.diag_map[ctypes.c_int(1)].value
        c_tcp = self.diag_map[ctypes.c_int(2)].value
        c_udp = self.diag_map[ctypes.c_int(3)].value
        c_qdrop = self.diag_map[ctypes.c_int(7)].value
        c_sdrop = self.diag_map[ctypes.c_int(6)].value

        print(f" Ingress Frames Intercepted: {c_total:<10} | IPv4 Frames Verified: {c_ipv4:<10}")
        print(f" TCP Intercepted           : {c_tcp:<10} | UDP Frames Parsed    : {c_udp:<10}")
        print(f" Quarantined Drops (XDP)   : {c_qdrop:<10} | Suspect Throttles    : {c_sdrop:<10}")
        print("------------------------------------------------------------------------------------------")
        print(f"{'Workload / Node':<22} {'State':<15} {'Trust Gauge':<22} {'PPS':<8} {'SYN/s':<8} {'Ports':<7} {'Drops':<8}")
        print("------------------------------------------------------------------------------------------")

        for ip in sorted(self.workloads.keys()):
            profile = self.workloads[ip]
            ip_key = ctypes.c_uint32(ip_to_u32(ip))
            drops = self.drop_map[ip_key].value if ip_key in self.drop_map else 0

            alias = KNOWN_NODES.get(ip, ip)
            st = profile.state
            if st == STATE_TRUSTED:
                st_badge = "\033[92m[TRUSTED]\033[0m    "
            elif st == STATE_SUSPECT:
                st_badge = "\033[93m[SUSPECT]\033[0m    "
            else:
                st_badge = "\033[91m[QUARANTINED]\033[0m"

            # 10-bar clean gauge
            filled = int(profile.trust_score / 10.0)
            bar = "=" * filled + "-" * (10 - filled)
            trust_str = f"[{bar}] {profile.trust_score:>5.1f}%"

            print(f"{alias:<22} {st_badge} {trust_str:<22} {profile.last_pps:<8.1f} {profile.last_syn_pps:<8.1f} {profile.last_unique_ports:<7} {drops:<8}")

        print("------------------------------------------------------------------------------------------")
        print(" Recent Security State Transitions & Microsecond Latencies (T_isolate):")
        if not self.event_log:
            print("   (Nominal — All workloads operating within zero-trust baseline)")
        else:
            for entry in self.event_log:
                print(f"   {entry}")

        print("==========================================================================================")
        print(" Sliding Window: 1.0s | Self-Healing: +6.0 pts/s | Dynamic Port Sync: Active | Ctrl+C to Exit")
        print("==========================================================================================")

    def run(self):
        last_eval_time = time.time()
        print("[*] Engine active. Monitoring network traffic...")

        while self.running:
            try:
                # Poll ring buffer for up to 100ms
                self.bpf.ring_buffer_poll(timeout=100)

                now = time.time()
                dt = now - last_eval_time

                # 1.0-second sliding-window evaluation tick
                if dt >= 1.0:
                    # Dynamically check for new or recreated member interfaces
                    self.sync_interfaces()

                    for ip, profile in list(self.workloads.items()):
                        new_state = profile.evaluate_window(dt)
                        if new_state != profile.state:
                            self.mutate_kernel_policy(profile, new_state)

                    self.print_telemetry_dashboard()
                    last_eval_time = now

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[-] Telemetry loop error: {e}")
                time.sleep(1)

    def cleanup(self):
        print("\n[*] Detaching XDP programs from network interfaces...")
        for iface in list(self.attached_ifaces):
            force_detach_interface(iface)
            print(f"    [-] Detached from '{iface}' [OK]")
        print("[✓] XDP Engine shut down cleanly.")

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "br-xdp"
    daemon = DynamicTrustDaemon(target_arg=target)

    def sig_handler(sig, frame):
        daemon.running = False

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    try:
        daemon.load_and_attach()
        daemon.run()
    finally:
        daemon.cleanup()

if __name__ == "__main__":
    main()
