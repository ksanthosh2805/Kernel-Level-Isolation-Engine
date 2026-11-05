#!/usr/bin/env python3
# Kernel-Level Zero-Trust Traffic Isolation Engine
# Phase 5 (v2.0): Swarm Trust Decay Daemon (Multi-Node Cluster Controller)
#
# Capabilities:
# 1. Binds Generic XDP across all 16 bridge member ports
# 2. Wire-speed 32-byte flow telemetry ingestion via eBPF Ring Buffer
# 3. 2^(k-1) Repeat-Offender Anti-Flapping Hysteresis Algorithm
# 4. East-West lateral movement micro-isolation and zero-trust matrix enforcement
# 5. Multi-attacker target flood aggregation and live 16-node ANSI dashboard

import os
import sys
import time
import socket
import struct
import signal
import ctypes
import argparse
import subprocess
from collections import deque, defaultdict
from typing import Dict, Set, Optional

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False


# Security States (3-Tier Dynamic State Machine)
STATE_TRUSTED = 0
STATE_SUSPECT = 1
STATE_QUARANTINED = 2

STATE_NAMES = {
    STATE_TRUSTED: "TRUSTED [PASS]",
    STATE_SUSPECT: "SUSPECT [50% THROTTLE]",
    STATE_QUARANTINED: "QUARANTINED [100% DROP]"
}

# East-West Lateral Matrix Policies
EW_ACTION_ALLOW = 0
EW_ACTION_DENY_LATERAL = 1

# Kernel Attachment Mode
XDP_FLAGS_SKB_MODE = 1 << 1

# 16-Node Cluster Network Definition (10.20.0.0/24)
CLUSTER_PORTS = [
    "veth-w01-br", "veth-w02-br", "veth-w03-br", "veth-w04-br",
    "veth-a01-br", "veth-a02-br", "veth-a03-br", "veth-a04-br",
    "veth-d01-br", "veth-d02-br", "veth-d03-br", "veth-d04-br",
    "veth-c01-br", "veth-c02-br", "veth-x01-br", "veth-x02-br"
]

CLUSTER_NODES = {
    "10.20.0.11": ("ns-web-01", "Tier 1: Web Frontend 01 (Public HTTP)"),
    "10.20.0.12": ("ns-web-02", "Tier 1: Web Frontend 02 (Public HTTP)"),
    "10.20.0.13": ("ns-web-03", "Tier 1: Web Frontend 03 (Public HTTP)"),
    "10.20.0.14": ("ns-web-04", "Tier 1: Web Frontend 04 (Public HTTP)"),
    "10.20.0.21": ("ns-api-auth", "Tier 2: Auth & Identity Microservice"),
    "10.20.0.22": ("ns-api-order", "Tier 2: Order Processing API"),
    "10.20.0.23": ("ns-api-pay", "Tier 2: Payment Gateway API"),
    "10.20.0.24": ("ns-api-user", "Tier 2: User Profile API"),
    "10.20.0.31": ("ns-db-primary", "Tier 3: PostgreSQL Primary DB"),
    "10.20.0.32": ("ns-db-replica", "Tier 3: PostgreSQL Read Replica"),
    "10.20.0.33": ("ns-redis-cache", "Tier 3: Redis Session Cache"),
    "10.20.0.34": ("ns-elastic-search", "Tier 3: Elasticsearch Analytics"),
    "10.20.0.41": ("ns-client-alpha", "Tier 4: Legitimate Consumer Alpha"),
    "10.20.0.42": ("ns-client-beta", "Tier 4: Legitimate Consumer Beta"),
    "10.20.0.51": ("ns-attk-lateral", "Tier 4: Compromised Pod (Lateral Scanner)"),
    "10.20.0.52": ("ns-attk-ddos", "Tier 4: Compromised Pod (Volumetric Flooder)")
}


def ip_to_u32(ip_str: str) -> int:
    """Network-byte order uint32 matching raw packet memory layout."""
    return struct.unpack("I", socket.inet_aton(ip_str))[0]


def u32_to_ip(ip_int: int) -> str:
    """Convert network-byte order uint32 back to dotted IPv4 string."""
    return socket.inet_ntoa(struct.pack("I", ip_int))


def make_ew_key(src_ip: str, dst_ip: str) -> int:
    """64-bit composite key: (src_ip << 32) | dst_ip."""
    return (ip_to_u32(src_ip) << 32) | ip_to_u32(dst_ip)


# 32-Byte Wire-Speed Flow Telemetry Event Structure
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
        ("ew_action", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
    ]


class WorkloadClusterProfile:
    """
    Manages mathematical trust score, sliding-window traffic heuristics,
    and 2^(k-1) repeat-offender anti-flapping hysteresis for a cluster workload.
    """

    def __init__(self, ip_str: str, alias: str, role: str):
        self.ip_str = ip_str
        self.alias = alias
        self.role = role
        self.trust_score = 100.0
        self.state = STATE_TRUSTED
        self.last_state_change = time.time()
        self.last_isolate_lat_us = 0.0

        # Repeat-Offender Hysteresis Tracker
        self.offense_count_k = 0     # Number of quarantine incidents
        self.quiescent_windows = 0    # Quiet evaluation cycles for cooldown
        self.base_healing_rate = 6.0  # R_base = +6.0 pts/sec

        # Sliding Window 1-Second Statistics
        self.win_packets = 0
        self.win_syns = 0
        self.win_ports: Set[int] = set()
        self.win_targets: Set[str] = set()
        self.win_lateral_violations = 0

        # Historical Evaluated Rates
        self.last_pps = 0.0
        self.last_syn_pps = 0.0
        self.last_unique_ports = 0
        self.last_penalty = 0.0
        self.total_packets_seen = 0

    def record_flow(self, event: FlowEvent):
        # Sampled quarantined frames represent 64 packets in kernel
        weight = 64 if event.state == STATE_QUARANTINED else 1
        self.win_packets += weight
        self.total_packets_seen += weight

        # TCP SYN inspection (flag 0x02)
        if event.protocol == 6 and (event.tcp_flags & 0x02):
            self.win_syns += weight

        if event.dst_port != 0:
            self.win_ports.add(event.dst_port)

        dst_str = u32_to_ip(event.dst_ip)
        self.win_targets.add(dst_str)

        # East-West Lateral Violation flag
        if event.ew_action == EW_ACTION_DENY_LATERAL:
            self.win_lateral_violations += 1

    def evaluate_sliding_window(self, dt: float):
        """
        Calculates sliding window penalties and applies 2^(k-1) exponential hysteresis.
        """
        self.last_pps = self.win_packets / dt if dt > 0 else 0.0
        self.last_syn_pps = self.win_syns / dt if dt > 0 else 0.0
        self.last_unique_ports = len(self.win_ports)

        # 1. Base Volumetric Penalty: P_pps = min(45, max(0, PPS - 75) * 0.20)
        p_pps = min(45.0, max(0.0, self.last_pps - 75.0) * 0.20)

        # 2. Base TCP SYN Flood Penalty: P_syn = min(50, max(0, SYN - 20) * 0.50)
        p_syn = min(50.0, max(0.0, self.last_syn_pps - 20.0) * 0.50)

        # 3. Base Port Scan Penalty: P_scan = min(60, max(0, Ports - 5) * 4.0)
        p_scan = min(60.0, max(0.0, float(self.last_unique_ports - 5)) * 4.0)

        # 4. East-West Lateral Penetration Violation: 50 points instant penalty
        p_lateral = 50.0 if self.win_lateral_violations > 0 else 0.0

        base_penalty = p_pps + p_syn + p_scan + p_lateral

        # -----------------------------------------------------------------
        # Idea C: Repeat-Offender Hysteresis Algorithm
        # P_decay = P_base * 2^(k-1)
        # R_heal  = R_base / 2^(k-1)
        # -----------------------------------------------------------------
        hysteresis_multiplier = 2 ** max(0, self.offense_count_k - 1) if self.offense_count_k > 0 else 1.0

        if base_penalty > 0:
            effective_penalty = base_penalty * hysteresis_multiplier
            self.trust_score = max(0.0, self.trust_score - effective_penalty)
            self.last_penalty = effective_penalty
            self.quiescent_windows = 0
        else:
            self.last_penalty = 0.0
            self.quiescent_windows += 1
            # Throttled self-healing for repeat offenders
            effective_healing = (self.base_healing_rate / hysteresis_multiplier) * dt
            self.trust_score = min(100.0, self.trust_score + effective_healing)

        # Clear window accumulators
        self.win_packets = 0
        self.win_syns = 0
        self.win_ports.clear()
        self.win_targets.clear()
        self.win_lateral_violations = 0

        # State Transition Determination
        old_state = self.state
        if self.trust_score >= 70.0:
            new_state = STATE_TRUSTED
        elif self.trust_score >= 30.0:
            new_state = STATE_SUSPECT
        else:
            new_state = STATE_QUARANTINED

        # Offense Count Increment on entering QUARANTINED
        if new_state == STATE_QUARANTINED and old_state != STATE_QUARANTINED:
            self.offense_count_k += 1

        # Synchronize profile state directly with computed verdict
        self.state = new_state
        return new_state


class SwarmTrustDecayDaemon:
    """
    Closed-loop control-plane daemon orchestrating the 16-node cluster eBPF datapath.
    """

    def __init__(self, c_src_path: str = "kernel/xdp_isolation_v2.c"):
        self.c_src_path = c_src_path
        self.bpf: Optional[BPF] = None
        self.fn = None
        self.running = True
        self.attached_ports = []
        self.workloads: Dict[str, WorkloadClusterProfile] = {}
        self.event_log = deque(maxlen=8)

        # Map references
        self.policy_map = None
        self.drop_map = None
        self.pass_map = None
        self.lat_map = None
        self.diag_map = None
        self.ew_map = None

        # Coordinated Flood Aggregator: dst_ip -> packet rate
        self.ingress_target_rates: Dict[str, float] = defaultdict(float)

        # Initialize profiles for all 16 known nodes
        for ip, (alias, role) in CLUSTER_NODES.items():
            self.workloads[ip] = WorkloadClusterProfile(ip, alias, role)

    def load_and_attach(self) -> bool:
        if not os.path.exists(self.c_src_path):
            print(f"[-] Error: Source file not found: {self.c_src_path}")
            return False

        print(f"[*] Compiling Phase 5 Cluster XDP Datapath: {self.c_src_path}...")
        try:
            self.bpf = BPF(src_file=self.c_src_path)
            self.fn = self.bpf.load_func("xdp_cluster_filter", BPF.XDP)
        except Exception as e:
            print(f"[-] eBPF Compilation Failed: {e}")
            return False

        print("[+] eBPF bytecode compiled and passed kernel verifier bounds checks!")

        # Initialize BPF Tables
        self.policy_map = self.bpf.get_table("policy_map")
        self.drop_map = self.bpf.get_table("drop_counter_map")
        self.pass_map = self.bpf.get_table("pass_counter_map")
        self.lat_map = self.bpf.get_table("lateral_drop_map")
        self.diag_map = self.bpf.get_table("diagnostic_counters")
        self.ew_map = self.bpf.get_table("east_west_matrix")

        # Attach Generic XDP across all 16 veth bridge ports
        self.attached_ports = []
        for port in CLUSTER_PORTS:
            if os.path.exists(f"/sys/class/net/{port}"):
                try:
                    subprocess.run(["ip", "link", "set", "dev", port, "xdpgeneric", "off"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.bpf.attach_xdp(port, self.fn, XDP_FLAGS_SKB_MODE)
                    self.attached_ports.append(port)
                except Exception as e:
                    print(f"[-] Warning: Failed to attach to {port}: {e}")

        if len(self.attached_ports) == 0:
            print("[-] ERROR: 0 cluster interfaces found!")
            print("[-] Please run the topology setup first: sudo bash topology/setup_netns_cluster.sh")
            return False

        print(f"[+] Successfully bound XDP filter across {len(self.attached_ports)} / 16 bridge ports.")

        # Pre-seed East-West Zero-Trust Policy Matrix (Web Frontend -> Direct Database DENY)
        print("[*] Pre-seeding East-West Zero-Trust Policy Matrix...")
        for web_ip in ["10.20.0.11", "10.20.0.12", "10.20.0.13", "10.20.0.14"]:
            for db_ip in ["10.20.0.31", "10.20.0.32", "10.20.0.33", "10.20.0.34"]:
                key = ctypes.c_uint64(make_ew_key(web_ip, db_ip))
                self.ew_map[key] = ctypes.c_uint32(EW_ACTION_DENY_LATERAL)

        # Deny compromised lateral scanner from querying stateful DBs
        for db_ip in ["10.20.0.31", "10.20.0.32", "10.20.0.33", "10.20.0.34"]:
            key = ctypes.c_uint64(make_ew_key("10.20.0.51", db_ip))
            self.ew_map[key] = ctypes.c_uint32(EW_ACTION_DENY_LATERAL)

        print("[+] Seeded 20 default East-West least-privilege tier isolation rules.")

        # Open eBPF Ring Buffer Telemetry Stream
        print("[*] Opening eBPF Ring Buffer telemetry stream...")
        self.bpf["telemetry_ringbuf"].open_ring_buffer(self._ringbuf_callback)
        print("[✓] 16-Node Swarm Trust Decay Daemon is LIVE!")
        return True

    def _ringbuf_callback(self, ctx, data, size):
        event = ctypes.cast(data, ctypes.POINTER(FlowEvent)).contents
        src_str = u32_to_ip(event.src_ip)

        # Filter noise/loopback
        if src_str.startswith("127.") or src_str == "0.0.0.0" or src_str == "255.255.255.255":
            return 0

        if src_str in self.workloads:
            self.workloads[src_str].record_flow(event)

        return 0

    def mutate_kernel_policy(self, profile: WorkloadClusterProfile, new_state: int):
        """Mutates kernel policy_map atomically in microseconds."""
        k = ctypes.c_uint32(ip_to_u32(profile.ip_str))
        v = ctypes.c_uint32(new_state)

        t0 = time.perf_counter_ns()
        self.policy_map[k] = v
        t1 = time.perf_counter_ns()

        iso_lat_us = (t1 - t0) / 1000.0
        profile.last_isolate_lat_us = iso_lat_us
        profile.state = new_state
        profile.last_state_change = time.time()

        ts = time.strftime("%H:%M:%S")
        k_val = profile.offense_count_k

        if new_state == STATE_QUARANTINED:
            self.event_log.append(
                f"[{ts}] 🚨 QUARANTINED: {profile.alias} ({profile.ip_str}) | T_iso: {iso_lat_us:.2f}µs | "
                f"Offenses (k): {k_val} | Score: {profile.trust_score:.1f}"
            )
        elif new_state == STATE_SUSPECT:
            self.event_log.append(
                f"[{ts}] ⚠️ SUSPECT: {profile.alias} ({profile.ip_str}) | T_iso: {iso_lat_us:.2f}µs | "
                f"50% Throttled | Score: {profile.trust_score:.1f}"
            )
        elif new_state == STATE_TRUSTED:
            self.event_log.append(
                f"[{ts}] 💚 HEALED: {profile.alias} ({profile.ip_str}) | T_iso: {iso_lat_us:.2f}µs | "
                f"Line-Rate Restored | Score: {profile.trust_score:.1f}"
            )

    def print_ansi_dashboard(self):
        """Renders live flicker-free 16-node cluster telemetry dashboard."""
        print("\033[H\033[J", end="", flush=True)
        print("=" * 105, flush=True)
        print("   KERNEL-LEVEL ZERO-TRUST ISOLATION ENGINE (v2.0) — 16-NODE SWARM TELEMETRY DASHBOARD   ", flush=True)
        print("=" * 105, flush=True)

        # Diagnostic summary
        try:
            c_tot = self.diag_map[ctypes.c_int(0)].value
            c_ip4 = self.diag_map[ctypes.c_int(1)].value
            c_lat = self.diag_map[ctypes.c_int(4)].value
            c_qdrop = self.diag_map[ctypes.c_int(7)].value
        except Exception:
            c_tot, c_ip4, c_lat, c_qdrop = 0, 0, 0, 0

        print(f" Datapath Ports Bound : {len(self.attached_ports)} / 16  | Ingress Frames Intercepted: {c_tot:<8} | IPv4 Frames: {c_ip4:<8}", flush=True)
        print(f" Lateral Drops (E-W)  : {c_lat:<8}   | Wire-Speed Driver Drops   : {c_qdrop:<8} | Offense Model: 2^(k-1)", flush=True)
        print("-" * 105, flush=True)
        print(f"{'POD & CLUSTER ROLE':<26} {'IP ADDRESS':<14} {'STATE':<14} {'TRUST GAUGE':<20} {'k':<3} {'PPS':<7} {'SYN/s':<7} {'DROPS':<7}", flush=True)
        print("-" * 105, flush=True)

        for ip in sorted(self.workloads.keys()):
            p = self.workloads[ip]
            ip_k = ctypes.c_uint32(ip_to_u32(ip))
            try:
                drops = self.drop_map[ip_k].value
            except KeyError:
                drops = 0
            try:
                lat_d = self.lat_map[ip_k].value
            except KeyError:
                lat_d = 0
            total_drops = drops + lat_d

            # State badge
            if p.state == STATE_TRUSTED:
                st_badge = "\033[92mTRUSTED\033[0m      "
            elif p.state == STATE_SUSPECT:
                st_badge = "\033[93mSUSPECT\033[0m      "
            else:
                st_badge = "\033[91mQUARANTINED\033[0m  "

            # 10-bar clean gauge
            filled = int(p.trust_score / 10.0)
            bar = "=" * filled + "-" * (10 - filled)
            gauge_str = f"[{bar}] {p.trust_score:>5.1f}%"

            display_name = f"{p.alias} ({p.role.split(':')[0]})"
            print(f"{display_name:<26} {ip:<14} {st_badge} {gauge_str:<20} {p.offense_count_k:<3} {p.last_pps:<7.1f} {p.last_syn_pps:<7.1f} {total_drops:<7}", flush=True)

        print("-" * 105, flush=True)
        print(" Recent Microsecond Isolation Audit & Self-Healing Events (T_isolate):", flush=True)
        if not self.event_log:
            print("   (Nominal — All 16 microservice workloads operating within zero-trust baseline)", flush=True)
        else:
            for log_entry in self.event_log:
                print(f"   {log_entry}", flush=True)

        print("=" * 105, flush=True)
        print(" Algorithmic Hysteresis: P * 2^(k-1) | Healing: R_base / 2^(k-1) | Window: 1.0s | Ctrl+C to Exit", flush=True)
        print("=" * 105, flush=True)

    def detach_all(self):
        """Detaches XDP hooks cleanly from all 16 ports."""
        print("\n[*] Safely detaching XDP hooks across all cluster ports...")
        for port in self.attached_ports:
            try:
                if self.bpf is not None:
                    self.bpf.remove_xdp(port, XDP_FLAGS_SKB_MODE)
                subprocess.run(["ip", "link", "set", "dev", port, "xdpgeneric", "off"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        self.attached_ports.clear()
        print("[+] All 16 XDP hooks detached cleanly.")

    def run(self):
        """Main closed-loop evaluation & ring-buffer polling loop."""
        last_eval_time = time.time()

        while self.running:
            # Poll ring buffer non-blockingly with 50ms timeout
            if self.bpf is not None:
                self.bpf.ring_buffer_poll(timeout=50)

            now = time.time()
            dt = now - last_eval_time

            # 1.0-Second Sliding-Window Mathematical Evaluation
            if dt >= 1.0:
                for ip, profile in self.workloads.items():
                    old_state = profile.state
                    new_state = profile.evaluate_sliding_window(dt)

                    if new_state != old_state:
                        self.mutate_kernel_policy(profile, new_state)

                self.print_ansi_dashboard()
                last_eval_time = now


def main():
    parser = argparse.ArgumentParser(description="Phase 5 (v2.0): Swarm Trust Decay Daemon")
    parser.add_argument("--test-only", action="store_true", help="Compile and verify without launching daemon loop")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Warning: Attaching XDP programs requires root privileges.")
        print("    Please run with: sudo python3 daemon/cluster_daemon.py")
        sys.exit(1)

    if not BCC_AVAILABLE:
        print("[-] Error: Python BCC module not found. Install with: sudo apt install python3-bpfcc")
        sys.exit(1)

    daemon = SwarmTrustDecayDaemon()

    def sig_handler(sig, frame):
        daemon.running = False
        daemon.detach_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    success = daemon.load_and_attach()
    if not success:
        sys.exit(1)

    if args.test_only:
        print("[+] Test Verification PASSED: daemon/cluster_daemon.py verified and ready.")
        daemon.detach_all()
        return

    try:
        daemon.run()
    except (KeyboardInterrupt, SystemExit):
        daemon.detach_all()


if __name__ == "__main__":
    main()

