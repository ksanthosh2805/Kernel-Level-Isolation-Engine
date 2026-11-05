#!/usr/bin/env python3
# Kernel-Level Zero-Trust Traffic Isolation Engine
# Phase 5 (v2.0): 16-Port eBPF Cluster Loader & Interactive Controller
#
# Capabilities:
# 1. Compiles and loads high-density kernel/xdp_isolation_v2.c via Python BCC
# 2. Auto-detects and binds Generic XDP across all 16 bridge member ports
# 3. Provides CLI control over policy_map and east_west_matrix
# 4. Monitors diagnostic counters and lateral drop statistics in real time

import os
import sys
import time
import socket
import struct
import signal
import ctypes
import argparse
import subprocess
from typing import List, Dict, Optional

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False


STATE_TRUSTED = 0
STATE_SUSPECT = 1
STATE_QUARANTINED = 2

STATE_NAMES = {
    STATE_TRUSTED: "TRUSTED [PASS]",
    STATE_SUSPECT: "SUSPECT [50% THROTTLE]",
    STATE_QUARANTINED: "QUARANTINED [100% DROP]"
}

EW_ACTION_ALLOW = 0
EW_ACTION_DENY_LATERAL = 1

XDP_FLAGS_SKB_MODE = 1 << 1  # Generic SKB mode for virtual interfaces

CLUSTER_VETH_PORTS = [
    "veth-w01-br", "veth-w02-br", "veth-w03-br", "veth-w04-br",
    "veth-a01-br", "veth-a02-br", "veth-a03-br", "veth-a04-br",
    "veth-d01-br", "veth-d02-br", "veth-d03-br", "veth-d04-br",
    "veth-c01-br", "veth-c02-br", "veth-x01-br", "veth-x02-br"
]

CLUSTER_NODES = {
    "10.20.0.11": "ns-web-01 (Tier 1 Web)",
    "10.20.0.12": "ns-web-02 (Tier 1 Web)",
    "10.20.0.13": "ns-web-03 (Tier 1 Web)",
    "10.20.0.14": "ns-web-04 (Tier 1 Web)",
    "10.20.0.21": "ns-api-auth (Tier 2 API)",
    "10.20.0.22": "ns-api-order (Tier 2 API)",
    "10.20.0.23": "ns-api-pay (Tier 2 API)",
    "10.20.0.24": "ns-api-user (Tier 2 API)",
    "10.20.0.31": "ns-db-primary (Tier 3 Data)",
    "10.20.0.32": "ns-db-replica (Tier 3 Data)",
    "10.20.0.33": "ns-redis-cache (Tier 3 Cache)",
    "10.20.0.34": "ns-elastic-search (Tier 3 Data)",
    "10.20.0.41": "ns-client-alpha (Tier 4 Client)",
    "10.20.0.42": "ns-client-beta (Tier 4 Client)",
    "10.20.0.51": "ns-attk-lateral (Tier 4 Scanner)",
    "10.20.0.52": "ns-attk-ddos (Tier 4 Flooder)"
}


def ip_to_u32(ip_str: str) -> int:
    return struct.unpack("I", socket.inet_aton(ip_str))[0]


def u32_to_ip(ip_int: int) -> str:
    return socket.inet_ntoa(struct.pack("I", ip_int))


def make_ew_key(src_ip: str, dst_ip: str) -> int:
    return (ip_to_u32(src_ip) << 32) | ip_to_u32(dst_ip)


class ClusterXDPController:
    """Manages multi-port attachment and kernel policy mutation for 16 nodes."""

    def __init__(self, c_src_path: str = "kernel/xdp_isolation_v2.c"):
        self.c_src_path = c_src_path
        self.bpf: Optional[BPF] = None
        self.fn = None
        self.attached_ports: List[str] = []

    def load_and_attach(self) -> bool:
        if not os.path.exists(self.c_src_path):
            print(f"[-] Error: Source file not found: {self.c_src_path}")
            return False

        print(f"[*] Compiling and verifying Phase 5 eBPF filter: {self.c_src_path}...")
        try:
            self.bpf = BPF(src_file=self.c_src_path)
            self.fn = self.bpf.load_func("xdp_cluster_filter", BPF.XDP)
        except Exception as e:
            print(f"[-] eBPF Verifier Compilation Failed: {e}")
            return False

        print("[+] eBPF bytecode compiled and passed kernel verifier bounds checks!")

        # Scan and attach to all available 16 veth bridge ports
        self.attached_ports = []
        for port in CLUSTER_VETH_PORTS:
            if os.path.exists(f"/sys/class/net/{port}"):
                try:
                    # Clean any stale programs
                    subprocess.run(["ip", "link", "set", "dev", port, "xdpgeneric", "off"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.bpf.attach_xdp(port, self.fn, XDP_FLAGS_SKB_MODE)
                    self.attached_ports.append(port)
                except Exception as e:
                    print(f"[-] Warning: Failed to attach to {port}: {e}")

        if len(self.attached_ports) == 0:
            print("[-] ERROR: 0 cluster interfaces found!", flush=True)
            print("[-] Please set up the 16-node cluster topology first by running:", flush=True)
            print("    sudo bash topology/setup_netns_cluster.sh\n", flush=True)
            return False

        print(f"[+] Successfully bound XDP filter across {len(self.attached_ports)} / 16 bridge ports.", flush=True)
        return True

    def detach_all(self):
        """Detach XDP from all ports on shutdown."""
        print("\n[*] Detaching XDP programs from cluster bridge interfaces...")
        for port in self.attached_ports:
            try:
                if self.bpf is not None:
                    self.bpf.remove_xdp(port, XDP_FLAGS_SKB_MODE)
                subprocess.run(["ip", "link", "set", "dev", port, "xdpgeneric", "off"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        self.attached_ports.clear()
        print("[+] All XDP hooks detached cleanly.")

    def set_workload_state(self, ip_str: str, state: int):
        if self.bpf is None:
            print("[-] Error: BPF module not loaded!", flush=True)
            return
        policy_map = self.bpf.get_table("policy_map")
        k = ctypes.c_uint32(ip_to_u32(ip_str))
        v = ctypes.c_uint32(state)

        t0 = time.perf_counter_ns()
        policy_map[k] = v
        t1 = time.perf_counter_ns()

        lat_us = (t1 - t0) / 1000.0
        print(f"[+] Mutated policy_map for {ip_str} -> {STATE_NAMES.get(state, 'UNKNOWN')} in {lat_us:.2f} µs", flush=True)

    def set_east_west_rule(self, src_ip: str, dst_ip: str, action: int):
        if self.bpf is None:
            print("[-] Error: BPF module not loaded!", flush=True)
            return
        ew_map = self.bpf.get_table("east_west_matrix")
        key = ctypes.c_uint64(make_ew_key(src_ip, dst_ip))
        val = ctypes.c_uint32(action)

        t0 = time.perf_counter_ns()
        ew_map[key] = val
        t1 = time.perf_counter_ns()

        lat_us = (t1 - t0) / 1000.0
        act_str = "DENY_LATERAL" if action == EW_ACTION_DENY_LATERAL else "ALLOW"
        print(f"[+] East-West Matrix: {src_ip} -> {dst_ip} = {act_str} in {lat_us:.2f} µs", flush=True)

    def print_status_table(self):
        if self.bpf is None:
            print("[-] Error: BPF module not loaded!", flush=True)
            return

        policy_map = self.bpf.get_table("policy_map")
        drop_map = self.bpf.get_table("drop_counter_map")
        pass_map = self.bpf.get_table("pass_counter_map")
        lat_map = self.bpf.get_table("lateral_drop_map")
        diag = self.bpf.get_table("diagnostic_counters")

        print("\n" + "=" * 95, flush=True)
        print(f"{'NAMESPACE & CLUSTER ROLE':<32} | {'IP ADDRESS':<14} | {'STATE':<24} | {'PASS':<8} | {'DROPS':<8}", flush=True)
        print("-" * 95, flush=True)

        for ip, desc in CLUSTER_NODES.items():
            ip_k = ctypes.c_uint32(ip_to_u32(ip))
            try:
                state_val = policy_map[ip_k].value
            except KeyError:
                state_val = STATE_TRUSTED

            try:
                passes = pass_map[ip_k].value
            except KeyError:
                passes = 0

            try:
                drops = drop_map[ip_k].value
            except KeyError:
                drops = 0

            try:
                lat_drops = lat_map[ip_k].value
            except KeyError:
                lat_drops = 0

            tot_drops = drops + lat_drops
            st_str = STATE_NAMES.get(state_val, "TRUSTED")

            print(f"{desc:<32} | {ip:<14} | {st_str:<24} | {passes:<8} | {tot_drops:<8}", flush=True)

        print("=" * 95, flush=True)
        try:
            print(f"[*] Diagnostics: Intercepted: {diag[ctypes.c_int(0)].value} | "
                  f"IPv4: {diag[ctypes.c_int(1)].value} | TCP: {diag[ctypes.c_int(2)].value} | "
                  f"Lateral Drops: {diag[ctypes.c_int(4)].value} | Quarantine Drops: {diag[ctypes.c_int(7)].value}", flush=True)
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Phase 5: 16-Port eBPF Cluster Loader & Controller")
    parser.add_argument("--test-only", action="store_true", help="Compile and verify in-memory without interactive shell")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Warning: Attaching XDP programs requires root privileges.")
        print("    Please run with: sudo python3 daemon/cluster_loader.py")
        sys.exit(1)

    if not BCC_AVAILABLE:
        print("[-] Error: Python BCC module not found. Install with: sudo apt install python3-bpfcc")
        sys.exit(1)

    controller = ClusterXDPController()

    # Register clean SIGINT/SIGTERM handler
    def sig_handler(sig, frame):
        controller.detach_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    success = controller.load_and_attach()
    if not success:
        sys.exit(1)

    if args.test_only:
        print("[+] Test Verification PASSED: kernel/xdp_isolation_v2.c verified and ready.")
        controller.detach_all()
        return

    print("\n[+] 16-Port eBPF Cluster Isolation Engine is ACTIVE! (v2.1-verified)")
    print("    Type 'help' for commands, 'status' to view cluster nodes, 'quit' to exit.\n", flush=True)

    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    while True:
        try:
            raw_line = input("cluster-xdp# ").strip()
            if not raw_line:
                continue

            cmd = raw_line.split()
            # Sanitize: Strip any leading prompt tokens if user pasted them from chat
            while cmd and (cmd[0].startswith("cluster-xdp") or cmd[0] == "#" or "cluster-xdp#" in cmd[0]):
                cmd.pop(0)

            if not cmd:
                continue

            action = cmd[0].lower()

            try:
                if action in ["quit", "exit", "q"]:
                    controller.detach_all()
                    break
                elif action == "status":
                    controller.print_status_table()
                elif action == "block" and len(cmd) > 1:
                    controller.set_workload_state(cmd[1], STATE_QUARANTINED)
                elif action == "suspect" and len(cmd) > 1:
                    controller.set_workload_state(cmd[1], STATE_SUSPECT)
                elif action == "allow" and len(cmd) > 1:
                    controller.set_workload_state(cmd[1], STATE_TRUSTED)
                elif action == "isolate-lateral" and len(cmd) > 2:
                    controller.set_east_west_rule(cmd[1], cmd[2], EW_ACTION_DENY_LATERAL)
                elif action == "allow-lateral" and len(cmd) > 2:
                    controller.set_east_west_rule(cmd[1], cmd[2], EW_ACTION_ALLOW)
                elif action == "help":
                    print("Commands:", flush=True)
                    print("  status                         - Print 16-node state and packet counters", flush=True)
                    print("  block <IP>                     - Quarantine IP (100% wire-speed driver drop)", flush=True)
                    print("  suspect <IP>                   - Throttle IP (50% probabilistic driver drop)", flush=True)
                    print("  allow <IP>                     - Restore IP to TRUSTED (Line-rate pass)", flush=True)
                    print("  isolate-lateral <src> <dst>    - Block inter-container East-West connection", flush=True)
                    print("  allow-lateral <src> <dst>      - Permit inter-container East-West connection", flush=True)
                    print("  quit                           - Detach all 16 XDP programs and exit", flush=True)
                else:
                    print(f"[-] Unknown command: {' '.join(cmd)}. Type 'help' for available commands.", flush=True)
            except Exception as cmd_err:
                import traceback
                print(f"[-] Command Execution Error: {cmd_err}", flush=True)
                traceback.print_exc()
        except (KeyboardInterrupt, EOFError):
            controller.detach_all()
            break


if __name__ == "__main__":
    main()

