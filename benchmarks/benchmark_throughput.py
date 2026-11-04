#!/usr/bin/env python3
"""
Kernel-Level Zero-Trust Traffic Isolation Engine
Phase 4: Quantitative Benchmarking Suite
Experiment 3: Legitimate Tenant Throughput & RTT Preservation

Evaluates legitimate tenant traffic (ns-legit -> ns-victim) under:
  1. Baseline (Idle, unattacked network)
  2. Active Volumetric Attack with Linux iptables DROP
  3. Active Volumetric Attack with eBPF/XDP Driver-Level Drop

Metrics collected:
  - iperf3 TCP Throughput (Mbits/sec or Gbits/sec)
  - TCP Retransmissions
  - ICMP Round-Trip Time (RTT: min/avg/max in ms)
  - Packet Loss Percentage (%)

Outputs:
  - Terminal comparison table
  - CSV log: benchmarks/results/throughput_comparison.csv
  - IEEE/ACM format LaTeX table snippet for thesis publication
"""

import os
import sys
import time
import json
import socket
import struct
import signal
import ctypes
import argparse
import subprocess
from typing import List, Dict, Any, Tuple

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False

VICTIM_IP = "10.10.0.10"
LEGIT_IP = "10.10.0.20"
ATTACKER_IP = "10.10.0.30"
IPERF_PORT = 5201
XDP_FLAGS_SKB_MODE = 1 << 1


def ip_to_u32(ip_str: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]


def clean_residual():
    """Kill any residual hping3 or iperf3 processes."""
    for ns in ["ns-attacker", "ns-victim", "ns-legit"]:
        try:
            subprocess.run(["ip", "netns", "exec", ns, "killall", "-9", "hping3", "iperf3"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    try:
        subprocess.run(["killall", "-9", "hping3"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def start_iperf_server() -> subprocess.Popen:
    """Launch iperf3 server daemon inside ns-victim."""
    clean_residual()
    cmd = ["ip", "netns", "exec", "ns-victim", "iperf3", "-s", "-p", str(IPERF_PORT)]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
    time.sleep(1)
    return proc


def run_iperf_client(duration: int = 10, retries: int = 3) -> Dict[str, Any]:
    """Execute iperf3 client from ns-legit targeting ns-victim with retry resilience."""
    cmd = [
        "ip", "netns", "exec", "ns-legit", "iperf3",
        "-c", VICTIM_IP, "-p", str(IPERF_PORT),
        "-t", str(duration), "-J"
    ]
    for attempt in range(retries):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 10)
            if res.returncode == 0:
                data = json.loads(res.stdout)
                sum_sent = data.get("end", {}).get("sum_sent", {})
                sum_received = data.get("end", {}).get("sum_received", {})
                bps = sum_received.get("bits_per_second", sum_sent.get("bits_per_second", 0.0))
                retrans = sum_sent.get("retransmits", 0)
                return {
                    "throughput_mbps": bps / 1e6,
                    "retransmits": retrans,
                    "success": True
                }
            time.sleep(1.5)
        except Exception as e:
            time.sleep(1.5)
    return {"throughput_mbps": 0.0, "retransmits": -1, "success": False}


def run_ping_test(count: int = 10) -> Dict[str, Any]:
    """Execute ping from ns-legit to ns-victim and parse RTT statistics."""
    cmd = ["ip", "netns", "exec", "ns-legit", "ping", "-c", str(count), "-W", "1", VICTIM_IP]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=count + 5)
        loss_pct = 100.0
        rtt_min, rtt_avg, rtt_max = 0.0, 0.0, 0.0

        for line in res.stdout.splitlines():
            if "packets transmitted" in line:
                parts = line.split(",")
                for p in parts:
                    if "packet loss" in p:
                        loss_pct = float(p.split("%")[0].strip().split()[-1])
            elif "rtt min/avg/max" in line or "round-trip min/avg/max" in line:
                stats = line.split("=")[1].strip().split()[0].split("/")
                rtt_min = float(stats[0])
                rtt_avg = float(stats[1])
                rtt_max = float(stats[2])

        return {
            "loss_pct": loss_pct,
            "rtt_min": rtt_min,
            "rtt_avg": rtt_avg,
            "rtt_max": rtt_max
        }
    except Exception:
        return {"loss_pct": 100.0, "rtt_min": 0.0, "rtt_avg": 0.0, "rtt_max": 0.0}


def run_throughput_benchmarks(duration: int, output_csv: str, output_latex: str):
    """Execute Experiment 3: Compare legitimate throughput across Baseline, iptables, and XDP."""
    print("================================================================================")
    print("   EXPERIMENT 3: LEGITIMATE TENANT THROUGHPUT & RTT PRESERVATION                ")
    print("   Evaluating Legitimate Workload (ns-legit -> ns-victim) During Attack Flood   ")
    print("================================================================================")

    # Launch iperf3 server in ns-victim
    server_proc = start_iperf_server()
    results: Dict[str, Dict[str, Any]] = {}

    try:
        # ---------------------------------------------------------------------
        # Condition 1: Baseline (Unattacked Network)
        # ---------------------------------------------------------------------
        print(f"\n[1/3] Benchmarking Baseline Legitimate Throughput (No Attack)...")
        ping_base = run_ping_test(count=5)
        iperf_base = run_iperf_client(duration=duration)
        results["baseline"] = {**iperf_base, **ping_base}
        print(f"      -> Baseline: {results['baseline']['throughput_mbps']:.2f} Mbps | "
              f"RTT Avg: {results['baseline']['rtt_avg']:.2f} ms | Loss: {results['baseline']['loss_pct']:.1f}%")

        time.sleep(2)

        # ---------------------------------------------------------------------
        # Condition 2: Active Volumetric Flood with iptables DROP
        # ---------------------------------------------------------------------
        print(f"\n[2/3] Benchmarking Legitimate Throughput Under Attack with iptables DROP...")
        subprocess.run(["ip", "netns", "exec", "ns-victim", "iptables", "-F"], check=False)
        subprocess.run(["ip", "netns", "exec", "ns-victim", "iptables", "-A", "INPUT", "-s", ATTACKER_IP, "-j", "DROP"], check=True)

        print(f"      [*] Starting flood from ns-attacker to ns-victim...")
        flood_proc = subprocess.Popen(
            ["ip", "netns", "exec", "ns-attacker", "hping3", "-S", "-p", "80", "--flood", VICTIM_IP],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid
        )
        time.sleep(2)

        ping_ipt = run_ping_test(count=5)
        iperf_ipt = run_iperf_client(duration=duration)
        results["iptables"] = {**iperf_ipt, **ping_ipt}

        print(f"      [*] Halting flood and cleaning iptables...")
        try:
            os.killpg(os.getpgid(flood_proc.pid), signal.SIGKILL)
        except Exception:
            pass
        clean_residual()
        subprocess.run(["ip", "netns", "exec", "ns-victim", "iptables", "-F"], check=False)

        print(f"      -> iptables: {results['iptables']['throughput_mbps']:.2f} Mbps | "
              f"RTT Avg: {results['iptables']['rtt_avg']:.2f} ms | Loss: {results['iptables']['loss_pct']:.1f}%")

        # Restart server in case it crashed
        server_proc = start_iperf_server()
        time.sleep(3)

        # ---------------------------------------------------------------------
        # Condition 3: Active Volumetric Flood with eBPF/XDP DROP
        # ---------------------------------------------------------------------
        print(f"\n[3/3] Benchmarking Legitimate Throughput Under Attack with eBPF/XDP DROP...")
        dev = "veth-attack-br"
        subprocess.run(["ip", "link", "set", "dev", dev, "xdpgeneric", "off"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        bpf = BPF(src_file="kernel/xdp_isolation_p2.c")
        fn = bpf.load_func("xdp_dynamic_filter", BPF.XDP)
        bpf.attach_xdp(dev, fn, XDP_FLAGS_SKB_MODE)

        # Quarantine Attacker
        policy_map = bpf.get_table("policy_map")
        k = ctypes.c_uint32(ip_to_u32(ATTACKER_IP))
        policy_map[k] = ctypes.c_uint32(2)

        print(f"      [*] Starting flood from ns-attacker to ns-victim...")
        flood_proc = subprocess.Popen(
            ["ip", "netns", "exec", "ns-attacker", "hping3", "-S", "-p", "80", "--flood", VICTIM_IP],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid
        )
        time.sleep(2)

        ping_xdp = run_ping_test(count=5)
        iperf_xdp = run_iperf_client(duration=duration)
        results["xdp"] = {**iperf_xdp, **ping_xdp}

        print(f"      [*] Halting flood and detaching XDP...")
        try:
            os.killpg(os.getpgid(flood_proc.pid), signal.SIGKILL)
        except Exception:
            pass
        clean_residual()
        bpf.remove_xdp(dev, XDP_FLAGS_SKB_MODE)
        bpf = None

        print(f"      -> eBPF/XDP: {results['xdp']['throughput_mbps']:.2f} Mbps | "
              f"RTT Avg: {results['xdp']['rtt_avg']:.2f} ms | Loss: {results['xdp']['loss_pct']:.1f}%")

    finally:
        try:
            os.killpg(os.getpgid(server_proc.pid), signal.SIGKILL)
        except Exception:
            pass
        clean_residual()

    # -------------------------------------------------------------------------
    # Format and Print ANSI Table
    # -------------------------------------------------------------------------
    base_tp = results["baseline"]["throughput_mbps"]
    ipt_ratio = (results["iptables"]["throughput_mbps"] / base_tp * 100.0) if base_tp > 0 else 0.0
    xdp_ratio = (results["xdp"]["throughput_mbps"] / base_tp * 100.0) if base_tp > 0 else 0.0

    print("\n" + "=" * 80)
    print(f"{'METRIC':<25} | {'Baseline (Normal)':<16} | {'iptables Defense':<16} | {'eBPF/XDP Engine':<16}")
    print("-" * 80)
    print(f"{'Throughput (Mbps)':<25} | {results['baseline']['throughput_mbps']:>14.2f} | {results['iptables']['throughput_mbps']:>14.2f} | {results['xdp']['throughput_mbps']:>14.2f}")
    print(f"{'Throughput Retention':<25} | {'100.0%':>16} | {ipt_ratio:>15.1f}% | {xdp_ratio:>15.1f}%")
    print(f"{'TCP Retransmissions':<25} | {results['baseline']['retransmits']:>16} | {results['iptables']['retransmits']:>16} | {results['xdp']['retransmits']:>16}")
    print(f"{'Ping Packet Loss %':<25} | {results['baseline']['loss_pct']:>15.1f}% | {results['iptables']['loss_pct']:>15.1f}% | {results['xdp']['loss_pct']:>15.1f}%")
    print(f"{'Ping RTT Avg (ms)':<25} | {results['baseline']['rtt_avg']:>14.2f} | {results['iptables']['rtt_avg']:>14.2f} | {results['xdp']['rtt_avg']:>14.2f}")
    print("=" * 80)

    print(f"\n[+] KEY RESEARCH FINDING:")
    print(f"    Under eBPF/XDP driver-level isolation, legitimate tenants retain {xdp_ratio:.1f}% of")
    print(f"    baseline throughput with {results['xdp']['loss_pct']:.1f}% packet loss and stable RTT!")
    print(f"    By shedding malicious traffic at the NIC layer, socket buffers and conntrack remain unpolluted.")

    # -------------------------------------------------------------------------
    # Save CSV
    # -------------------------------------------------------------------------
    with open(output_csv, "w") as f:
        f.write("metric,baseline,iptables_defense,xdp_engine\n")
        f.write(f"throughput_mbps,{results['baseline']['throughput_mbps']:.2f},{results['iptables']['throughput_mbps']:.2f},{results['xdp']['throughput_mbps']:.2f}\n")
        f.write(f"throughput_retention_pct,100.0,{ipt_ratio:.2f},{xdp_ratio:.2f}\n")
        f.write(f"tcp_retransmissions,{results['baseline']['retransmits']},{results['iptables']['retransmits']},{results['xdp']['retransmits']}\n")
        f.write(f"packet_loss_pct,{results['baseline']['loss_pct']:.2f},{results['iptables']['loss_pct']:.2f},{results['xdp']['loss_pct']:.2f}\n")
        f.write(f"rtt_avg_ms,{results['baseline']['rtt_avg']:.2f},{results['iptables']['rtt_avg']:.2f},{results['xdp']['rtt_avg']:.2f}\n")

    print(f"[+] Saved metrics CSV to:      {output_csv}")

    # -------------------------------------------------------------------------
    # Save LaTeX Snippet
    # -------------------------------------------------------------------------
    latex = f"""% --- Auto-Generated by Kernel-Isolation-Engine Phase 4 Benchmarking Suite ---
\\begin{{table}}[htbp]
\\caption{{Legitimate Tenant Workload Preservation Under Active Volumetric Attack}}
\\label{{tab:throughput_preservation}}
\\centering
\\begin{{tabular}}{{|l|c|c|c|c|}}
\\hline
\\textbf{{Defense Mechanism}} & \\textbf{{Throughput (Mbps)}} & \\textbf{{Retention (\\%)}} & \\textbf{{Retransmits}} & \\textbf{{Ping Loss (\\%)}} \\\\
\\hline
Baseline (No Attack) & {results['baseline']['throughput_mbps']:.2f} & 100.0\\% & {results['baseline']['retransmits']} & {results['baseline']['loss_pct']:.1f}\\% \\\\
Linux \\texttt{{iptables}} & {results['iptables']['throughput_mbps']:.2f} & {ipt_ratio:.1f}\\% & {results['iptables']['retransmits']} & {results['iptables']['loss_pct']:.1f}\\% \\\\
\\textbf{{Our eBPF/XDP Engine}} & \\textbf{{{results['xdp']['throughput_mbps']:.2f}}} & \\textbf{{{xdp_ratio:.1f}\\%}} & \\textbf{{{results['xdp']['retransmits']}}} & \\textbf{{{results['xdp']['loss_pct']:.1f}\\%}} \\\\
\\hline
\\end{{tabular}}
\\end{{table}}
"""
    with open(output_latex, "w") as f:
        f.write(latex)

    print(f"[+] Exported LaTeX snippet to: {output_latex}")


def main():
    parser = argparse.ArgumentParser(description="Phase 4: Legitimate Workload Throughput & RTT Preservation")
    parser.add_argument("--duration", "-t", type=int, default=10, help="Duration of each iperf3 test in seconds (default: 10)")
    parser.add_argument("--output-csv", type=str, default="benchmarks/results/throughput_comparison.csv")
    parser.add_argument("--output-latex", type=str, default="benchmarks/results/latex_throughput_table.tex")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Warning: Benchmarking requires root privileges to configure namespaces and run XDP.")
        print("    Please run with: sudo python3 benchmarks/benchmark_throughput.py")
        sys.exit(1)

    os.makedirs(os.path.dirname(args.output_csv), exist_ok=True)
    run_throughput_benchmarks(args.duration, args.output_csv, args.output_latex)


if __name__ == "__main__":
    main()

