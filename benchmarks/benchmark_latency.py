#!/usr/bin/env python3
"""
Kernel-Level Zero-Trust Traffic Isolation Engine
Phase 4: Quantitative Benchmarking Suite
Experiment 1: Microsecond Policy Mutation Latency (T_isolate in µs)

Measures and compares atomic policy mutation latency:
  1. eBPF Hash Map Mutation (Kernel BPF_HASH table update via BCC)
  2. Linux Netfilter iptables Rule Insertion (iptables -A INPUT -s <IP> -j DROP)

Outputs:
  - Terminal statistical summary table
  - CSV log: benchmarks/results/latency_comparison.csv
  - IEEE/ACM format LaTeX table snippet for thesis publication
"""

import os
import sys
import time
import math
import argparse
import socket
import struct
import ctypes
import subprocess
from typing import List, Dict, Any, Tuple

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False


def ip_to_u32(ip_str: str) -> int:
    """Convert IPv4 string to 32-bit unsigned integer (network byte order)."""
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]


def u32_to_ip(ip_int: int) -> str:
    """Convert 32-bit unsigned integer to IPv4 string."""
    return socket.inet_ntoa(struct.pack("!I", ip_int))


def compute_statistics(samples: List[float]) -> Dict[str, float]:
    """Calculate statistical distribution metrics for latency samples."""
    if not samples:
        return {
            "count": 0, "mean": 0.0, "median": 0.0, "min": 0.0, "max": 0.0,
            "p95": 0.0, "p99": 0.0, "stddev": 0.0
        }
    sorted_s = sorted(samples)
    n = len(sorted_s)
    mean_val = sum(sorted_s) / n
    variance = sum((x - mean_val) ** 2 for x in sorted_s) / (n - 1) if n > 1 else 0.0
    stddev_val = math.sqrt(variance)

    def percentile(p: float) -> float:
        idx = int(math.ceil(p * n)) - 1
        return sorted_s[max(0, min(idx, n - 1))]

    median_val = sorted_s[n // 2] if n % 2 != 0 else (sorted_s[n // 2 - 1] + sorted_s[n // 2]) / 2.0

    return {
        "count": n,
        "mean": mean_val,
        "median": median_val,
        "min": sorted_s[0],
        "max": sorted_s[-1],
        "p95": percentile(0.95),
        "p99": percentile(0.99),
        "stddev": stddev_val
    }


def benchmark_ebpf_latency(iterations: int, warmup: int = 5) -> Tuple[List[float], Dict[str, float]]:
    """Benchmark eBPF policy_map atomic hash mutation latency in microseconds."""
    print(f"[*] Initializing eBPF BPF_HASH map benchmark (BCC)...")
    
    # Inline minimalist BPF map for pure kernel map update measurement
    bpf_code = """
    #include <uapi/linux/bpf.h>
    BPF_HASH(policy_map, u32, u32, 2048);
    """
    try:
        bpf = BPF(text=bpf_code)
        policy_map = bpf.get_table("policy_map")
    except Exception as e:
        print(f"[-] Error loading eBPF map: {e}")
        return [], {}

    # Warmup cycles
    for i in range(warmup):
        k = ctypes.c_uint32(ip_to_u32(f"192.0.2.{i + 1}"))
        v = ctypes.c_uint32(2)  # STATE_QUARANTINED
        policy_map[k] = v

    # Timed iterations
    samples_us: List[float] = []
    base_ip = ip_to_u32("198.51.100.1")

    for i in range(iterations):
        k = ctypes.c_uint32(base_ip + i)
        v = ctypes.c_uint32(2)  # STATE_QUARANTINED

        t0 = time.perf_counter_ns()
        policy_map[k] = v
        t1 = time.perf_counter_ns()

        lat_us = (t1 - t0) / 1000.0
        samples_us.append(lat_us)

    stats = compute_statistics(samples_us)
    return samples_us, stats


def benchmark_iptables_latency(iterations: int, warmup: int = 3) -> Tuple[List[float], Dict[str, float]]:
    """Benchmark Linux iptables rule insertion latency in microseconds."""
    print(f"[*] Initializing Linux iptables rule insertion benchmark...")
    samples_us: List[float] = []
    test_ips: List[str] = []

    # Generate synthetic IP range (RFC 5737 TEST-NET-2)
    base_int = ip_to_u32("198.51.100.1")
    for i in range(iterations + warmup):
        test_ips.append(u32_to_ip(base_int + i))

    # Warmup cycles
    for i in range(warmup):
        ip = test_ips[i]
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    # Timed iterations
    print(f"[*] Running {iterations} iptables rule insertions (measuring system call overhead)...")
    for i in range(warmup, warmup + iterations):
        ip = test_ips[i]
        
        t0 = time.perf_counter_ns()
        res = subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        t1 = time.perf_counter_ns()

        if res.returncode == 0:
            lat_us = (t1 - t0) / 1000.0
            samples_us.append(lat_us)
            # Immediate cleanup to avoid growing rule list during test
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        else:
            print(f"[-] Warning: iptables insertion failed for {ip}")

    stats = compute_statistics(samples_us)
    return samples_us, stats


def generate_latex_table(ebpf_stats: Dict[str, float], iptables_stats: Dict[str, float], n: int) -> str:
    """Format benchmark results into an IEEE/ACM compatible LaTeX table snippet."""
    speedup = (iptables_stats["mean"] / ebpf_stats["mean"]) if ebpf_stats["mean"] > 0 else 0.0
    
    latex = f"""% --- Auto-Generated by Kernel-Isolation-Engine Phase 4 Benchmarking Suite ---
\\begin{{table}}[htbp]
\\caption{{Empirical Policy Mutation Latency ($T_{{\\text{{isolate}}}}$) Comparison ($N={n}$)}}
\\label{{tab:mutation_latency}}
\\centering
\\begin{{tabular}}{{|l|c|c|c|c|c|c|}}
\\hline
\\textbf{{Mechanism}} & \\textbf{{Mean ($\\mu$s)}} & \\textbf{{Median ($\\mu$s)}} & \\textbf{{Min ($\\mu$s)}} & \\textbf{{Max ($\\mu$s)}} & \\textbf{{$P_{{95}}$ ($\\mu$s)}} & \\textbf{{StdDev ($\\sigma$)}} \\\\
\\hline
Linux \\texttt{{iptables}} & {iptables_stats['mean']:.2f} & {iptables_stats['median']:.2f} & {iptables_stats['min']:.2f} & {iptables_stats['max']:.2f} & {iptables_stats['p95']:.2f} & {iptables_stats['stddev']:.2f} \\\\
\\textbf{{Our eBPF Map Engine}} & \\textbf{{{ebpf_stats['mean']:.2f}}} & \\textbf{{{ebpf_stats['median']:.2f}}} & \\textbf{{{ebpf_stats['min']:.2f}}} & \\textbf{{{ebpf_stats['max']:.2f}}} & \\textbf{{{ebpf_stats['p95']:.2f}}} & \\textbf{{{ebpf_stats['stddev']:.2f}}} \\\\
\\hline
\\multicolumn{{7}}{{|c|}}{{\\textbf{{Acceleration Factor: $\\sim${speedup:.1f}$\\times$ Faster Policy Enforcement}}}} \\\\
\\hline
\\end{{tabular}}
\\end{{table}}
"""
    return latex


def main():
    parser = argparse.ArgumentParser(description="Phase 4: Policy Mutation Latency (T_isolate) Benchmark")
    parser.add_argument("--iterations", "-n", type=int, default=100, help="Number of test iterations (default: 100)")
    parser.add_argument("--warmup", "-w", type=int, default=5, help="Number of warmup iterations (default: 5)")
    parser.add_argument("--output-csv", type=str, default="benchmarks/results/latency_comparison.csv",
                        help="Path to export CSV results")
    parser.add_argument("--output-latex", type=str, default="benchmarks/results/latex_latency_table.tex",
                        help="Path to export LaTeX table snippet")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Warning: This benchmark requires root privileges for eBPF and iptables operations.")
        print("    Please run with: sudo python3 benchmarks/benchmark_latency.py")
        sys.exit(1)

    if not BCC_AVAILABLE:
        print("[-] Error: Python BCC module not found. Install with: sudo apt install python3-bpfcc")
        sys.exit(1)

    os.makedirs(os.path.dirname(args.output_csv), exist_ok=True)

    print("================================================================================")
    print("   EXPERIMENT 1: POLICY MUTATION LATENCY (T_isolate in Microseconds)            ")
    print("   Comparing Atomic eBPF Map Update vs Linux Netfilter iptables Rule Insertion  ")
    print("================================================================================")
    print(f"[*] Configuration: Iterations N={args.iterations}, Warmup={args.warmup}")
    print()

    # 1. Benchmark eBPF Hash Map
    ebpf_samples, ebpf_stats = benchmark_ebpf_latency(args.iterations, args.warmup)

    # 2. Benchmark iptables
    ipt_samples, ipt_stats = benchmark_iptables_latency(args.iterations, args.warmup)

    if not ebpf_samples or not ipt_samples:
        print("[-] Benchmarking failed to collect samples.")
        sys.exit(1)

    speedup = ipt_stats["mean"] / ebpf_stats["mean"] if ebpf_stats["mean"] > 0 else 0.0

    # 3. Print ANSI Comparison Table
    print("\n" + "=" * 80)
    print(f"{'METRIC':<22} | {'eBPF policy_map':<24} | {'Linux iptables':<24}")
    print("-" * 80)
    print(f"{'Sample Count (N)':<22} | {ebpf_stats['count']:<24} | {ipt_stats['count']:<24}")
    print(f"{'Mean Latency':<22} | {ebpf_stats['mean']:>18.2f} µs | {ipt_stats['mean']:>18.2f} µs")
    print(f"{'Median Latency':<22} | {ebpf_stats['median']:>18.2f} µs | {ipt_stats['median']:>18.2f} µs")
    print(f"{'Minimum Latency':<22} | {ebpf_stats['min']:>18.2f} µs | {ipt_stats['min']:>18.2f} µs")
    print(f"{'Maximum Latency':<22} | {ebpf_stats['max']:>18.2f} µs | {ipt_stats['max']:>18.2f} µs")
    print(f"{'95th Percentile (P95)':<22} | {ebpf_stats['p95']:>18.2f} µs | {ipt_stats['p95']:>18.2f} µs")
    print(f"{'99th Percentile (P99)':<22} | {ebpf_stats['p99']:>18.2f} µs | {ipt_stats['p99']:>18.2f} µs")
    print(f"{'Standard Dev (σ)':<22} | {ebpf_stats['stddev']:>18.2f} µs | {ipt_stats['stddev']:>18.2f} µs")
    print("=" * 80)
    print(f"\n[+] KEY RESEARCH FINDING:")
    print(f"    eBPF/XDP atomic policy mutation is {speedup:.1f}x FASTER than Linux iptables!")
    print(f"    (eBPF Mean: {ebpf_stats['mean']:.2f} µs vs iptables Mean: {ipt_stats['mean']:.2f} µs)")

    # 4. Save CSV Output
    with open(args.output_csv, "w") as f:
        f.write("iteration,ebpf_latency_us,iptables_latency_us\n")
        min_len = min(len(ebpf_samples), len(ipt_samples))
        for i in range(min_len):
            f.write(f"{i + 1},{ebpf_samples[i]:.3f},{ipt_samples[i]:.3f}\n")
        f.write("\n# Summary Statistics\n")
        f.write(f"# ebpf_mean_us,{ebpf_stats['mean']:.3f}\n")
        f.write(f"# iptables_mean_us,{ipt_stats['mean']:.3f}\n")
        f.write(f"# speedup_factor,{speedup:.2f}\n")

    print(f"[+] Saved raw samples and statistics to: {args.output_csv}")

    # 5. Save LaTeX Output
    latex_table = generate_latex_table(ebpf_stats, ipt_stats, args.iterations)
    with open(args.output_latex, "w") as f:
        f.write(latex_table)

    print(f"[+] Exported LaTeX table snippet to:     {args.output_latex}")


if __name__ == "__main__":
    main()

