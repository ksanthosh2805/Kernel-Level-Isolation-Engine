#!/usr/bin/env bash
# ==============================================================================
# Kernel-Level Zero-Trust Traffic Isolation Engine (v2.0)
# Phase 5: Master Cluster Quantitative Benchmarking Orchestrator
#
# Automates the 3 Version 2.0 Academic Experiments:
#   1. Blast-Radius Confinement Ratio (B_confine in %)
#   2. Multi-Port Policy Mutation Latency (T_mutate in µs)
#   3. Anti-Flapping Hysteresis Evasion Mitigation (2^(k-1) escalation)
#
# Generates:
#   - benchmarks/results/cluster_benchmark.csv
#   - benchmarks/results/latex_cluster_table.tex
#   - benchmarks/results/CLUSTER_BENCHMARK_REPORT.md
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RESULTS_DIR="${REPO_ROOT}/benchmarks/results"

mkdir -p "${RESULTS_DIR}"

# ANSI Color Codes
CYAN="\033[1;36m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
BOLD="\033[1m"
RESET="\033[0m"

# Safe cleanup trap
cleanup() {
    echo -e "\n${YELLOW}[*] Cleaning up any residual test processes...${RESET}"
    killall -9 hping3 nmap ping 2>/dev/null || true
    iptables -D FORWARD -s 10.20.0.52 -j DROP 2>/dev/null || true
    iptables -D FORWARD -s 10.20.0.99 -j DROP 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo -e "\n${CYAN}==============================================================================${RESET}"
echo -e "${BOLD}  KERNEL ZERO-TRUST ISOLATION ENGINE (v2.0) — CLUSTER BENCHMARKING SUITE${RESET}"
echo -e "${CYAN}==============================================================================${RESET}"

# Verify Root Privileges
if [[ $(id -u) -ne 0 ]]; then
    echo -e "${RED}[!] Error: Running cluster benchmarks requires root privileges (for ip netns and XDP).${RESET}"
    echo -e "${BOLD}    Please execute: sudo bash benchmarks/run_cluster_benchmarks.sh${RESET}\n"
    exit 1
fi

# Check if 16-node cluster topology is initialized
if ! ip link show br-xdp-v2 >/dev/null 2>&1; then
    echo -e "${YELLOW}[!] Warning: br-xdp-v2 bridge not found. Initializing 16-node cluster mesh...${RESET}"
    bash "${REPO_ROOT}/topology/setup_netns_cluster.sh"
fi

# Run the benchmark engine
python3 "${SCRIPT_DIR}/benchmark_cluster.py" "$@"

echo -e "\n${GREEN}==============================================================================${RESET}"
echo -e "${BOLD}  [✓] CLUSTER BENCHMARKS COMPLETE — PUBLICATION ARTIFACTS GENERATED${RESET}"
echo -e "${GREEN}==============================================================================${RESET}"
echo -e "  ├─ CSV Metrics    : ${BOLD}benchmarks/results/cluster_benchmark.csv${RESET}"
echo -e "  ├─ LaTeX Table    : ${BOLD}benchmarks/results/latex_cluster_table.tex${RESET}"
echo -e "  └─ Academic Report: ${BOLD}benchmarks/results/CLUSTER_BENCHMARK_REPORT.md${RESET}\n"

