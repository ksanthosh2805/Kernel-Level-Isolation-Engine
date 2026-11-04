#!/usr/bin/env bash
# ==============================================================================
# Kernel-Level Zero-Trust Traffic Isolation Engine (eBPF/XDP)
# Phase 5 (v2.0): 16-Node Enterprise Microservice Cluster Teardown
#
# Cleanly destroys the 16-node cluster topology and detaches all XDP hooks:
#   - Kills background attack/benchmark processes
#   - Detaches generic XDP hooks on all 16 veth ports
#   - Deletes virtual bridge br-xdp-v2
#   - Deletes all 16 network namespaces
# ==============================================================================

set -euo pipefail

# ANSI Color Codes
CYAN="\033[1;36m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
BOLD="\033[1m"
RESET="\033[0m"

BRIDGE="br-xdp-v2"

# Check root privileges
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[-] Error: This script must be run as root.${RESET}"
    echo -e "    Please run: ${BOLD}sudo ./topology/teardown_netns_cluster.sh${RESET}"
    exit 1
fi

echo -e "${YELLOW}================================================================================${RESET}"
echo -e "${BOLD}${YELLOW}   TEARING DOWN 16-NODE ENTERPRISE CLUSTER (v2.0)                              ${RESET}"
echo -e "${YELLOW}================================================================================${RESET}"

NAMESPACES=(
    "ns-web-01" "ns-web-02" "ns-web-03" "ns-web-04"
    "ns-api-auth" "ns-api-order" "ns-api-pay" "ns-api-user"
    "ns-db-primary" "ns-db-replica" "ns-redis-cache" "ns-elastic-search"
    "ns-client-alpha" "ns-client-beta" "ns-attk-lateral" "ns-attk-ddos"
)

VETH_PORTS=(
    "veth-w01-br" "veth-w02-br" "veth-w03-br" "veth-w04-br"
    "veth-a01-br" "veth-a02-br" "veth-a03-br" "veth-a04-br"
    "veth-d01-br" "veth-d02-br" "veth-d03-br" "veth-d04-br"
    "veth-c01-br" "veth-c02-br" "veth-x01-br" "veth-x02-br"
)

# 1. Kill lingering processes in namespaces
echo -e "[*] Terminating lingering benchmark and attack processes..."
for NS in "${NAMESPACES[@]}"; do
    if ip netns list | grep -qw "$NS"; then
        ip netns exec "$NS" killall -9 hping3 iperf3 nmap 2>/dev/null || true
    fi
done
killall -9 hping3 iperf3 nmap 2>/dev/null || true

# 2. Detach XDP hooks from host veth ports
echo -e "[*] Stripping generic XDP hooks from 16 bridge member interfaces..."
for DEV in "${VETH_PORTS[@]}"; do
    if ip link show "$DEV" &>/dev/null; then
        ip link set dev "$DEV" xdpgeneric off 2>/dev/null || true
        ip link delete "$DEV" 2>/dev/null || true
    fi
done

# 3. Delete virtual bridge
if ip link show "${BRIDGE}" &>/dev/null; then
    echo -e "[*] Removing virtual bridge: ${BRIDGE}..."
    ip link set dev "${BRIDGE}" xdpgeneric off 2>/dev/null || true
    ip link set dev "${BRIDGE}" down 2>/dev/null || true
    ip link delete "${BRIDGE}" type bridge 2>/dev/null || true
fi

# 4. Delete all 16 network namespaces
echo -e "[*] Deleting 16 network namespaces..."
for NS in "${NAMESPACES[@]}"; do
    if ip netns list | grep -qw "$NS"; then
        ip netns delete "$NS" 2>/dev/null || true
    fi
done

echo -e "\n${BOLD}${GREEN}[+] 16-Node Enterprise Cluster Teardown Complete! Host is clean.${RESET}"

