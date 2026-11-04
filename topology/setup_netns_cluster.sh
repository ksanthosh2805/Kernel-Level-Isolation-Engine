#!/usr/bin/env bash
# ==============================================================================
# Kernel-Level Zero-Trust Traffic Isolation Engine (eBPF/XDP)
# Phase 5 (v2.0): 16-Node Enterprise Microservice Cluster Provisioner
#
# Creates a 16-node 4x4 multi-tier container mesh on subnet 10.20.0.0/24:
#   - Tier 1: Web Ingress (4 nodes: web-01 to web-04)
#   - Tier 2: Microservices (4 nodes: api-auth, api-order, api-pay, api-user)
#   - Tier 3: Database & Cache (4 nodes: db-primary, db-replica, redis, elastic)
#   - Tier 4: Clients & Adversaries (2 clients, 1 lateral scanner, 1 DDoS flooder)
#
# Connected via high-density virtual bridge: br-xdp-v2 (10.20.0.1/24)
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
SUBNET="10.20.0.0/24"
GATEWAY="10.20.0.1"

# Check root privileges
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[-] Error: This script must be run as root.${RESET}"
    echo -e "    Please run: ${BOLD}sudo ./topology/setup_netns_cluster.sh${RESET}"
    exit 1
fi

echo -e "${CYAN}================================================================================${RESET}"
echo -e "${BOLD}${CYAN}   PROVISIONING 16-NODE ENTERPRISE MICROSERVICE CLUSTER (v2.0)                 ${RESET}"
echo -e "${CYAN}================================================================================${RESET}"

# Define 16 Cluster Nodes: (Namespace | IPv4 | Host-Bridge-Veth | Description)
# Interface names strictly <= 15 chars (IFNAMSIZ = 16)
NODES=(
    # Tier 1: Web Ingress
    "ns-web-01:10.20.0.11:veth-w01-br:Web Frontend 01 (Public HTTP/S)"
    "ns-web-02:10.20.0.12:veth-w02-br:Web Frontend 02 (Public HTTP/S)"
    "ns-web-03:10.20.0.13:veth-w03-br:Web Frontend 03 (Public HTTP/S)"
    "ns-web-04:10.20.0.14:veth-w04-br:Web Frontend 04 (Public HTTP/S)"
    # Tier 2: Microservices
    "ns-api-auth:10.20.0.21:veth-a01-br:Auth & Identity Microservice (Port 8080)"
    "ns-api-order:10.20.0.22:veth-a02-br:Order Processing API (Port 8081)"
    "ns-api-pay:10.20.0.23:veth-a03-br:Payment Gateway API (Port 8082)"
    "ns-api-user:10.20.0.24:veth-a04-br:User Profile API (Port 8083)"
    # Tier 3: Stateful Data & Cache
    "ns-db-primary:10.20.0.31:veth-d01-br:PostgreSQL Database Primary (Port 5432)"
    "ns-db-replica:10.20.0.32:veth-d02-br:PostgreSQL Read Replica (Port 5432)"
    "ns-redis-cache:10.20.0.33:veth-d03-br:Redis In-Memory Session Cache (Port 6379)"
    "ns-elastic-search:10.20.0.34:veth-d04-br:Elasticsearch Analytics Node (Port 9200)"
    # Tier 4: Peripheral Clients & Adversaries
    "ns-client-alpha:10.20.0.41:veth-c01-br:Legitimate Consumer Workload Alpha"
    "ns-client-beta:10.20.0.42:veth-c02-br:Legitimate Consumer Workload Beta"
    "ns-attk-lateral:10.20.0.51:veth-x01-br:Compromised Pod (East-West Lateral Scanner)"
    "ns-attk-ddos:10.20.0.52:veth-x02-br:Compromised Pod (Volumetric Flooder)"
)

echo -e "[*] Enabling Linux kernel IPv4 forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Clean up existing bridge if present
if ip link show "${BRIDGE}" &>/dev/null; then
    echo -e "${YELLOW}[!] Existing bridge ${BRIDGE} found. Removing for clean slate...${RESET}"
    ip link set dev "${BRIDGE}" down 2>/dev/null || true
    ip link delete "${BRIDGE}" type bridge 2>/dev/null || true
fi

# Create virtual bridge br-xdp-v2
echo -e "[*] Creating bridge: ${BOLD}${BRIDGE}${RESET} with IP ${BOLD}${GATEWAY}/24${RESET}..."
ip link add name "${BRIDGE}" type bridge
ip addr add "${GATEWAY}/24" dev "${BRIDGE}"
ip link set dev "${BRIDGE}" up

# Optional: Disable bridge netfilter packet mangling
sysctl -w net.bridge.bridge-nf-call-iptables=0 2>/dev/null || true

echo -e "\n[*] Provisioning 16 isolated network namespaces and dual veth pairs..."

for item in "${NODES[@]}"; do
    IFS=":" read -r NS IP BR_VETH DESC <<< "$item"

    # Remove existing namespace if present
    if ip netns list | grep -qw "$NS"; then
        ip netns delete "$NS" 2>/dev/null || true
    fi

    # Create network namespace
    ip netns add "$NS"

    # Generate peer name inside namespace (standard eth0)
    NS_PEER="eth0"

    # Clean existing host interface if present
    ip link delete "$BR_VETH" 2>/dev/null || true

    # Create veth pair
    ip link add "$BR_VETH" type veth peer name "$NS_PEER" netns "$NS"

    # Attach host end to bridge
    ip link set dev "$BR_VETH" master "$BRIDGE"
    ip link set dev "$BR_VETH" up

    # Disable offloads on host veth for deterministic XDP packet inspection
    ethtool -K "$BR_VETH" rx off tx off tso off gso off gro off 2>/dev/null || true

    # Configure namespace loopback and eth0
    ip netns exec "$NS" ip link set dev lo up
    ip netns exec "$NS" ip addr add "${IP}/24" dev "$NS_PEER"
    ip netns exec "$NS" ip link set dev "$NS_PEER" up
    ip netns exec "$NS" ip route add default via "$GATEWAY"

    # Disable offloads inside namespace
    ip netns exec "$NS" ethtool -K "$NS_PEER" rx off tx off tso off gso off gro off 2>/dev/null || true
done

echo -e "${GREEN}[+] Successfully created all 16 namespaces and bridge ports!${RESET}\n"

# Verification Table
echo -e "${CYAN}================================================================================${RESET}"
echo -e "${BOLD}${CYAN}   16-NODE CLUSTER TOPOLOGY INVENTORY (${BRIDGE})${RESET}"
echo -e "${CYAN}================================================================================${RESET}"
printf "%-18s | %-12s | %-14s | %s\n" "Namespace" "IP Address" "Bridge Port" "Cluster Role & Description"
echo -e "-------------------+--------------+----------------+------------------------------------"

for item in "${NODES[@]}"; do
    IFS=":" read -r NS IP BR_VETH DESC <<< "$item"
    printf "%-18s | %-12s | %-14s | %s\n" "$NS" "$IP" "$BR_VETH" "$DESC"
done

echo -e "${CYAN}================================================================================${RESET}"

echo -e "\n[*] Running quick cluster connectivity smoke test..."
if ip netns exec ns-client-alpha ping -c 1 -W 1 10.20.0.11 &>/dev/null; then
    echo -e "${GREEN}[+] Smoke Test PASSED: ns-client-alpha (10.20.0.41) -> ns-web-01 (10.20.0.11) reachable.${RESET}"
else
    echo -e "${YELLOW}[!] Warning: Initial ping probe pending ARP learning.${RESET}"
fi

if ip netns exec ns-attk-lateral ping -c 1 -W 1 10.20.0.31 &>/dev/null; then
    echo -e "${GREEN}[+] Smoke Test PASSED: ns-attk-lateral (10.20.0.51) -> ns-db-primary (10.20.0.31) reachable.${RESET}"
fi

echo -e "\n${BOLD}${GREEN}>>> 16-Node Enterprise Microservice Cluster is READY for Version 2.0!${RESET}"

