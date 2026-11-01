#!/usr/bin/env bash
set -e

echo "[*] Cleaning up any previous network namespaces and bridge..."
sudo ip netns del ns-victim 2>/dev/null || true
sudo ip netns del ns-legit 2>/dev/null || true
sudo ip netns del ns-attacker 2>/dev/null || true
sudo ip link del br-xdp 2>/dev/null || true

echo "[*] Creating virtual bridge br-xdp (10.10.0.1/24)..."
sudo ip link add name br-xdp type bridge
sudo ip addr add 10.10.0.1/24 dev br-xdp
sudo ip link set dev br-xdp up

create_node() {
    local NS=$1
    local VETH_NS=$2
    local VETH_BR=$3
    local IP=$4

    echo "[+] Provisioning namespace ${NS} with IP ${IP}..."
    sudo ip netns add ${NS}
    sudo ip link add ${VETH_NS} type veth peer name ${VETH_BR}
    sudo ip link set ${VETH_NS} netns ${NS}
    sudo ip link set ${VETH_BR} master br-xdp
    sudo ip link set ${VETH_BR} up
    sudo ip netns exec ${NS} ip link set lo up
    sudo ip netns exec ${NS} ip addr add ${IP}/24 dev ${VETH_NS}
    sudo ip netns exec ${NS} ip link set ${VETH_NS} up
    sudo ip netns exec ${NS} ip route add default via 10.10.0.1
}

# Create Node A (Victim), Node B (Legit), Node C (Attacker)
create_node "ns-victim" "veth-victim" "veth-victim-br" "10.10.0.10"
create_node "ns-legit" "veth-legit" "veth-legit-br" "10.10.0.20"
create_node "ns-attacker" "veth-attack" "veth-attack-br" "10.10.0.30"

# Ensure bridge frames are not prematurely filtered by host iptables
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "[✓] 3-Node Zero-Trust Testbed Active!"
echo "    Victim   (ns-victim)   -> 10.10.0.10"
echo "    Legit    (ns-legit)    -> 10.10.0.20"
echo "    Attacker (ns-attacker) -> 10.10.0.30"
