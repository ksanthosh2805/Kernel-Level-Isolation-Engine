#!/usr/bin/env bash

# Detach any lingering XDP programs from all testbed interfaces
for dev in br-xdp veth-victim-br veth-legit-br veth-attack-br; do
    sudo ip link set dev $dev xdpgeneric off 2>/dev/null || true
    sudo ip link set dev $dev xdp off 2>/dev/null || true
done

echo "[*] Cleaning up network namespaces and bridge..."
sudo ip netns del ns-victim 2>/dev/null || true
sudo ip netns del ns-legit 2>/dev/null || true
sudo ip netns del ns-attacker 2>/dev/null || true
sudo ip link del br-xdp 2>/dev/null || true

echo "[✓] Teardown complete. All namespaces and br-xdp bridge removed."

