#!/usr/bin/env python3
import os
import sys
import socket
import struct
import ctypes
from bcc import BPF

# Linux Kernel XDP Attachment Flags (from <linux/if_link.h>)
# 1 << 1 (value = 2) specifies Generic / SKB mode, required for virtual interfaces
XDP_FLAGS_SKB_MODE = getattr(BPF, "XDP_FLAGS_SKB_MODE", 1 << 1)

STATE_TRUSTED = 0
STATE_SUSPECT = 1
STATE_QUARANTINED = 2

def ip_to_u32(ip_str):
    return struct.unpack("I", socket.inet_aton(ip_str))[0]

def u32_to_ip(ip_u32):
    return socket.inet_ntoa(struct.pack("I", ip_u32))

def get_target_interfaces(iface_arg):
    """
    If iface_arg is a Linux bridge, returns all its member ports + bridge itself.
    In Linux bridging, inter-container forwarded packets traverse the member ports
    (veth-*-br) directly without entering the bridge device's own RX queue.
    """
    brif_path = f"/sys/class/net/{iface_arg}/brif"
    if os.path.exists(brif_path):
        ports = sorted(os.listdir(brif_path))
        if ports:
            return [iface_arg] + ports
    return [iface_arg]

def main():
    target_arg = sys.argv[1] if len(sys.argv) > 1 else "br-xdp"
    c_file = os.path.join(os.path.dirname(__file__), "../kernel/xdp_isolation_p1.c")

    print(f"[*] Compiling XDP program from {c_file}...")
    b = BPF(src_file=c_file)
    fn = b.load_func("xdp_static_filter", BPF.XDP)

    target_interfaces = get_target_interfaces(target_arg)
    attached_ifaces = []

    print(f"[*] Attaching XDP program (Generic SKB Mode) to interfaces: {', '.join(target_interfaces)}...")
    for iface in target_interfaces:
        try:
            b.attach_xdp(iface, fn, XDP_FLAGS_SKB_MODE)
            attached_ifaces.append(iface)
            print(f"    [+] Attached to '{iface}' [OK]")
        except Exception as e:
            print(f"    [-] WARNING: Could not attach to '{iface}': {e}")

    if not attached_ifaces:
        print("[-] Error: Failed to attach XDP to any interface. Exiting.")
        return

    policy_map = b.get_table("policy_map")
    drop_map = b.get_table("drop_counter_map")
    diag_map = b.get_table("diagnostic_counters")
    last_ip_map = b.get_table("last_intercepted_ip")

    print(f"[✓] Phase 1 Static XDP Isolation Engine is LIVE on: {', '.join(attached_ifaces)}")
    print("Commands: block <IP> | allow <IP> | status | quit")

    try:
        while True:
            cmd = input("xdp-engine> ").strip().split()
            if not cmd:
                continue

            action = cmd[0].lower()

            if action == "block" and len(cmd) == 2:
                ip_int = ip_to_u32(cmd[1])
                ip_key = ctypes.c_uint32(ip_int)
                policy_map[ip_key] = ctypes.c_uint32(STATE_QUARANTINED)
                print(f"[!] QUARANTINED {cmd[1]} (hex: {hex(ip_int)}) -> Kernel Map updated to XDP_DROP.")
            elif action == "allow" and len(cmd) == 2:
                ip_int = ip_to_u32(cmd[1])
                ip_key = ctypes.c_uint32(ip_int)
                policy_map[ip_key] = ctypes.c_uint32(STATE_TRUSTED)
                print(f"[+] TRUSTED {cmd[1]} (hex: {hex(ip_int)}) -> Kernel Map updated to XDP_PASS.")
            elif action == "status":
                print("\n================= Live eBPF Diagnostics =================")
                c_0 = diag_map[ctypes.c_int(0)].value
                c_1 = diag_map[ctypes.c_int(1)].value
                c_2 = diag_map[ctypes.c_int(2)].value
                c_3 = diag_map[ctypes.c_int(3)].value
                last_ip = last_ip_map[ctypes.c_int(0)].value
                last_ip_str = u32_to_ip(last_ip) if last_ip != 0 else "None yet"

                print(f"  Total Frames Intercepted by XDP : {c_0}")
                print(f"  IPv4 Frames Verified            : {c_1}")
                print(f"  Policy Map Matches (Hits)       : {c_2}")
                print(f"  Quarantined Drops Executed      : {c_3}")
                print(f"  Last Source IP Intercepted      : {last_ip_str} (hex: {hex(last_ip)})")
                print("---------------------------------------------------------")
                print("Active Policy Map Entries:")
                if len(policy_map) == 0:
                    print("  (No policies currently configured)")
                for k, v in policy_map.items():
                    ip_str = u32_to_ip(k.value)
                    st_str = "QUARANTINED (DROP)" if v.value == 2 else "TRUSTED (PASS)"
                    drops = drop_map[k].value if k in drop_map else 0
                    print(f"  IP: {ip_str:15s} | State: {st_str:20s} | Dropped Packets: {drops}")
                print("=========================================================\n")
            elif action in ("quit", "exit"):
                break
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        print("\n[*] Detaching XDP programs from interfaces...")
        for iface in attached_ifaces:
            try:
                b.remove_xdp(iface, XDP_FLAGS_SKB_MODE)
                print(f"    [-] Detached from '{iface}' [OK]")
            except Exception as e:
                print(f"    [-] Warning: Could not detach from '{iface}': {e}")
        print("[✓] Cleanly detached all interfaces.")

if __name__ == "__main__":
    main()
