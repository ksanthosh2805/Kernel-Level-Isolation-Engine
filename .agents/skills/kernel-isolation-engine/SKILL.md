---
name: kernel-isolation-engine
description: Comprehensive operational runbook and engineering manual for the Kernel-Level Zero-Trust Network Traffic Isolation Engine (eBPF/XDP), covering 3-node netns topology, XDP filters, BCC loaders, dynamic trust decay engine, and multi-terminal verification workflows.
---

# Kernel-Level Zero-Trust Traffic Isolation Engine Skill

Use this skill when developing, testing, verifying, or debugging the Kernel-Level Zero-Trust Traffic Isolation Engine codebase in `/home/daemon_targaryen/kernel-isolation-engine`.

---

## 1. System Architecture & Closed-Loop Mechanics

The engine enforces zero-trust microsegmentation at wire speed directly at the Network Interface Card (NIC) driver layer across three decoupled planes:
1. **Data Plane (`kernel/`)**: C-based eBPF programs attached to XDP (`xdpgeneric`). Intercepts raw packet frames (`xdp_md`) before Linux network stack (`sk_buff`) allocation and connection tracking (`conntrack`). Enforces $O(1)$ policy lookups via `BPF_HASH(policy_map)`.
2. **Control Plane (`daemon/`)**: Python user-space daemons (`bcc`) consuming flow telemetry via `BPF_RINGBUF_OUTPUT(telemetry_ringbuf)`. Runs 1.0-second sliding-window heuristics to calculate workload trust scores ($0.0 - 100.0$) and mutates kernel maps in $15\text{--}45\,\mu\text{s}$.
3. **Presentation Plane (`dashboard/`)**: FastAPI backend broadcasting real-time metrics over WebSockets to an HTML5/Chart.js browser UI.

---

## 2. Directory Layout & Manifest

```text
/home/daemon_targaryen/kernel-isolation-engine/
├── AGENTS.md                                # Workspace conscience and rules of engagement
├── PROJECT_MASTER_GUIDE.md                  # Comprehensive architectural blueprint & future-centric roadmap
├── PROJECT_KNOWLEDGE_BASE.md                # Master knowledge base & manual check logs
├── kernel/                                  # Data Plane
│   ├── xdp_isolation_p1.c                   # Static XDP filter (Ethernet/IPv4, policy_map)
│   └── xdp_isolation_p2.c                   # Dynamic XDP filter (TCP/UDP, ringbuf, suspect throttle)
├── daemon/                                  # Control Plane
│   ├── phase1_loader.py                     # Phase 1 CLI policy controller (block/allow/status)
│   └── trust_daemon.py                      # Phase 2 dynamic trust decay engine & event consumer
├── topology/                                # Virtual Testbed
│   ├── setup_netns.sh                       # 3-node netns topology script
│   └── teardown_netns.sh                    # Teardown script for namespaces & bridge
├── dashboard/                               # Presentation Plane
│   ├── app.py                               # FastAPI & WebSocket server
│   └── static/index.html                    # Frontend dashboard with Chart.js
└── benchmarks/                              # Benchmarking
    └── run_benchmarks.sh                    # Automated benchmarking suite (iperf3, T_isolate, CPU)
```

---

## 3. Testbed Topology Reference (10.10.0.0/24)

- **Bridge Switch**: `br-xdp` (IP: `10.10.0.1/24`) on host root namespace.
- **Node A (Victim)**: `ns-victim` (`10.10.0.10`), host port `veth-victim-br`. Target running Nginx / `iperf3 -s`.
- **Node B (Legitimate)**: `ns-legit` (`10.10.0.20`), host port `veth-legit-br`. Healthy container generating baseline traffic.
- **Node C (Attacker)**: `ns-attacker` (`10.10.0.30`), host port `veth-attack-br`. Compromised container running `nmap` and `hping3`.

---

## 4. Multi-Tier Trust Decay & Self-Healing State Machine

Workloads transition across three states based on Trust Score $T \in [0.0, 100.0]$:
- **`TRUSTED` (0)**: $70.0 \le T \le 100.0$ $\rightarrow$ Line-rate pass (`XDP_PASS`).
- **`SUSPECT` (1)**: $30.0 \le T < 70.0$ $\rightarrow$ Probabilistic rate-limit (Drops SYN bursts & 50% random packets).
- **`QUARANTINED` (2)**: $0.0 \le T < 30.0$ $\rightarrow$ Wire-speed drop (`XDP_DROP`).

### Math Formula:
$$\text{Penalty}(t) = \left(W_{\text{pps}} \times \max(0, \text{PPS} - 80) \times 0.15\right) + \left(W_{\text{syn}} \times \max(0, \text{SYN} - 25) \times 0.45\right) + \left(W_{\text{scan}} \times \max(0, \text{Ports} - 6) \times 4.50\right)$$

$$\text{Trust}(t + \Delta t) = \begin{cases} \max\left(0.0,\; \text{Trust}(t) - \text{Total\_Penalty}(t)\right) & \text{if } \text{Penalty} > 0 \\ \min\left(100.0,\; \text{Trust}(t) + R_{\text{heal}}\right) & \text{if } \text{Penalty} == 0 \end{cases}$$

- Recovery Rate $R_{\text{heal}} = +6.0\,\text{points/sec}$ auto-recovery during peaceful intervals.
- Quarantined sampling: $1:64$ packets emitted to ring buffer via `((bpf_get_prandom_u32() & 0x3F) == 0)` to prevent ring buffer overflow while keeping daemon aware of ongoing attack.

---

## 5. Verification Runbooks

### Runbook 1: Network Topology Verification (Phase 1 Step 1)
**Status: VERIFIED [OK]**
```bash
chmod +x ~/kernel-isolation-engine/topology/*.sh
~/kernel-isolation-engine/topology/setup_netns.sh
sudo ip netns exec ns-legit ping -c 2 10.10.0.10
sudo ip netns exec ns-attacker ping -c 2 10.10.0.10
```

### Runbook 2: Phase 1 Static XDP Filtering (Phase 1 Step 2)
**Status: VERIFIED [OK]** (100% packet loss under quarantine; atomic drop counter increment; sub-millisecond recovery on allow verified)
1. **Terminal 1**: `sudo python3 ~/kernel-isolation-engine/daemon/phase1_loader.py br-xdp`
2. **Terminal 2**: `sudo ip netns exec ns-legit ping 10.10.0.10`
3. **Terminal 3**: `sudo ip netns exec ns-attacker ping 10.10.0.10`
4. **Terminal 1 CLI**:
   - `block 10.10.0.30` $\rightarrow$ Terminal 3 freezes (`XDP_DROP`). Terminal 2 continues unaffected.
   - `status` $\rightarrow$ Displays dropped packet counters.
   - `allow 10.10.0.30` $\rightarrow$ Terminal 3 recovers immediately.
   - `quit` $\rightarrow$ Detaches XDP cleanly.

### Runbook 3: Phase 2 Dynamic Trust Decay Verification
**Status: VERIFIED LIVE [OK]** (Measured $T_{\text{isolate}}$: 27.57–51.89 µs, multi-tier transitions TRUSTED $\rightarrow$ SUSPECT $\rightarrow$ QUARANTINED, autonomous +6.0/s auto-healing, zero impact on legitimate traffic)
1. **Terminal 1**: `sudo python3 ~/kernel-isolation-engine/daemon/trust_daemon.py br-xdp`
2. **Terminal 2**: `sudo ip netns exec ns-victim iperf3 -s`
3. **Terminal 3**: `sudo ip netns exec ns-legit ping 10.10.0.10`
4. **Terminal 4**:
   - Attack A: `sudo ip netns exec ns-attacker nmap -sS -p 1-100 10.10.0.10`
   - Attack B: `sudo ip netns exec ns-attacker hping3 -S -p 80 --faster -c 2500 10.10.0.10`
   - Observe Terminal 1 auto-transitioning `10.10.0.30` into `SUSPECT` then `QUARANTINED` in 27–51 µs, and self-healing back to `TRUSTED` (+6.0/s) when attack ceases.

### Runbook 4: Phase 3 Real-Time Dashboard (Upcoming)
1. Launch daemon + web server: `sudo python3 ~/kernel-isolation-engine/dashboard/app.py`
2. Open browser at `http://localhost:8000`.
3. Launch attack in Terminal 2; observe real-time Chart.js gauges transition from Green (`TRUSTED`) to Amber (`SUSPECT`) to Red (`QUARANTINED`).

### Runbook 5: Phase 4 Quantitative Benchmarks (Upcoming)
1. Execute: `sudo bash ~/kernel-isolation-engine/benchmarks/run_benchmarks.sh`
2. Generates CSV logs for:
   - Mitigation Latency $T_{\text{isolate}}$ ($15\text{--}45\,\mu\text{s}$ vs $3,000\text{--}12,000\,\mu\text{s}$ for `iptables`)
   - CPU utilization under flood
   - Legitimate workload throughput preservation under active attack

---

## 6. Critical Guidelines for Future Agents

- **Verifier Bounds**: Always bounds-check every header before dereferencing: `(void *)(hdr + 1) <= data_end`.
- **Bridge Member Ports**: Inter-container forwarded traffic crosses member ports (`veth-*-br`) directly without hitting `br-xdp`'s RX queue. Attach Generic XDP directly to member ports, and avoid attaching to `br-xdp` concurrently to prevent Netlink `EEXIST` (File exists) upper/slave conflicts.
- **SKB Mode**: Virtual bridge and veth interfaces require Generic SKB mode (`XDP_FLAGS_SKB_MODE = 1 << 1`, value `2`). Do not use `BPF.XDP_FLAGS_SKB_MODE` as BCC's Python class does not expose kernel `if_link.h` mode constants directly.
- **BCC Package**: In Ubuntu APT the package is `python3-bpfcc`, imported as `from bcc import BPF`.
- **Root Context**: Python packages required by root must be installed system-wide (`sudo pip3 install ...`).
- **User Executes**: Never execute long-running interactive loaders in background tasks; provide clean commands for the user's terminal.
- **GitHub Push Policy (Strict User Consent)**: NEVER run `git push` or push updates to the remote GitHub repository automatically or on incremental edits. All commits remain strictly local. Only push to GitHub when the user explicitly gives the command.

