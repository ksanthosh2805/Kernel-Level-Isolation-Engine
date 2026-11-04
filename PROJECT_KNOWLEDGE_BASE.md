# Kernel-Level Zero-Trust Network Traffic Isolation Engine
## Master Knowledge Base, Memory Mapping & Project Conscience

> **Document Purpose**: Serves as the persistent knowledge mapping, technical memory, and manual check registry for the Kernel-Level Zero-Trust Traffic Isolation Engine project. Ensures any agent or collaborator opening this workspace retains continuous, exact context regarding project scope, architecture, current status, and future roadmap.

---

### 1. Executive Summary & Problem Formulation

In containerized cloud environments, traditional firewalls (`iptables`, `nftables`) and service meshes (Envoy, Istio) suffer from:
1. **Resource Asymmetry under Volumetric Flood**: The Linux kernel allocates heavy `sk_buff` (~256+ bytes plus DMA overhead) and registers connection tracking (`conntrack`) before netfilter firewall rules execute. Volumetric SYN floods saturate CPU cores (`ksoftirqd`), starving legitimate workloads.
2. **Perimeter-Only Trust & East-West Blindness**: Perimeter security groups only filter North-South traffic. Once a container is compromised (via RCE or application vulnerability), internal bridge traffic is implicitly trusted, allowing lateral movement and port scans to go undetected.

**The Solution**: Intercept raw Ethernet frames at the NIC driver layer using **eBPF/XDP** (`struct xdp_md`) before `sk_buff` allocation. Couple this kernel-level performance with a user-space Python daemon consuming an **eBPF Ring Buffer** to evaluate flow entropy, calculate trust scores ($0.0 - 100.0$), and atomically update kernel eBPF maps in microseconds.

---

### 2. High-Level Concept Analogy

- **Traditional Firewall (`iptables`)**: A visitor arrives at a corporate office. The receptionist invites them inside, fills out a paper visitor log, prints a badge, and escorts them to a lobby checkpoint before checking a security blacklist. During a crowd rush, the lobby is overrun and the building freezes.
- **XDP (eXpress Data Path)**: The **Outer Parking Lot Security Gate**. Frames are inspected at the earliest possible physical entry point and dropped in nanoseconds (`XDP_DROP`) before entering kernel memory.
- **eBPF (Extended Berkeley Packet Filter)**: The **Guard's Synchronized Digital Tablet**. A safe, sandboxed in-kernel virtual machine with shared hash tables (`BPF_HASH`) allowing instantaneous lookup of dynamic trust scores.

---

### 3. Three-Plane System Architecture

| Plane | Execution Space | Core Technologies | Functional Responsibilities |
| :--- | :--- | :--- | :--- |
| **Plane 1: Data Plane (Kernel Space)** | Linux Kernel (NIC Driver Hook) | Restricted C, XDP (`xdpgeneric`/SKB mode), eBPF Hash Maps, eBPF Ring Buffer | Parses Ethernet/IPv4/TCP/UDP headers; performs $O(1)$ source IP lookups in `policy_map`; enforces `TRUSTED` (`XDP_PASS`), `SUSPECT` (50% probabilistic rate-limit drop), or `QUARANTINED` (`XDP_DROP`); pushes lightweight flow events to `telemetry_ringbuf`. |
| **Plane 2: Control Plane (User Space)** | User Space Daemon (Root Privilege) | Python 3, `python3-bpfcc` (BCC), Sliding-Window Heuristics | Continuously polls `telemetry_ringbuf`; aggregates 1.0-second sliding windows (PPS, TCP SYNs, unique destination ports); evaluates the Trust Decay & Recovery state machine; atomically mutates kernel `policy_map` in $15\text{--}45\,\mu\text{s}$. |
| **Plane 3: Presentation Plane (Observability)** | User Space Web Server & Browser | FastAPI, Uvicorn, WebSockets, HTML5, Chart.js | Streams live telemetry, workload trust score trajectories, kernel drop counters, and state transitions over WebSockets with zero database bottleneck. |

---

### 4. Step-by-Step Packet Lifecycle

```text
[ Incoming Frame at NIC (br-xdp) ]
               │
               ▼
   [ 1. XDP Driver Hook Invocation (xdp_dynamic_isolation) ]
               │
               ▼
   [ 2. Bounds-Checked Parsing (Ethernet -> IPv4 -> TCP/UDP) ]
               │ (Non-IPv4 / ARP -> XDP_PASS to preserve L2 connectivity)
               ▼
   [ 3. O(1) Policy Map Lookup (policy_map[src_ip]) ]
               │
       ┌───────┴────────────────────────┐
       ▼                                ▼
[ Quarantined (State 2) ]        [ Suspect (State 1) ]        [ Trusted (State 0) ]
       │                                │                                │
Drop instantly at driver         Drop 50% & SYN bursts            Line-rate pass
(Atomic counter increment)       (Atomic counter increment)       (XDP_PASS)
       │                                │                                │
Sample 1:64 to Ringbuf           100% to Ringbuf                  100% to Ringbuf
       │                                │                                │
       └────────────────────────────────┴────────────────────────────────┘
                                        │
                                        ▼
                  [ 4. Ring Buffer Telemetry Stream (telemetry_ringbuf) ]
                                        │
                                        ▼
                  [ 5. User-Space Daemon Sliding Window Evaluation (1.0s) ]
                     - Volumetric Flood Check: PPS > 80
                     - TCP SYN Flood Check: SYNs > 25
                     - Port Scan Check: Unique Ports > 6
                                        │
                                        ▼
                  [ 6. Trust Score Decay / Self-Healing Recovery ]
                     - Malicious activity: Trust decays proportionally
                     - Peaceful window: Trust self-heals by +6.0 pts/sec
                                        │
                                        ▼
                  [ 7. Atomic Kernel eBPF Map Update (T_isolate: 15-45 µs) ]
                     - Mutates policy_map[src_ip] in real time
                     - Broadcasts telemetry payload over WebSocket to UI
```

---

### 5. Multi-Tier Trust Decay & Self-Healing State Machine

#### 5.1 Security States

| Security State | Map Value | Trust Score Range ($T$) | Kernel XDP Action | Behavioral Trigger Condition |
| :--- | :---: | :---: | :--- | :--- |
| **`TRUSTED`** | `0` | $70.0 \le T \le 100.0$ | `XDP_PASS` (100% Line Rate) | Workload exhibits baseline connection rates and low port entropy. Restored automatically when recovering above 70.0. |
| **`SUSPECT`** | `1` | $30.0 \le T < 70.0$ | Probabilistic Rate-Limit (50% burst drop) | Triggered when PPS ($>80$), SYNs ($>25$), or unique ports ($>6$) exceed thresholds. Protects victim while evaluating if spike is transient. |
| **`QUARANTINED`** | `2` | $0.0 \le T < 30.0$ | `XDP_DROP` at NIC Driver (100% Isolation) | Triggered by sustained volumetric flood (`hping3`) or aggressive port scan (`nmap`). Recovers only after quiet cooldown. |

#### 5.2 Mathematical Equations
- Sliding Window Duration: $\Delta t = 1.0\,\text{second}$
- Behavioral Penalty Calculations:
  $$P_{\text{pps}}(t) = \min\left(45.0,\; \max(0, \text{PPS}(t) - 80) \times 0.15\right)$$
  $$P_{\text{syn}}(t) = \min\left(50.0,\; \max(0, \text{SYN\_Count}(t) - 25) \times 0.45\right)$$
  $$P_{\text{scan}}(t) = \min\left(60.0,\; \max(0, \text{Unique\_Ports}(t) - 6) \times 4.50\right)$$
  $$\text{Total\_Penalty}(t) = P_{\text{pps}}(t) + P_{\text{syn}}(t) + P_{\text{scan}}(t)$$
- State Transition & Self-Healing Update Rule:
  $$\text{Trust}(t + \Delta t) = \begin{cases} \max\left(0.0,\; \text{Trust}(t) - \text{Total\_Penalty}(t)\right) & \text{if } \text{Total\_Penalty}(t) > 0 \\ \min\left(100.0,\; \text{Trust}(t) + R_{\text{heal}}\right) & \text{if } \text{Total\_Penalty}(t) = 0 \end{cases}$$
  *(where $R_{\text{heal}} = +6.0\,\text{points/sec}$)*

---

### 6. Testbed Topology Reference (10.10.0.0/24)

```text
               +---------------------------------------------------+
               |               Host Linux Bridge                   |
               |                    br-xdp                         |
               |                 10.10.0.1/24                      |
               +---------+-------------------+-----------------+---+
                         |                   |                 |
            veth-victim-br|       veth-legit-br|    veth-attack-br|
                         |                   |                 |
            veth-victim  |       veth-legit   |    veth-attack   |
               +---------+---+       +-------+-----+   +-------+-------+
               |  ns-victim  |       |   ns-legit  |   |  ns-attacker  |
               | 10.10.0.10  |       | 10.10.0.20  |   |  10.10.0.30   |
               |  Node A     |       |  Node B     |   |   Node C      |
               | (Victim/Svc)|       | (Legit/Ping)|   | (Attacker)    |
               +-------------+       +-------------+   +---------------+
```

---

### 7. Complete Project Directory & File Tree

```text
/home/daemon_targaryen/kernel-isolation-engine/
├── AGENTS.md                                # Root conscience file automatically ingested by any Antigravity agent
├── PROJECT_MASTER_GUIDE.md                  # Comprehensive architectural blueprint & future-centric roadmap
├── PROJECT_KNOWLEDGE_BASE.md                # Master knowledge base, manual checks, and operational reference
├── PROJECT_CHANGELOG.md                     # Persistent chronological audit log of all edits and milestones
├── .agents/
│   ├── hooks.json                           # Lifecycle event hooks (PreInvocation pulse, PostToolUse audit)
│   ├── scripts/
│   │   ├── pulse_hook.py                    # PreInvocation session state & roadmap recall hook
│   │   ├── post_edit_hook.py                # PostToolUse file edit logger
│   │   └── checkpoint.py                    # Milestone synchronizer CLI
│   ├── state/
│   │   ├── project_state.json               # Machine-readable single source of truth for project state
│   │   └── audit_log.jsonl                  # Append-only tool execution & file audit log
│   └── skills/
│       └── kernel-isolation-engine/
│           └── SKILL.md                     # Antigravity skill for autonomous pair programming on this engine
├── kernel/                                  # Data Plane (Kernel-Space eBPF / XDP C programs)
│   ├── xdp_isolation_p1.c                   # [Phase 1 - Created] Static XDP packet filter (hash map drop)
│   └── xdp_isolation_p2.c                   # [Phase 2 - Architecture Ready] Dynamic XDP filter with Ringbuf
├── daemon/                                  # Control Plane (User-Space Python daemons)
│   ├── phase1_loader.py                     # [Phase 1 - Created] BCC loader & interactive CLI controller
│   └── trust_daemon.py                      # [Phase 2 - Architecture Ready] Closed-loop Trust Decay Engine
├── topology/                                # Virtual Testbed (Network Namespaces & Linux Bridge)
│   ├── setup_netns.sh                       # [Phase 1 - Created & Verified OK] 3-node netns topology script
│   └── teardown_netns.sh                    # [Phase 1 - Created] Teardown script for netns & bridge
├── dashboard/                               # Presentation Plane (FastAPI + WebSocket + Chart.js)
│   ├── app.py                               # [Phase 3 - COMPLETED & VERIFIED] FastAPI backend, dual-mode engine & attack API
│   └── static/
│       ├── index.html                       # [Phase 3 - COMPLETED & VERIFIED] Real-time Chart.js dashboard & topology canvas
│       ├── css/style.css                    # [Phase 3 - COMPLETED & VERIFIED] High-performance obsidian dark mode design system
│       └── js/app.js                        # [Phase 3 - COMPLETED & VERIFIED] WebSocket stream consumer & interactive animator
└── benchmarks/                              # Evaluation & Performance Metrics
    ├── benchmark_latency.py                 # [Phase 4 - COMPLETED & VERIFIED] Microsecond T_isolate benchmark (N=100)
    ├── benchmark_cpu.py                     # [Phase 4 - COMPLETED & VERIFIED] Volumetric DDoS CPU & softirq monitor
    ├── benchmark_throughput.py              # [Phase 4 - COMPLETED & VERIFIED] Legitimate tenant throughput & ping RTT tester
    ├── run_benchmarks.sh                    # [Phase 4 - COMPLETED & VERIFIED] Master benchmark orchestrator & report generator
    └── results/                             # [Phase 4 - COMPLETED & VERIFIED] Benchmark metrics, CSVs & LaTeX tables
        ├── latency_comparison.csv           # Raw N=100 latency samples (Mean: 4.04 µs vs 7000.16 µs)
        ├── cpu_comparison.csv               # CPU & softirq metrics (67.7% peak vs 77.5%, 18.2% lower kernel load)
        ├── throughput_comparison.csv        # iperf3 & ping retention (232 vs 1434 retransmits, 0.04 ms RTT)
        ├── latex_*.tex                      # Publication-ready IEEE/ACM LaTeX tables
        └── BENCHMARK_REPORT.md              # Consolidated empirical thesis evaluation report
```

---

### 8. Verification History & Milestone Registry

- **Latest Checkpoint (2026-11-05 01:03:12)**: Ingested complete conversational history, faculty feedback, architectural rationales (Ideas A, B, C unified), and persistent conscience directive into knowledge base and agent rules. *Next*: Step 2: Author 16-port eBPF kernel datapath (kernel/xdp_isolation_v2.c) with LRU policy map and East-West matrix.
- **Phase 0: Environment & Dependencies**:
  - Toolchain installed on Ubuntu 22.04 LTS: `clang`, `llvm`, `libbpf-dev`, `python3-bpfcc`, `bpftool`, `iproute2`, `iperf3`, `hping3`, `nmap`, `fastapi`, `uvicorn`, `websockets`.
  - **Status: VERIFIED [OK]**

- **Phase 1: 3-Node Virtual Testbed & Static XDP Driver Enforcement**:
  - **Status: COMPLETED & VERIFIED [OK]**
  - **Step 1 (3-Node Netns Connectivity)**: **VERIFIED [OK]** by user. Both `ns-legit` and `ns-attacker` ping `ns-victim` through `br-xdp`.
  - **Step 2 (Multi-Terminal Static XDP Verification)**: **VERIFIED [OK]** by user. Quarantining `10.10.0.30` drops packets at wire speed with 100% loss, kernel `drop_counter_map` increments atomically, and `allow` triggers instant sub-millisecond recovery.

- **Phase 2: Ring Buffer Telemetry & Dynamic Trust Decay Engine**:
  - **Status: COMPLETED & FULLY VERIFIED LIVE [OK]**
  - **Verification Date**: 2026-11-01 23:02:04
  - **Data Plane Filter**: `kernel/xdp_isolation_p2.c` — L4 TCP/UDP parsing, TCP SYN inspection, 3-tier state enforcement (`TRUSTED`, `SUSPECT`, `QUARANTINED`), and 32-byte `flow_event_t` streaming over `BPF_RINGBUF_OUTPUT(telemetry_ringbuf, 256)`.
  - **Control Plane Daemon**: `daemon/trust_daemon.py` — 1.0-second sliding-window heuristics, mathematical decay, autonomous $+6.0\,\text{pts/sec}$ self-healing, and microsecond `policy_map` mutations.
  - **Empirical Measured Latencies ($T_{\text{isolate}}$)**:
    - Attack 1 Isolation: **27.57 µs** (Score: 7.8 | Penalty: 92.2 $\rightarrow$ `QUARANTINED`)
    - Self-Healing Step 1: **42.24 µs** (Score: 32.4 $\rightarrow$ `SUSPECT`)
    - Full Self-Healing: **31.71 µs** (Score: 75.4 $\rightarrow$ `TRUSTED`)
    - Attack 2 Re-Quarantine: **51.89 µs** (Score: 8.2 | Penalty: 91.8 $\rightarrow$ `QUARANTINED`)
  - **Workload Preservation**: Legitimate node (`10.10.0.20`) maintained 100.0% trust with zero packet drops during full active flood on victim (`10.10.0.10`).

- **Phase 3: Real-Time Observability Presentation Plane**:
  - **Status: COMPLETED & VERIFIED LIVE [OK]**
  - **Backend Server**: `dashboard/app.py` — FastAPI application providing `/ws/telemetry` WebSocket streaming, dual-mode engine (Live Kernel eBPF + Interactive Simulator), and REST attack simulation APIs (`/api/attack/start`, `/api/attack/stop`, `/api/policy/override`).
  - **Frontend UI**: `dashboard/static/index.html` + `css/style.css` + `js/app.js` — High-performance dark mode dashboard featuring 4 Chart.js charts (PPS, Trust Trajectory, Penalty Breakdown, Latency Comparison), animated topology particle flow canvas with driver-level drop collision, and microsecond transition audit feed.
  - **Dual Mirroring**: Preserved live terminal ASCII dashboard printing in `app.py` matching Phase 2, allowing concurrent monitoring in both terminal and web browser.
  - **Performance Optimization**: Eliminated 15+ CSS `backdrop-filter: blur()` instances and HTML5 canvas `shadowBlur` operations, achieving silky-smooth 60 FPS scrolling and responsive UI interactions even on software-rendered Linux displays.

- **Phase 4: Comparative Benchmarking & Thesis Evaluation**:
  - **Status: COMPLETED & FULLY VERIFIED LIVE [OK]**
  - **Verification Date**: 2026-11-04 23:59:00 UTC
  - **Master Runner**: `benchmarks/run_benchmarks.sh` — Automated end-to-end benchmarking harness.
  - **Empirical Experiment 1: Policy Mutation Latency ($T_{\text{isolate}}$)**:
    - Sample Count: $N = 100$ iterations.
    - Our eBPF Engine Mean: **$4.04\,\mu\text{s}$** (Median: **$2.09\,\mu\text{s}$**, Min: $2.00\,\mu\text{s}$, $P_{95} = 3.18\,\mu\text{s}$, StdDev: $17.62\,\mu\text{s}$).
    - Linux Netfilter `iptables` Mean: **$7,000.16\,\mu\text{s}$** (Median: $6,567.25\,\mu\text{s}$, Min: $3,741.83\,\mu\text{s}$, $P_{95} = 10,912.95\,\mu\text{s}$).
    - **Academic Finding**: eBPF hash map mutation is **$\mathbf{1,732.6\times}$ faster** than `iptables` rule insertions.
  - **Empirical Experiment 2: Volumetric DDoS CPU Survivability**:
    - Under active `hping3 --flood` from `ns-attacker`:
    - Peak Host CPU: Bounded at **$67.70\%$** under XDP vs **$77.50\%$** under `iptables`.
    - Peak Kernel SoftIRQ: **$65.84\%$** under XDP vs **$95.71\%$** under `iptables` ($29.87\%$ reduction in softirq saturation).
    - Kernel/System Load: **$63.93\%$** under XDP vs **$82.12\%$** under `iptables` (**$18.19\%$ reduction in kernel CPU cycles**).
  - **Empirical Experiment 3: Legitimate Tenant Workload Preservation**:
    - Tested legitimate traffic (`ns-legit` $\rightarrow$ `ns-victim`) during active attack flood:
    - TCP Retransmissions: **$232$** under eBPF/XDP vs **$1,434$** under `iptables` (**$\mathbf{6.18\times}$ fewer retransmissions**).
    - ICMP Ping RTT: **$0.04\,\text{ms}$** under eBPF/XDP vs **$0.06\,\text{ms}$** under `iptables` ($33.3\%$ lower latency).
    - Packet Loss: **$0.0\%$** across all trials under XDP micro-isolation.

---

### 9. Complete Troubleshooting Reference

| Error Encountered | Root Cause | Verified Permanent Fix |
| :--- | :--- | :--- |
| `Failed to attach BPF to device ...: File exists (EEXIST)` | Linux kernel prevents attaching Generic XDP to bridge slave ports (`veth-*-br`) when the bridge master (`br-xdp`) already has XDP attached, or if stale XDP programs remain from prior runs. | 1. Attach directly to member ports (`veth-*-br`) where inter-container frames enter the host, bypassing the bridge device hook.<br/>2. Run `force_detach_interface()` on startup to strip any stale programs via `BPF.remove_xdp(dev, flags)` and `ip link set dev <dev> xdpgeneric off`. |
| `Ingress Frames Intercepted: 0` for container traffic | In Linux bridging, inter-container forwarded packets (`10.10.0.30` $\rightarrow$ `10.10.0.10`) traverse bridge member ports directly without entering the bridge master's (`br-xdp`) own RX queue. | Attach XDP directly to the member endpoints (`veth-attack-br`, `veth-legit-br`, `veth-victim-br`). |
| In-memory bytecode retention across code edits | In Linux/Python, modifying a `.py` file on disk while a daemon is running in a terminal does NOT reload the code in RAM; the process keeps executing the old loop. | Stop the running process (`Ctrl+C` or `sudo pkill -9 -f trust_daemon.py`) before launching the updated script. |
| `E: Unable to locate package python3-bcc` | Debian/Ubuntu APT packages Python 3 BCC bindings as `python3-bpfcc` in universe repo. | Run `sudo add-apt-repository universe -y && sudo apt install python3-bpfcc`. Import in Python remains `from bcc import BPF`. |
| `bash: !": event not found` | GNU Bash treats `!` in double quotes as history expansion. | Remove `!` from double-quoted strings (e.g. use `'BCC Ready'` instead of `"BCC Ready!"`). |
| `ModuleNotFoundError: No module named 'fastapi'` | Pip installed packages only for regular user, while XDP daemons execute as `root` via `sudo`. | Install system-wide: `sudo pip3 install fastapi "uvicorn[standard]" websockets pydantic psutil`. |
| `AttributeError: type object 'BPF' has no attribute 'XDP_FLAGS_SKB_MODE'` | Python BCC class `BPF` does not export kernel `if_link.h` XDP mode constants. | Define `XDP_FLAGS_SKB_MODE = getattr(BPF, "XDP_FLAGS_SKB_MODE", 1 << 1)` (value `2`) in Python. |
| `Operation not supported` when attaching XDP | Attaching in native driver mode (`XDP_FLAGS_DRV_MODE`) to virtual interfaces (`veth`, `bridge`). | Always attach in Generic SKB mode: `XDP_FLAGS_SKB_MODE = 1 << 1`. |
| `TypeError: byref() argument must be a ctypes instance, not 'int'` in BCC maps | Querying BCC `BPF_HASH` or `BPF_ARRAY` using a standard Python integer key (`0` or `ip_u32`) instead of a ctypes object. Throws silently in WebSocket handlers, causing the UI to show `RECONNECTING...`. | Always wrap map keys with ctypes: `ctypes.c_uint32(ip_to_u32(ip))` for `drop_counter_map`, and `ctypes.c_int(idx)` for `diagnostic_counters`. |
| Severe UI scroll lag and low FPS in Linux browser | CSS `backdrop-filter: blur(16px)` on 15+ card panels and HTML5 canvas `ctx.shadowBlur` run software Gaussian blur passes on the CPU every scroll frame in VMs/hosts without GPU passthrough. | Replaced `backdrop-filter` with solid high-performance obsidian surfaces (`#0d121f` with 1px borders), removed canvas `shadowBlur`, and throttled the animation loop to a lightweight 30 FPS. |
| Attack process not terminating on Emergency Stop | `hping3 --flood` launched via `subprocess.Popen("...", shell=True)` runs in a subshell, ignoring `SIGTERM` and leaving orphan flood processes in the network namespace. | Launch directly as argument list with `os.setsid`, send `SIGKILL` (`-9`) to the process group, and execute `ip netns exec ns-attacker killall -9 hping3`. |
| Terminal silent during Phase 3 dashboard execution | In `app.py`, `self.daemon.print_telemetry_dashboard()` was not invoked inside the live evaluation loop, leaving the terminal backend silent. | Re-enabled `self.daemon.print_telemetry_dashboard()` on every 1.0-second tick, enabling dual live terminal ASCII monitoring and browser dashboard visualization simultaneously. |

---

### 10. Automated Conscience & State Tracking System

To maintain unbroken project continuity across sessions separated by days or weeks, the repository uses an automated state persistence and recall system:

1. **State Store (`.agents/state/project_state.json`)**:
   - Stores current active phase, completed milestones, recent activity logs, and immediate next action.
2. **Session Wakeup Recall (`.agents/scripts/pulse_hook.py`)**:
   - Integrated with Antigravity's `PreInvocation` hook (`.agents/hooks.json`).
   - Before any agent interaction, automatically evaluates `project_state.json` and injects an ephemeral memory pulse containing current phase status, last action performed, and immediate next action.
   - Run manually anytime via: `python3 .agents/scripts/pulse_hook.py --cli`
3. **Audit Trail Logger (`.agents/scripts/post_edit_hook.py`)**:
   - Integrated with Antigravity's `PostToolUse` hook.
   - Logs tool invocations and modified files into `.agents/state/audit_log.jsonl` and updates state timestamps automatically.
4. **Milestone Synchronizer (`.agents/scripts/checkpoint.py`)**:
   - Synchronizes `project_state.json`, `PROJECT_CHANGELOG.md`, and documentation:
     ```bash
     python3 .agents/scripts/checkpoint.py "Completed Phase X milestone" --phase "Phase X" --next "Upcoming task"
     ```

---

### 11. Final Capstone Completion & Viva Voce Defense Prep

All 4 engineering and research phases have been fully implemented, executed, and verified:

#### System State Overview
- **Phase 0 (Environment)**: Fully provisioned (`clang`, `llvm`, `python3-bpfcc`, `fastapi`, `hping3`, `nmap`).
- **Phase 1 (Static XDP)**: Verified live. Line-rate packet drops in nanoseconds (`kernel/xdp_isolation_p1.c` + `daemon/phase1_loader.py`).
- **Phase 2 (Dynamic Trust Decay Engine)**: Verified live. 1.0s sliding-window flow entropy, multi-tier transitions (`TRUSTED` $\rightarrow$ `SUSPECT` $\rightarrow$ `QUARANTINED`), $T_{\text{isolate}} = 27.57\text{--}51.89\,\mu\text{s}$, and $+6.0\,\text{pts/sec}$ self-healing.
- **Phase 3 (Observability Presentation Plane)**: Verified live. FastAPI WebSocket backend (`dashboard/app.py`), Chart.js UI (`static/index.html`), animated topology canvas, one-click attack simulator, and mirrored terminal ASCII dashboard.
- **Phase 4 (Quantitative Benchmarks & Evaluation)**: Verified live. $T_{\text{isolate}} = 4.04\,\mu\text{s}$ ($1,732.6\times$ faster than iptables), $6.18\times$ fewer TCP retransmits under flood, $18.2\%$ lower kernel CPU load, and publication-ready LaTeX tables generated in `benchmarks/results/`.

#### Quick Commands Reference
```bash
# 1. Start Phase 3 Live Presentation Server & Telemetry Dashboard
sudo python3 dashboard/app.py

# 2. Re-run Phase 4 Quantitative Benchmarks (Generates fresh CSVs & LaTeX tables)
sudo bash benchmarks/run_benchmarks.sh --all

# 3. Clean testbed namespaces and detach XDP hooks
sudo ./topology/teardown_netns.sh
```

---

### 12. Version 2.0: 16-Node Enterprise Microservice Cluster Architecture

Subnet: `10.20.0.0/24` | Master Bridge: `br-xdp-v2` (`10.20.0.1`)

| Tier & Role | Namespace | Assigned IPv4 | Host Bridge Veth Port | Internal Interface | Port Protocol / Services |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Bridge Master** | Host | `10.20.0.1/24` | `br-xdp-v2` | — | Virtual Bridge Master |
| **Tier 1: Web Ingress** | `ns-web-01` | `10.20.0.11` | `veth-w01-br` | `eth0` | TCP 80/443 (HTTP/HTTPS) |
| **Tier 1: Web Ingress** | `ns-web-02` | `10.20.0.12` | `veth-w02-br` | `eth0` | TCP 80/443 (HTTP/HTTPS) |
| **Tier 1: Web Ingress** | `ns-web-03` | `10.20.0.13` | `veth-w03-br` | `eth0` | TCP 80/443 (HTTP/HTTPS) |
| **Tier 1: Web Ingress** | `ns-web-04` | `10.20.0.14` | `veth-w04-br` | `eth0` | TCP 80/443 (HTTP/HTTPS) |
| **Tier 2: Microservices** | `ns-api-auth` | `10.20.0.21` | `veth-a01-br` | `eth0` | TCP 8080 (Auth Microservice) |
| **Tier 2: Microservices** | `ns-api-order` | `10.20.0.22` | `veth-a02-br` | `eth0` | TCP 8081 (Order Microservice) |
| **Tier 2: Microservices** | `ns-api-pay` | `10.20.0.23` | `veth-a03-br` | `eth0` | TCP 8082 (Payment Microservice) |
| **Tier 2: Microservices** | `ns-api-user` | `10.20.0.24` | `veth-a04-br` | `eth0` | TCP 8083 (User Profile API) |
| **Tier 3: Database & Cache** | `ns-db-primary` | `10.20.0.31` | `veth-d01-br` | `eth0` | TCP 5432 (PostgreSQL Primary) |
| **Tier 3: Database & Cache** | `ns-db-replica` | `10.20.0.32` | `veth-d02-br` | `eth0` | TCP 5432 (PostgreSQL Read Replica) |
| **Tier 3: Database & Cache** | `ns-redis-cache` | `10.20.0.33` | `veth-d03-br` | `eth0` | TCP 6379 (Redis In-Memory Cache) |
| **Tier 3: Database & Cache** | `ns-elastic-search` | `10.20.0.34` | `veth-d04-br` | `eth0` | TCP 9200 (Elasticsearch Analytics) |
| **Tier 4: Peripheral Clients** | `ns-client-alpha` | `10.20.0.41` | `veth-c01-br` | `eth0` | Batch API Consumer / Tenant |
| **Tier 4: Peripheral Clients** | `ns-client-beta` | `10.20.0.42` | `veth-c02-br` | `eth0` | Mobile Gateway Simulator |
| **Tier 4: Adversary Nodes** | `ns-attk-lateral` | `10.20.0.51` | `veth-x01-br` | `eth0` | Stealth Lateral Scan Attacker |
| **Tier 4: Adversary Nodes** | `ns-attk-ddos` | `10.20.0.52` | `veth-x02-br` | `eth0` | High-Rate SYN Flood Attacker |

*Note: All interface names are $\leq 15$ characters to conform strictly with Linux kernel `IFNAMSIZ` (16 bytes including `\0`).*

---

### 13. Executive Morning Briefing: Tomorrow's Step 2 and Following Phase Roadmap

When starting tomorrow's session, review this operational blueprint:

#### Where We Stand (Step 1 Complete)
- **Branch**: `v2` (Version 2.0 Feature Development).
- **Step 1 Completed**: `topology/setup_netns_cluster.sh` and `topology/teardown_netns_cluster.sh` are authored and syntax-checked. They automate the 16-node 4x4 cluster on `10.20.0.0/24` with zero memory overhead.
- **Conscience Status**: Synchronized across `AGENTS.md`, `project_state.json`, and `PROJECT_MASTER_GUIDE.md`.

#### Tomorrow's Immediate Target: Step 2 — 16-Port eBPF Kernel Datapath (`kernel/xdp_isolation_v2.c`)
In Step 2, author the high-density eBPF filter engineered for 16 concurrent container ports:
1. **LRU Scaled Policy Map**:
   - Upgrade from standard fixed hash to `BPF_TABLE("lru_hash", u32, u32, policy_map, 65536)` to support tens of thousands of dynamic flow states with $O(1)$ memory bounds.
2. **East-West Micro-Isolation Matrix (`east_west_policy`)**:
   - Introduce a composite 64-bit key table `BPF_HASH(east_west_policy, u64, u32)` encoding `((u64)src_ip << 32) | (u64)dst_ip`.
   - Allows strict tier boundaries: e.g. `Tier 1 (Web)` may talk to `Tier 2 (APIs)` on 8080–8083, but any direct connection from `Tier 1` to `Tier 3 (DB 5432)` or `Tier 4` is immediately flagged as anomalous lateral movement.
3. **Automated Multi-Interface Attachment**:
   - Python BCC loader iterates through all 16 `veth-*-br` interfaces, automatically binding the XDP program in `XDP_FLAGS_SKB_MODE`.

#### Following Phase Roadmap
- **Step 3 (Control Plane: `daemon/cluster_daemon.py`)**:
  - Implement the $2^{k-1}$ Repeat-Offender Hysteresis Algorithm ($P \times 2^{k-1}$, $R_{\text{heal}} / 2^{k-1}$).
  - Implement Sliding-Window Target Ingress Aggregation for distributed botnet correlation.
- **Step 4 (Presentation Plane: 4x4 Enterprise Cluster Grid)**:
  - Upgrade dashboard UI to display the 4x4 symmetric matrix (Web, API, DB, Clients/Attacker).
  - Animate lateral reconnaissance sweeps getting deflected at driver barriers.
- **Step 5 (High-Density Benchmarking: `benchmarks/benchmark_cluster.py`)**:
  - Measure blast-radius confinement ratio ($\mathcal{B}_{\text{confine}}$) and generate IEEE publication LaTeX tables for the 16-node cluster under multi-attacker floods.

---

### 14. Conversational History, Faculty Feedback & Architectural Decision Registry

This section preserves the complete conversational intelligence, faculty feedback, trade-off analyses, and user directives from project inception to Version 2.0:

#### 14.1 Faculty Demo Review & Scaling Recommendation (2026-11-05 00:34)
* **User Input**: *"I showed the demo to my faculty she was okay with project scope and working and all, but she recommended me to add more virtual devices. For our Project we set one victim, one legit and one attacker - she telling us to go with multi device setup like 10 or 20 virtual device each could interact in a network setup that prove our setup more deliberately and our focus and setup can be viable for IEEE or sort of publication we can go with."*
* **Faculty Verdict**: The 3-node POC is technically sound, but scaling to 10–20 nodes is the required differentiator to prove multi-tenant isolation, enterprise realism, and achieve acceptance in IEEE/ACM conferences.

#### 14.2 Repository Branching Strategy
* **User Directive**: Create three distinct branches from the fully verified `main` repository:
  1. **`v1`**: Version 1.0 — Permanent immutable snapshot of the completed Phase 0–4 capstone (3-node testbed, empirical $4.04\,\mu\text{s}$ latency, $18.2\%$ CPU savings).
  2. **`v2`**: Version 2.0 — Active enhancement branch for the 16-node enterprise cluster, East-West lateral movement isolation, and $2^{k-1}$ hysteresis.
  3. **`academic-presentation`**: Dedicated repository workspace for capstone viva presentation slides (PPT/PDF), formal reports (DOCX/LaTeX), and faculty review documents.
* **Status**: Branches created and pushed to GitHub (`origin/v1`, `origin/v2`, `origin/academic-presentation`).

#### 14.3 VirtualBox Hardware Constraints & Technical Rationale
* **Environment Audit**: Ubuntu 22.04 LTS on VirtualBox, 4 vCPUs, 5.8 GiB RAM (2.8 GiB free), software CPU rendering (no GPU passthrough).
* **Technical Decision**:
  * **REJECTED**: Heavy container orchestrators (Docker Swarm, Minikube, Kubernetes). 16 full containers would consume 3–4 GiB RAM, triggering swap thrashing and CPU starvation.
  * **ADOPTED**: Pure Linux Network Namespaces (`ip netns`). Namespaces are in-kernel pointer structs (`struct net *`). 16 namespaces consume **$<11\,\text{MB}$ of RAM total** and 0% CPU at idle, providing identical networking fidelity with zero virtualization penalty.

#### 14.4 Strategic Node Count & Architectural Tiering (Why 16 Nodes?)
* **Decision**: 16 Nodes arranged as a 4×4 symmetric multi-tier grid on subnet `10.20.0.0/24`:
  * *Academic Value*: $N = 16 = 2^4$ is the canonical benchmark scale in distributed systems literature.
  * *UI Compositing*: Formats symmetrically into a 4-column card grid fitting a single 1080p screen without scrolling.
  * *Tier Distribution*:
    - Tier 1: 4 Web Pods (`ns-web-01` to `04`, `10.20.0.11–14`)
    - Tier 2: 4 API Pods (`ns-api-auth`, `order`, `pay`, `user`, `10.20.0.21–24`)
    - Tier 3: 4 Data Pods (`ns-db-primary`, `replica`, `redis`, `elastic`, `10.20.0.31–34`)
    - Tier 4: 2 Clients (`ns-client-alpha`, `beta`) + 2 Attackers (`ns-attk-lateral`, `ddos`)
  * *Kernel Limit Compliance*: All host interface names (`veth-w01-br` to `veth-x02-br`) are $\leq 15$ characters to strictly obey Linux `IFNAMSIZ` (16 bytes).

#### 14.5 Unifying Ideas A, B, and C into a Single Academic Stack
* **Question**: Should we choose Idea A, B, or C?
* **Verdict**: All three must be combined. They are not competing options—they represent the Infrastructure, Mechanism, and Mathematical proof of a single system:
  1. **Idea A (Infrastructure)**: The 16-node microservice mesh provides the high-density multi-tenant playground.
  2. **Idea B (Security Mechanism)**: East-West lateral movement micro-isolation proves *why* 16 nodes are needed (a compromised web container cannot pivot to internal DBs; adjacent 15 nodes suffer 0% blast radius).
  3. **Idea C (Algorithmic Proof)**: The $2^{k-1}$ Repeat-Offender Hysteresis Formula ($P_{\text{decay}} = P \times 2^{k-1}$, $R_{\text{heal}} = R_{\text{base}} / 2^{k-1}$) provides the published mathematical innovation.

#### 14.6 Verified Empirical Baseline Data (Phase 4 Results)
* **$T_{\text{isolate}}$ Latency**: Mean **$4.04\,\mu\text{s}$** ($2.09\,\mu\text{s}$ median, $P_{95} = 3.18\,\mu\text{s}$) vs Linux `iptables` **$7,000.16\,\mu\text{s}$** (**$1,732.6\times$ faster**).
* **Volumetric DDoS CPU**: Peak CPU bounded at **$67.70\%$** (vs $77.50\%$), peak softirq bounded at **$65.84\%$** (vs $95.71\%$), kernel load reduced by **$18.19\%$** ($63.93\%$ vs $82.12\%$).
* **Legitimate Retention**: TCP retransmissions reduced by **$6.18\times$** (**$232$** vs $1,434$), average ping RTT **$0.04\,\text{ms}$** (vs $0.06\,\text{ms}$), with **$0.0\%$ packet loss**.

#### 14.7 Master Directive on Conscience Tracking
* **User Directive (2026-11-05 01:01)**: All modifications, conversation decisions, strategic outputs, and chat replies must be preserved simultaneously in project documentation and conscience files so future agents retain complete operational context and make informed decisions without memory loss.

