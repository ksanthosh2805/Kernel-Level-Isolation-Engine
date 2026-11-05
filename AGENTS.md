# AGENTS.md — Kernel-Level Zero-Trust Traffic Isolation Engine

Welcome, Agent. This repository contains a final-year engineering capstone project: **Kernel-Level Zero-Trust Network Traffic Isolation Engine (eBPF/XDP)**.
Read this document to orient yourself on the codebase context, current project state, rules of engagement, and future roadmap.

---

## 1. Project Context, Problem Statement & Academic Novelty

The project intercepts raw packet frames (`xdp_md`) at the Network Interface Card (NIC) driver layer before socket buffer (`sk_buff`) allocation and connection tracking (`conntrack`). It enforces micro-isolation and mitigation for volumetric DDoS, SYN floods, and port scanning in nanoseconds.

### 60-Second Defense Elevator Pitch (For Viva & Faculty Examination)
> *"In modern cloud and containerized environments, traditional firewalls like iptables and user-space proxies fail under load—consuming excessive CPU cycles and reacting too slowly to stop lateral movement. Our project solves this by introducing a kernel-level Zero-Trust Traffic Isolation Engine powered by eBPF and XDP. Instead of allowing malicious packets to enter the Linux networking stack, our system inspects and enforces security policies directly at the NIC driver level, dropping unwanted traffic in nanoseconds before the kernel even allocates memory buffers. We pair this raw performance with dynamic intelligence: a user-space Python daemon continuously analyzes flow telemetry via an eBPF Ring Buffer to calculate real-time trust scores, updating kernel-space eBPF maps atomically in under a millisecond. This neutralizes volumetric DDoS floods with flat CPU usage, prevents inter-container lateral movement, and dynamically quarantines reconnaissance and port scans—all without restarting services, reloading firewall rules, or disrupting legitimate workloads. We deliver intelligence in user space and enforcement at wire speed in the kernel."*

---

## 2. Master Documentation & Knowledge Hierarchy

Before modifying or executing any code, consult these documents:
- [PROJECT_MASTER_GUIDE.md](file:///home/daemon_targaryen/kernel-isolation-engine/PROJECT_MASTER_GUIDE.md): Master architectural blueprint, theoretical foundations, 5-pillar literature mapping, packet lifecycle sequence diagram, state machine math, and complete Phase 0–4 roadmap.
- [PROJECT_KNOWLEDGE_BASE.md](file:///home/daemon_targaryen/kernel-isolation-engine/PROJECT_KNOWLEDGE_BASE.md): Operational knowledge base, network testbed IP table, manual verification log, and verified troubleshooting fixes.
- [ACADEMIC_EVALUATION_REPORT.md](file:///home/daemon_targaryen/kernel-isolation-engine/ACADEMIC_EVALUATION_REPORT.md): Comprehensive academic evaluation report, empirical latency analysis (T_isolate: 27–51 µs), bug post-mortem registry, and viva defense Q&A.
- [.agents/skills/kernel-isolation-engine/SKILL.md](file:///home/daemon_targaryen/kernel-isolation-engine/.agents/skills/kernel-isolation-engine/SKILL.md): Specialized Antigravity skill with executable runbooks, C/Python code templates, and verifier safety patterns.

---

## 3. Directory Layout & Key Files

- [kernel/](file:///home/daemon_targaryen/kernel-isolation-engine/kernel/)
  - [xdp_isolation_p1.c](file:///home/daemon_targaryen/kernel-isolation-engine/kernel/xdp_isolation_p1.c): Phase 1 static XDP packet filter (Ethernet/IPv4 parsing, `policy_map`, and `drop_counter_map`).
  - [xdp_isolation_p2.c](file:///home/daemon_targaryen/kernel-isolation-engine/kernel/xdp_isolation_p2.c): Phase 2 dynamic XDP filter with L4 TCP/UDP parsing, SYN flag inspection, probabilistic suspect throttling, and ring buffer event streaming.
  - [xdp_isolation_v2.c](file:///home/daemon_targaryen/kernel-isolation-engine/kernel/xdp_isolation_v2.c): Phase 5 (v2.0) 16-port high-density eBPF datapath with canonical 65k `policy_map`, 64-bit East-West matrix (`east_west_matrix`), and wire-speed ring buffer telemetry.
- [daemon/](file:///home/daemon_targaryen/kernel-isolation-engine/daemon/)
  - [phase1_loader.py](file:///home/daemon_targaryen/kernel-isolation-engine/daemon/phase1_loader.py): Phase 1 BCC loader and interactive CLI controller (`block <IP>`, `allow <IP>`, `status`).
  - [trust_daemon.py](file:///home/daemon_targaryen/kernel-isolation-engine/daemon/trust_daemon.py): Phase 2 closed-loop trust decay daemon consuming the eBPF ring buffer.
  - [cluster_loader.py](file:///home/daemon_targaryen/kernel-isolation-engine/daemon/cluster_loader.py): Phase 5 (v2.0) 16-port generic XDP loader and interactive CLI controller with sub-microsecond map mutation.
  - [cluster_daemon.py](file:///home/daemon_targaryen/kernel-isolation-engine/daemon/cluster_daemon.py): Phase 5 (v2.0) closed-loop swarm trust decay daemon with $2^{k-1}$ repeat-offender hysteresis.

- [topology/](file:///home/daemon_targaryen/kernel-isolation-engine/topology/)
  - [setup_netns.sh](file:///home/daemon_targaryen/kernel-isolation-engine/topology/setup_netns.sh): Creates virtual bridge `br-xdp` (10.10.0.1) and 3 isolated network namespaces:
    - Node A (Victim): `ns-victim` -> `10.10.0.10`
    - Node B (Legit): `ns-legit` -> `10.10.0.20`
    - Node C (Attacker): `ns-attacker` -> `10.10.0.30`
  - [teardown_netns.sh](file:///home/daemon_targaryen/kernel-isolation-engine/topology/teardown_netns.sh): Cleanly deletes `ns-victim`, `ns-legit`, `ns-attacker`, and `br-xdp`.
  - [setup_netns_cluster.sh](file:///home/daemon_targaryen/kernel-isolation-engine/topology/setup_netns_cluster.sh): Creates virtual bridge `br-cluster` (`10.20.0.1/24`) and 16 isolated enterprise microservice namespaces (Web, API, DB, Clients, Attackers).
  - [teardown_netns_cluster.sh](file:///home/daemon_targaryen/kernel-isolation-engine/topology/teardown_netns_cluster.sh): Cleanly tears down the 16 namespaces and `br-cluster`.
- [dashboard/](file:///home/daemon_targaryen/kernel-isolation-engine/dashboard/): FastAPI application (`app.py`), Chart.js UI (`static/index.html`), obsidian dark mode (`static/css/style.css`), and animated topology consumer (`static/js/app.js`).
- [benchmarks/](file:///home/daemon_targaryen/kernel-isolation-engine/benchmarks/): Quantitative Benchmarking Suite & Academic Evaluation:
  - [benchmark_latency.py](file:///home/daemon_targaryen/kernel-isolation-engine/benchmarks/benchmark_latency.py): Microsecond $T_{\text{isolate}}$ benchmark comparing eBPF map mutation vs iptables rules over $N=100$ iterations.
  - [benchmark_cpu.py](file:///home/daemon_targaryen/kernel-isolation-engine/benchmarks/benchmark_cpu.py): Volumetric DDoS CPU & softirq survivability monitor across Baseline, iptables, and XDP.
  - [benchmark_throughput.py](file:///home/daemon_targaryen/kernel-isolation-engine/benchmarks/benchmark_throughput.py): Legitimate tenant bandwidth and ICMP RTT preservation tester using `iperf3`.
  - [run_benchmarks.sh](file:///home/daemon_targaryen/kernel-isolation-engine/benchmarks/run_benchmarks.sh): Master automated benchmark orchestrator with safe cleanup traps and LaTeX report generator.
  - [results/](file:///home/daemon_targaryen/kernel-isolation-engine/benchmarks/results/): Raw CSV metrics (`latency_comparison.csv`, `cpu_comparison.csv`, `throughput_comparison.csv`), LaTeX tables (`latex_*.tex`), and consolidated academic report (`BENCHMARK_REPORT.md`).

---

## 4. Automation & Conscience Tracking System

To ensure that knowledge, state, and audit history persist even when the workspace is closed for days:
- [`.agents/state/project_state.json`](file:///home/daemon_targaryen/kernel-isolation-engine/.agents/state/project_state.json): Machine-readable single source of truth for active phase, milestones, recent activities, and immediate next steps.
- [`.agents/hooks.json`](file:///home/daemon_targaryen/kernel-isolation-engine/.agents/hooks.json): Antigravity lifecycle hooks:
  - `PreInvocation`: Runs `pulse_hook.py` before each model turn, automatically injecting the live project pulse and state-of-work into the agent's context.
  - `PostToolUse`: Runs `post_edit_hook.py` after code edits, automatically recording touched files into `.agents/state/audit_log.jsonl`.
- [`.agents/scripts/checkpoint.py`](file:///home/daemon_targaryen/kernel-isolation-engine/.agents/scripts/checkpoint.py): CLI synchronizer for recording milestones:
  `python3 .agents/scripts/checkpoint.py "Summary of work" --phase "Phase X" --next "Next step"`
- [`PROJECT_CHANGELOG.md`](file:///home/daemon_targaryen/kernel-isolation-engine/PROJECT_CHANGELOG.md): Persistent chronological audit trail of all project modifications.

---

## 5. Current Project State & Milestones

- **Latest Checkpoint (2026-11-05 21:14:03)**: Version 2.0 Step 4 Verified Live: 16-Node Enterprise Presentation Plane fully operational with live WebSocket streaming, strict Zero-Trust score-to-state synchronization, 60 FPS batched canvas particle engine, and verified multi-vector attack/neutralize controls. *Next*: Implement Step 5: Quantitative Cluster Benchmarking Suite (benchmarks/benchmark_cluster.py) to measure Blast-Radius Confinement Ratio B_confine and generate IEEE/ACM LaTeX tables.
- **Phase 0 (Environment Provisioning)**: **COMPLETE & VERIFIED [OK]**
  - Toolchain, headers, Clang, LLVM, BCC, FastAPI installed and ready.
- **Phase 1 Setup & Verification**: **COMPLETE & VERIFIED [OK]**
  - All Phase 1 files created and operational (`kernel/xdp_isolation_p1.c`, `daemon/phase1_loader.py`, `topology/setup_netns.sh`).
  - **Manual Check Step 1 (3-Node Netns Connectivity)**: **VERIFIED [OK]** by user.
  - **Manual Check Step 2 (Multi-Terminal Static XDP Enforcement)**: **VERIFIED [OK]** by user. Attacker IP (`10.10.0.30`) successfully quarantined with 100% packet loss, `drop_counter_map` incremented atomically in kernel, and `allow` command verified instant recovery.
- **Phase 2 Setup & Verification**: **COMPLETE & VERIFIED LIVE [OK]**
  - Dynamic XDP filter with TCP SYN inspection & Ring Buffer event streaming (`kernel/xdp_isolation_p2.c`).
  - Closed-loop user-space Trust Decay Daemon (`daemon/trust_daemon.py`).
  - Measured isolation latencies ($T_{\text{isolate}}$): **27.57 µs to 51.89 µs**.
  - Autonomous self-healing ($+6.0\,\text{pts/sec}$) verified under live multi-terminal attack simulations.
- **Phase 3 Setup & Verification**: **COMPLETE & VERIFIED LIVE [OK]**
  - Unified server with FastAPI WebSocket broadcasting and mirrored live terminal ASCII dashboard (`dashboard/app.py`).
  - Real-time dark-mode web dashboard (`dashboard/static/index.html`) with 4 Chart.js charts, animated topology flow canvas, one-click attack simulator, and microsecond audit stream.
  - Tested and confirmed working smoothly by user.
- **Phase 4 Setup & Verification**: **COMPLETE & VERIFIED LIVE [OK]**
  - Quantitative Benchmarking Suite executed via `sudo bash benchmarks/run_benchmarks.sh`.
  - **Empirical Latency ($T_{\text{isolate}}$)**: Mean **$4.04\,\mu\text{s}$** ($2.09\,\mu\text{s}$ median, $P_{95} = 3.18\,\mu\text{s}$) vs Linux `iptables` **$7,000.16\,\mu\text{s}$** (**$1,732.6\times$ faster**).
  - **DDoS CPU Survivability**: Peak CPU bounded at **$67.70\%$** (vs $77.50\%$ for iptables), softirq peak bounded at **$65.84\%$** (vs $95.71\%$ for iptables), and kernel load reduced by **$18.19\%$** ($63.93\%$ vs $82.12\%$).
  - **Legitimate Workload Retention**: TCP retransmissions reduced by **$6.18\times$** (**$232$** vs $1,434$ for iptables), ICMP RTT dropped to **$0.04\,\text{ms}$** (vs $0.06\,\text{ms}$ for iptables), with **$0.0\%$ packet loss**.
  - All CSV logs, LaTeX tables, and academic reports generated in `benchmarks/results/`.
- **Phase 5 (v2.0) Active Development**: **STEPS 1–4 COMPLETE & VERIFIED LIVE [OK]**
  - **Step 1 (16-Node Enterprise Microservice Mesh)**: **COMPLETE & VERIFIED [OK]**. 4x4 multi-tier cluster (`10.20.0.0/24`) simulating Web, API, Database, Client, and Adversary tiers in pure Linux `ip netns` (<11 MB RAM).
  - **Step 2 (16-Port eBPF Datapath & Controller)**: **COMPLETE & VERIFIED [OK]**. Canonical 65k `policy_map`, 64-bit East-West matrix (`east_west_matrix`), wire-speed driver drops (~40 ns), and sub-microsecond map mutation ($10.59\,\mu\text{s}$).
  - **Step 3 (Swarm Trust Decay Daemon)**: **COMPLETE & VERIFIED LIVE [OK]**. Closed-loop ring buffer consumer with $2^{k-1}$ repeat-offender anti-flapping hysteresis ($P \times 2^{k-1}$, $R_{\text{heal}} / 2^{k-1}$) and zero collateral degradation to legitimate nodes.
  - **Step 4 (16-Node 4x4 Presentation Plane)**: **COMPLETE & VERIFIED LIVE [OK]**. FastAPI WebSocket server (`dashboard/cluster_app.py`), dark-mode UI (`dashboard/static/cluster.html`), batched Canvas 2D particle visualizer, dynamic throughput vs discard rate curves, and one-click attack simulations with instantaneous process-group neutralization.
  - **Step 5 (Cluster Quantitative Benchmarking & IEEE/ACM LaTeX Report)**: **READY FOR IMPLEMENTATION**. Quantitative Blast-Radius Confinement Ratio ($\mathcal{B}_{\text{confine}}$), multi-port eBPF map mutation benchmarking ($T_{\text{mutate}}$), and academic publication tables.

---

## 6. Rules of Engagement for Antigravity Agents

1. **User Executes Verification**: The user tests network namespaces and XDP programs in their own terminal windows. Do **not** execute blocking interactive commands (such as running `phase1_loader.py` or interactive shells) in background tasks unless explicitly requested.
2. **eBPF Verifier Compliance**: When authoring or modifying kernel C code in `kernel/`, always verify bounds (`pointer + sizeof(...) <= data_end`) before dereferencing any headers. Failure to do so will cause kernel verifier rejection.
3. **Generic XDP Mode**: Always attach to virtual interfaces (`veth`, bridges) using `BPF.XDP_FLAGS_SKB_MODE`.
4. **BCC Import**: Always use `from bcc import BPF`. The APT package on Ubuntu is `python3-bpfcc`.
5. **No Shell History Expansion**: Avoid exclamation marks inside double quotes in bash commands.
6. **Self-Healing Math**: Follow the exact mathematical formulations ($P_{\text{pps}}$, $P_{\text{syn}}$, $P_{\text{scan}}$, $R_{\text{heal}} = +6.0$) documented in [PROJECT_MASTER_GUIDE.md](file:///home/daemon_targaryen/kernel-isolation-engine/PROJECT_MASTER_GUIDE.md).
7. **Record State Updates**: When completing milestones or major file modifications, run `checkpoint.py` or update `project_state.json` so future sessions inherit the state.
8. **Strict GitHub Remote Policy (Explicit User Trigger Only)**:
   - **NEVER** run `git push` or push updates to the remote GitHub repository automatically, periodically, or on standard code changes/checkpoints.
   - All Git commits and state-tracking checkpoints remain strictly local on this machine.
   - Only execute `git push` or update the remote GitHub repository when the user explicitly and directly instructs to update/push to GitHub.
9. **Continuous Conversational Intelligence & Decision Rationale Logging**:
   - Every strategic discussion, user instruction, faculty recommendation, architectural trade-off, and conversational output must be recorded simultaneously in `PROJECT_KNOWLEDGE_BASE.md` (Section 14), `PROJECT_CHANGELOG.md`, and `.agents/state/project_state.json`.
   - Never lose the operational *context* and *reasoning* behind decisions (e.g. why 16 nodes, why pure Linux `ip netns` over Docker in VirtualBox, why Ideas A, B, and C are unified into a 3-layer stack, and why branches `v1`, `v2`, `academic-presentation` were structured). Future agents must inherit complete conversational intelligence without amnesia.
