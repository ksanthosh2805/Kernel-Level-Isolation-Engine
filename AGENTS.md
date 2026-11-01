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
- [daemon/](file:///home/daemon_targaryen/kernel-isolation-engine/daemon/)
  - [phase1_loader.py](file:///home/daemon_targaryen/kernel-isolation-engine/daemon/phase1_loader.py): Phase 1 BCC loader and interactive CLI controller (`block <IP>`, `allow <IP>`, `status`).
  - [trust_daemon.py](file:///home/daemon_targaryen/kernel-isolation-engine/daemon/trust_daemon.py): Phase 2 closed-loop trust decay daemon consuming the eBPF ring buffer.

- [topology/](file:///home/daemon_targaryen/kernel-isolation-engine/topology/)
  - [setup_netns.sh](file:///home/daemon_targaryen/kernel-isolation-engine/topology/setup_netns.sh): Creates virtual bridge `br-xdp` (10.10.0.1) and 3 isolated network namespaces:
    - Node A (Victim): `ns-victim` -> `10.10.0.10`
    - Node B (Legit): `ns-legit` -> `10.10.0.20`
    - Node C (Attacker): `ns-attacker` -> `10.10.0.30`
  - [teardown_netns.sh](file:///home/daemon_targaryen/kernel-isolation-engine/topology/teardown_netns.sh): Cleanly deletes `ns-victim`, `ns-legit`, `ns-attacker`, and `br-xdp`.
- [dashboard/](file:///home/daemon_targaryen/kernel-isolation-engine/dashboard/): FastAPI application (`app.py`) and Chart.js UI (`static/index.html`).
- [benchmarks/](file:///home/daemon_targaryen/kernel-isolation-engine/benchmarks/): Latency ($T_{\text{isolate}}$), CPU, and throughput benchmarking scripts (`run_benchmarks.sh`).

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

- **Latest Checkpoint (2026-11-02 00:08:15)**: Phase 3 Real-Time Observability Presentation Plane Complete: Built FastAPI WebSocket backend, Chart.js time-series dashboard, animated SVG topology flow canvas, multi-vector attack simulation deck, and microsecond audit feed. *Next*: Phase 4: Quantitative Benchmarking Suite & Thesis Evaluation (run_benchmarks.sh).
- **Phase 0 (Environment Provisioning)**: **COMPLETE & VERIFIED [OK]**
  - Toolchain, headers, Clang, LLVM, BCC, FastAPI installed and ready.
- **Phase 1 Setup & Verification**: **COMPLETE & VERIFIED [OK]**
  - All Phase 1 files created and operational.
  - **Manual Check Step 1 (3-Node Netns Connectivity)**: **VERIFIED [OK]** by user.
  - **Manual Check Step 2 (Multi-Terminal Static XDP Enforcement)**: **VERIFIED [OK]** by user. Attacker IP (`10.10.0.30`) successfully quarantined with 100% packet loss, `drop_counter_map` incremented atomically in kernel, and `allow` command verified instant recovery.
- **Phase 2 Status**: **NEXT IMMEDIATE PHASE TO IMPLEMENT TOMORROW**.
  - Dynamic XDP filter with TCP SYN inspection & Ring Buffer event streaming (`kernel/xdp_isolation_p2.c`).
  - Closed-loop user-space Trust Decay Daemon (`daemon/trust_daemon.py`).
- **Phase 3 & 4 Status**: Fully documented and architected in [PROJECT_MASTER_GUIDE.md](file:///home/daemon_targaryen/kernel-isolation-engine/PROJECT_MASTER_GUIDE.md).

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
