#!/usr/bin/env python3
"""
pulse_hook.py — Antigravity PreInvocation Lifecycle Hook & Session State Presenter
Automatically reads .agents/state/project_state.json and injects the live project
conscience pulse into the agent context before each interaction.
"""

import sys
import os
import json
from datetime import datetime

WORKSPACE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
STATE_FILE = os.path.join(WORKSPACE_DIR, ".agents/state/project_state.json")

def load_state():
    if not os.path.exists(STATE_FILE):
        return None
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return None

def build_pulse_message(state):
    if not state:
        return (
            "[PROJECT CONSCIENCE PULSE]\n"
            "Warning: .agents/state/project_state.json not found. "
            "Please consult AGENTS.md and PROJECT_MASTER_GUIDE.md."
        )

    phase_info = state.get("active_phase", {})
    recent_activity = state.get("recent_activity", [])
    last_act = recent_activity[0] if recent_activity else {}
    next_step = state.get("immediate_next_step", {})

    milestones = state.get("milestones", {})
    p0_st = milestones.get("phase_0_environment", {}).get("status", "COMPLETED")
    p1_st = milestones.get("phase_1_static_xdp", {}).get("status", "COMPLETED_AND_VERIFIED")
    p2_st = milestones.get("phase_2_dynamic_trust_engine", {}).get("status", "READY_TO_START")
    p3_st = milestones.get("phase_3_observability_dashboard", {}).get("status", "ARCHITECTED_READY")
    p4_st = milestones.get("phase_4_benchmarking", {}).get("status", "PLANNED")

    msg = [
        "==================================================================",
        "[PROJECT CONSCIENCE PULSE — STATE OF WORK & ROADMAP RECALL]",
        f"Project: {state.get('project_name', 'Kernel Isolation Engine')}",
        f"Active Phase: {phase_info.get('name', 'Unknown')} (Status: {phase_info.get('status', 'Unknown')})",
        "------------------------------------------------------------------",
        f"Last Recorded Activity: {last_act.get('action', 'N/A')} ({last_act.get('timestamp', 'N/A')})",
        f"Summary: {last_act.get('summary', 'N/A')}",
        "------------------------------------------------------------------",
        "Current Milestones State:",
        f"  - Phase 0 (Environment): {p0_st}",
        f"  - Phase 1 (Static XDP Driver Enforcement): {p1_st}",
        f"  - Phase 2 (Dynamic Trust Decay Engine): {p2_st}",
        f"  - Phase 3 (FastAPI WebSocket Dashboard): {p3_st}",
        f"  - Phase 4 (Benchmarking): {p4_st}",
        "------------------------------------------------------------------",
        f"IMMEDIATE NEXT ACTION: {next_step.get('description', 'N/A')}",
        "GitHub Policy: STRICT_USER_TRIGGER_ONLY (Push only when user explicitly commands)",
        "Master Docs: PROJECT_MASTER_GUIDE.md | AGENTS.md | PROJECT_KNOWLEDGE_BASE.md",
        "=================================================================="
    ]
    return "\n".join(msg)

def main():
    state = load_state()
    pulse_text = build_pulse_message(state)

    # CLI mode for human user inspection
    if len(sys.argv) > 1 and sys.argv[1] in ("--cli", "-c", "status"):
        print(pulse_text)
        return

    # Try reading stdin if piped from Antigravity lifecycle hook
    try:
        if not sys.stdin.isatty():
            sys.stdin.read()
    except Exception:
        pass

    # PreInvocation hook JSON response
    payload = {
        "injectSteps": [
            {
                "ephemeralMessage": pulse_text
            }
        ]
    }
    print(json.dumps(payload))

if __name__ == "__main__":
    main()
