#!/usr/bin/env python3
"""
post_edit_hook.py — Antigravity PostToolUse Lifecycle Hook
Automatically captures every file edit/creation made during development,
logs it into .agents/state/audit_log.jsonl, and updates the project state timestamp.
"""

import sys
import os
import json
from datetime import datetime

WORKSPACE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
STATE_FILE = os.path.join(WORKSPACE_DIR, ".agents/state/project_state.json")
AUDIT_LOG = os.path.join(WORKSPACE_DIR, ".agents/state/audit_log.jsonl")

def main():
    hook_input = {}
    try:
        raw = sys.stdin.read()
        if raw.strip():
            hook_input = json.loads(raw)
    except Exception:
        pass

    now_iso = datetime.now().isoformat()
    tool_call = hook_input.get("toolCall", {})
    tool_name = tool_call.get("name", "unknown_tool")
    args = tool_call.get("args", {})
    target_file = args.get("TargetFile", "")

    # Record to audit log
    entry = {
        "timestamp": now_iso,
        "tool": tool_name,
        "target_file": target_file,
        "step_idx": hook_input.get("stepIdx", 0),
        "status": "success" if not hook_input.get("error") else "error"
    }

    try:
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

    # Update project_state.json last_updated if state file exists
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                state = json.load(f)
            state["last_updated"] = now_iso
            with open(STATE_FILE, "w") as f:
                json.dump(state, f, indent=2)
        except Exception:
            pass

    # PostToolUse expects empty JSON on stdout
    print(json.dumps({}))

if __name__ == "__main__":
    main()
