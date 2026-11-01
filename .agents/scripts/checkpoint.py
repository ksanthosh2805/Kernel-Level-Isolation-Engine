#!/usr/bin/env python3
"""
checkpoint.py — Conscience & Milestone Checkpoint Synchronizer
Synchronizes project state across:
  1. .agents/state/project_state.json (Machine-readable single source of truth)
  2. PROJECT_CHANGELOG.md (Chronological human & agent audit log)
  3. AGENTS.md (Root workspace conscience ingested on session start)
  4. PROJECT_KNOWLEDGE_BASE.md (Master operational manual & milestone registry)

Usage:
  python3 .agents/scripts/checkpoint.py "Completed Phase 1 multi-terminal verification" \
      --phase "Phase 1" \
      --files "daemon/phase1_loader.py,kernel/xdp_isolation_p1.c" \
      --next "Begin Phase 2 dynamic trust decay engine"
"""

import sys
import os
import re
import json
import argparse
from datetime import datetime

WORKSPACE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
STATE_FILE = os.path.join(WORKSPACE_DIR, ".agents/state/project_state.json")
CHANGELOG_FILE = os.path.join(WORKSPACE_DIR, "PROJECT_CHANGELOG.md")
AGENTS_FILE = os.path.join(WORKSPACE_DIR, "AGENTS.md")
KB_FILE = os.path.join(WORKSPACE_DIR, "PROJECT_KNOWLEDGE_BASE.md")

def update_agents_md(summary, now_str, next_step):
    if not os.path.exists(AGENTS_FILE):
        return
    try:
        with open(AGENTS_FILE, "r") as f:
            content = f.read()

        bullet = f"- **Latest Checkpoint ({now_str})**: {summary}. *Next*: {next_step}."
        
        # Look for ## 5. Current Project State & Milestones
        pattern = r"(## 5\. Current Project State & Milestones\n\n)"
        if re.search(pattern, content):
            # Check if there is already a Latest Checkpoint bullet to replace or prepend
            if "- **Latest Checkpoint" in content:
                content = re.sub(r"- \*\*Latest Checkpoint.*?\n", bullet + "\n", content, count=1)
            else:
                content = re.sub(pattern, r"\1" + bullet + "\n", content, count=1)
            with open(AGENTS_FILE, "w") as f:
                f.write(content)
    except Exception as e:
        print(f"[!] Warning: Could not update AGENTS.md: {e}")

def update_kb_md(summary, now_str, next_step):
    if not os.path.exists(KB_FILE):
        return
    try:
        with open(KB_FILE, "r") as f:
            content = f.read()

        bullet = f"- **Latest Checkpoint ({now_str})**: {summary}. *Next*: {next_step}."
        pattern = r"(### 8\. Verification History & Milestone Registry\n\n)"
        if re.search(pattern, content):
            if "- **Latest Checkpoint" in content:
                content = re.sub(r"- \*\*Latest Checkpoint.*?\n", bullet + "\n", content, count=1)
            else:
                content = re.sub(pattern, r"\1" + bullet + "\n", content, count=1)
            with open(KB_FILE, "w") as f:
                f.write(content)
    except Exception as e:
        print(f"[!] Warning: Could not update PROJECT_KNOWLEDGE_BASE.md: {e}")

def update_state(summary, phase=None, files=None, next_step=None):
    if not os.path.exists(STATE_FILE):
        print(f"[-] State file not found at {STATE_FILE}")
        return False

    with open(STATE_FILE, "r") as f:
        state = json.load(f)

    now_iso = datetime.now().isoformat()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    state["last_updated"] = now_iso

    if phase:
        state.setdefault("active_phase", {})["name"] = phase

    file_list = [f.strip() for f in files.split(",")] if files else []

    activity_entry = {
        "timestamp": now_iso,
        "action": "CHECKPOINT_UPDATE",
        "summary": summary,
        "files_touched": file_list
    }

    # Prepend to recent activities, keeping last 15
    recent = state.get("recent_activity", [])
    recent.insert(0, activity_entry)
    state["recent_activity"] = recent[:15]

    effective_next = next_step or "See PROJECT_MASTER_GUIDE.md for phase roadmap"
    state["immediate_next_step"] = {
        "action": "NEXT_ACTION",
        "description": effective_next
    }

    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

    # 1. Update PROJECT_CHANGELOG.md
    if os.path.exists(CHANGELOG_FILE):
        entry_md = [
            f"\n## {now_str} — {summary}",
            f"- **Phase**: {phase or state.get('active_phase', {}).get('name', 'Active')}",
            f"- **Files**: {', '.join([f'`{fl}`' for fl in file_list]) if file_list else 'None specified'}",
            f"- **Next Step**: {effective_next}\n"
        ]
        with open(CHANGELOG_FILE, "a") as f:
            f.write("\n".join(entry_md))

    # 2. Synchronize AGENTS.md conscience
    update_agents_md(summary, now_str, effective_next)

    # 3. Synchronize PROJECT_KNOWLEDGE_BASE.md registry
    update_kb_md(summary, now_str, effective_next)

    print(f"[✓] Complete Conscience Checkpoint Recorded at {now_str}:")
    print(f"    ├─ State Store:        .agents/state/project_state.json (Updated)")
    print(f"    ├─ Changelog:          PROJECT_CHANGELOG.md (Appended)")
    print(f"    ├─ Root Conscience:    AGENTS.md (Synchronized)")
    print(f"    └─ Knowledge Base:     PROJECT_KNOWLEDGE_BASE.md (Synchronized)")
    print(f"\n    Summary:   {summary}")
    print(f"    Next Step: {effective_next}\n")
    return True

def main():
    parser = argparse.ArgumentParser(description="Record a project checkpoint and update all conscience files")
    parser.add_argument("summary", help="Description of milestone or work completed")
    parser.add_argument("--phase", help="Current active phase name")
    parser.add_argument("--files", help="Comma-separated list of files modified")
    parser.add_argument("--next", help="Immediate next action description")

    args = parser.parse_args()
    update_state(args.summary, args.phase, args.files, args.next)

if __name__ == "__main__":
    main()
