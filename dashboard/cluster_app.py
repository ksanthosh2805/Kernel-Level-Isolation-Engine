#!/usr/bin/env python3
# Kernel-Level Zero-Trust Traffic Isolation Engine — Presentation Plane (Version 2.0)
# FastAPI WebSocket Backend for 16-Node Enterprise Microservice Cluster Mesh.

import os
import sys
import time
import json
import ctypes
import asyncio
import signal
import subprocess
import threading
from typing import Dict, List, Optional
from pathlib import Path
from collections import deque

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel

# Repository path configuration
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

try:
    from daemon.cluster_daemon import (
        SwarmTrustDecayDaemon,
        WorkloadClusterProfile,
        CLUSTER_NODES,
        CLUSTER_PORTS,
        STATE_TRUSTED,
        STATE_SUSPECT,
        STATE_QUARANTINED,
        STATE_NAMES,
        EW_ACTION_ALLOW,
        EW_ACTION_DENY_LATERAL,
        ip_to_u32,
        u32_to_ip,
        make_ew_key
    )
    from bcc import BPF
    CLUSTER_DAEMON_AVAILABLE = True
except Exception as e:
    print(f"[!] Warning: eBPF Cluster Daemon not available in current process ({e}). Simulation mode enabled.")
    CLUSTER_DAEMON_AVAILABLE = False
    STATE_TRUSTED = 0
    STATE_SUSPECT = 1
    STATE_QUARANTINED = 2
    STATE_NAMES = {0: "TRUSTED", 1: "SUSPECT", 2: "QUARANTINED"}
    EW_ACTION_ALLOW = 0
    EW_ACTION_DENY_LATERAL = 1
    CLUSTER_PORTS = []
    CLUSTER_NODES = {
        "10.20.0.11": ("ns-web-01", "Tier 1: Web Frontend 01 (Public HTTP)"),
        "10.20.0.12": ("ns-web-02", "Tier 1: Web Frontend 02 (Public HTTP)"),
        "10.20.0.13": ("ns-web-03", "Tier 1: Web Frontend 03 (Public HTTP)"),
        "10.20.0.14": ("ns-web-04", "Tier 1: Web Frontend 04 (Public HTTP)"),
        "10.20.0.21": ("ns-api-auth", "Tier 2: Auth & Identity Microservice"),
        "10.20.0.22": ("ns-api-order", "Tier 2: Order Processing API"),
        "10.20.0.23": ("ns-api-pay", "Tier 2: Payment Gateway API"),
        "10.20.0.24": ("ns-api-user", "Tier 2: User Profile API"),
        "10.20.0.31": ("ns-db-primary", "Tier 3: PostgreSQL Primary DB"),
        "10.20.0.32": ("ns-db-replica", "Tier 3: PostgreSQL Read Replica"),
        "10.20.0.33": ("ns-redis-cache", "Tier 3: Redis Session Cache"),
        "10.20.0.34": ("ns-elastic-search", "Tier 3: Elasticsearch Analytics"),
        "10.20.0.41": ("ns-client-alpha", "Tier 4: Legitimate Consumer Alpha"),
        "10.20.0.42": ("ns-client-beta", "Tier 4: Legitimate Consumer Beta"),
        "10.20.0.51": ("ns-attk-lateral", "Tier 4: Compromised Pod (Lateral Scanner)"),
        "10.20.0.52": ("ns-attk-ddos", "Tier 4: Compromised Pod (Volumetric Flooder)")
    }


app = FastAPI(
    title="Zero-Trust Traffic Isolation Engine (v2.0)",
    description="16-Node Enterprise Microservice Cluster Mesh — Real-Time Control & Observability Deck",
    version="2.0.0"
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class MutateRequest(BaseModel):
    ip: str
    action: str  # "block", "suspect", "allow"


class LateralRuleRequest(BaseModel):
    src_ip: str
    dst_ip: str
    action: str  # "deny", "allow"


class AttackRequest(BaseModel):
    vector: str  # "lateral_scan", "volumetric_flood", "web_db_bypass"
    target_ip: Optional[str] = "10.20.0.31"
    rate: Optional[int] = 500


# ==============================================================================
# Telemetry Bridge & Live Simulation Controller
# ==============================================================================

class ClusterTelemetryBridge:
    def __init__(self):
        self.daemon: Optional[SwarmTrustDecayDaemon] = None
        self.live_mode = False
        self.sim_nodes: Dict[str, dict] = {}
        self.active_attacks: List[subprocess.Popen] = []
        self.audit_log: deque = deque(maxlen=20)
        self.flow_particles: deque = deque(maxlen=40)
        self.total_intercepted = 0
        self.total_dropped = 0
        self.total_lateral_dropped = 0

        # Initialize simulation data models
        for ip, (alias, role) in CLUSTER_NODES.items():
            self.sim_nodes[ip] = {
                "ip": ip,
                "alias": alias,
                "role": role,
                "tier": self._classify_tier(ip),
                "trust_score": 100.0,
                "state": STATE_TRUSTED,
                "offense_count_k": 0,
                "healing_rate": 6.0,
                "pps": 0.0,
                "syn_pps": 0.0,
                "passes": 0,
                "drops": 0,
                "lateral_drops": 0,
                "last_lat_us": 0.0
            }

    def _classify_tier(self, ip: str) -> str:
        last = int(ip.split(".")[-1])
        if 11 <= last <= 14:
            return "web"
        elif 21 <= last <= 24:
            return "api"
        elif 31 <= last <= 34:
            return "data"
        elif 41 <= last <= 42:
            return "client"
        else:
            return "attacker"

    def initialize_live(self) -> bool:
        if os.geteuid() != 0 or not CLUSTER_DAEMON_AVAILABLE:
            return False

        try:
            self.daemon = SwarmTrustDecayDaemon()
            success = self.daemon.load_and_attach()
            if success:
                self.live_mode = True
                # Start background ring buffer loop thread
                t = threading.Thread(target=self.daemon.run, daemon=True)
                t.start()
                self._record_audit("SYSTEM", "Initialized Live eBPF Datapath across all 16 bridge ports", 0.0)
                return True
        except Exception as e:
            print(f"[-] Live kernel initialization failed: {e}")

        return False

    def _record_audit(self, entity: str, msg: str, lat_us: float = 0.0):
        ts = time.strftime("%H:%M:%S")
        self.audit_log.append({
            "timestamp": ts,
            "entity": entity,
            "message": msg,
            "latency_us": round(lat_us, 2)
        })

    def get_snapshot(self) -> dict:
        if self.live_mode and self.daemon:
            # Extract live values from kernel daemon
            nodes_data = []
            for ip, (alias, role) in CLUSTER_NODES.items():
                p = self.daemon.workloads.get(ip)
                if p:
                    ip_k = ctypes.c_uint32(ip_to_u32(ip))
                    try:
                        drops = self.daemon.drop_map[ip_k].value
                    except Exception:
                        drops = 0
                    try:
                        lat_d = self.daemon.lat_map[ip_k].value
                    except Exception:
                        lat_d = 0
                    try:
                        passes = self.daemon.pass_map[ip_k].value
                    except Exception:
                        passes = 0

                    mult = 2 ** max(0, p.offense_count_k - 1) if p.offense_count_k > 0 else 1.0
                    h_rate = 6.0 / mult

                    # Strict Zero-Trust state alignment: Trust Score governs state
                    eff_state = p.state
                    if p.trust_score < 30.0:
                        eff_state = STATE_QUARANTINED
                    elif p.trust_score < 70.0:
                        eff_state = STATE_SUSPECT
                    else:
                        eff_state = STATE_TRUSTED

                    nodes_data.append({
                        "ip": ip,
                        "alias": p.alias,
                        "role": p.role,
                        "tier": self._classify_tier(ip),
                        "trust_score": round(p.trust_score, 1),
                        "state": eff_state,
                        "state_name": STATE_NAMES.get(eff_state, "TRUSTED [PASS]"),
                        "offense_count_k": p.offense_count_k,
                        "healing_rate": round(h_rate, 2),
                        "pps": round(p.last_pps, 1),
                        "syn_pps": round(p.last_syn_pps, 1),
                        "passes": passes,
                        "drops": drops,
                        "lateral_drops": lat_d,
                        "total_drops": drops + lat_d,
                        "last_lat_us": round(p.last_isolate_lat_us, 2)
                    })

            try:
                c_tot = self.daemon.diag_map[ctypes.c_int(0)].value
                c_ip4 = self.daemon.diag_map[ctypes.c_int(1)].value
                c_lat = self.daemon.diag_map[ctypes.c_int(4)].value
                c_qdrop = self.daemon.diag_map[ctypes.c_int(7)].value
            except Exception:
                c_tot, c_ip4, c_lat, c_qdrop = 0, 0, 0, 0

            return {
                "live_mode": True,
                "ports_bound": len(self.daemon.attached_ports),
                "nodes": nodes_data,
                "diagnostics": {
                    "intercepted": c_tot,
                    "ipv4": c_ip4,
                    "lateral_drops": c_lat,
                    "quarantine_drops": c_qdrop
                },
                "audit_log": list(self.audit_log),
                "flow_particles": list(self.flow_particles)
            }
        else:
            # Simulation Mode for UI demonstration
            nodes_data = []
            for ip, data in self.sim_nodes.items():
                eff_state = data["state"]
                if data["trust_score"] < 30.0:
                    eff_state = STATE_QUARANTINED
                elif data["trust_score"] < 70.0:
                    eff_state = STATE_SUSPECT
                else:
                    eff_state = STATE_TRUSTED

                nodes_data.append({
                    "ip": ip,
                    "alias": data["alias"],
                    "role": data["role"],
                    "tier": data["tier"],
                    "trust_score": round(data["trust_score"], 1),
                    "state": eff_state,
                    "state_name": STATE_NAMES.get(eff_state, "TRUSTED [PASS]"),
                    "offense_count_k": data["offense_count_k"],
                    "healing_rate": round(data["healing_rate"], 2),
                    "pps": round(data["pps"], 1),
                    "syn_pps": round(data["syn_pps"], 1),
                    "passes": data["passes"],
                    "drops": data["drops"],
                    "lateral_drops": data["lateral_drops"],
                    "total_drops": data["drops"] + data["lateral_drops"],
                    "last_lat_us": round(data["last_lat_us"], 2)
                })

            return {
                "live_mode": False,
                "ports_bound": 16,
                "nodes": nodes_data,
                "diagnostics": {
                    "intercepted": self.total_intercepted,
                    "ipv4": self.total_intercepted,
                    "lateral_drops": self.total_lateral_dropped,
                    "quarantine_drops": self.total_dropped
                },
                "audit_log": list(self.audit_log),
                "flow_particles": list(self.flow_particles)
            }

    def mutate_workload(self, ip: str, action: str) -> float:
        state_map = {"block": STATE_QUARANTINED, "suspect": STATE_SUSPECT, "allow": STATE_TRUSTED}
        target_state = state_map.get(action, STATE_TRUSTED)

        if self.live_mode and self.daemon:
            p = self.daemon.workloads.get(ip)
            if p:
                t0 = time.perf_counter_ns()
                self.daemon.mutate_kernel_policy(p, target_state)
                t1 = time.perf_counter_ns()
                lat_us = (t1 - t0) / 1000.0
                alias = p.alias
                self._record_audit(alias, f"Manual Override -> {STATE_NAMES[target_state]}", lat_us)
                return lat_us
        else:
            if ip in self.sim_nodes:
                lat_us = 12.45
                self.sim_nodes[ip]["state"] = target_state
                if target_state == STATE_QUARANTINED:
                    self.sim_nodes[ip]["trust_score"] = 0.0
                    self.sim_nodes[ip]["offense_count_k"] += 1
                elif target_state == STATE_TRUSTED:
                    self.sim_nodes[ip]["trust_score"] = 100.0
                self.sim_nodes[ip]["last_lat_us"] = lat_us
                self._record_audit(self.sim_nodes[ip]["alias"], f"Simulated Mutation -> {STATE_NAMES[target_state]}", lat_us)
                return lat_us

        return 0.0

    def set_lateral_rule(self, src_ip: str, dst_ip: str, action: str):
        act_val = EW_ACTION_DENY_LATERAL if action == "deny" else EW_ACTION_ALLOW
        if self.live_mode and self.daemon:
            key = ctypes.c_uint64(make_ew_key(src_ip, dst_ip))
            t0 = time.perf_counter_ns()
            self.daemon.ew_map[key] = ctypes.c_uint32(act_val)
            t1 = time.perf_counter_ns()
            lat_us = (t1 - t0) / 1000.0
            act_str = "DENY_LATERAL" if act_val == EW_ACTION_DENY_LATERAL else "ALLOW"
            self._record_audit(src_ip, f"East-West Matrix -> {dst_ip} = {act_str}", lat_us)
            return lat_us
        else:
            self._record_audit(src_ip, f"Simulated East-West Policy: {src_ip} -> {dst_ip} ({action.upper()})", 15.2)
            return 15.2

    def _clean_exec_cmd(self, cmd_list: List[str]) -> List[str]:
        """Ensures commands run cleanly with root permissions without nesting sudo."""
        if os.geteuid() == 0:
            if cmd_list[0] == "sudo":
                return cmd_list[1:]
            return cmd_list
        else:
            if cmd_list[0] != "sudo":
                return ["sudo"] + cmd_list
            return cmd_list

    def launch_attack(self, vector: str, target_ip: str = "10.20.0.31", rate: int = 500):
        # Stop and neutralize any existing attacks first
        self.stop_attacks()

        if vector == "lateral_scan":
            raw_cmd = ["ip", "netns", "exec", "ns-attk-lateral", "nmap", "-sS", "-p", "1-200", target_ip]
            cmd = self._clean_exec_cmd(raw_cmd)
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
                self.active_attacks.append(proc)
                self._record_audit("ns-attk-lateral", f"Launched SYN Reconnaissance Scan against {target_ip}", 0.0)
            except Exception as e:
                self._record_audit("ATTACK_ERROR", f"Failed to spawn nmap: {e}", 0.0)

            if not self.live_mode and "10.20.0.51" in self.sim_nodes:
                self.sim_nodes["10.20.0.51"]["state"] = STATE_QUARANTINED
                self.sim_nodes["10.20.0.51"]["trust_score"] = 0.0
                self.sim_nodes["10.20.0.51"]["offense_count_k"] += 1
                self.sim_nodes["10.20.0.51"]["pps"] = 350.0
                self.sim_nodes["10.20.0.51"]["syn_pps"] = 350.0
                self.sim_nodes["10.20.0.51"]["drops"] += 200

        elif vector == "volumetric_flood":
            raw_cmd = ["ip", "netns", "exec", "ns-attk-ddos", "hping3", "-S", "-p", "80", "--flood", target_ip]
            cmd = self._clean_exec_cmd(raw_cmd)
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
                self.active_attacks.append(proc)
                self._record_audit("ns-attk-ddos", f"Launched Volumetric SYN Flood against {target_ip}", 0.0)
            except Exception as e:
                self._record_audit("ATTACK_ERROR", f"Failed to spawn hping3: {e}", 0.0)

            if not self.live_mode and "10.20.0.52" in self.sim_nodes:
                self.sim_nodes["10.20.0.52"]["state"] = STATE_QUARANTINED
                self.sim_nodes["10.20.0.52"]["trust_score"] = 0.0
                self.sim_nodes["10.20.0.52"]["offense_count_k"] += 1
                self.sim_nodes["10.20.0.52"]["pps"] = 45000.0
                self.sim_nodes["10.20.0.52"]["syn_pps"] = 45000.0
                self.sim_nodes["10.20.0.52"]["drops"] += 5000

        elif vector == "web_db_bypass":
            raw_cmd = ["ip", "netns", "exec", "ns-web-01", "ping", "-c", "50", "-i", "0.2", target_ip]
            cmd = self._clean_exec_cmd(raw_cmd)
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
                self.active_attacks.append(proc)
                self._record_audit("ns-web-01", f"Triggered Unauthorized Direct Web->DB Bypass to {target_ip}", 0.0)
            except Exception as e:
                self._record_audit("ATTACK_ERROR", f"Failed to spawn bypass ping: {e}", 0.0)

    def stop_attacks(self):
        """Terminates all attack process groups and neutralizes/restores datapath to baseline."""
        # 1. Kill all tracked process groups immediately
        for p in self.active_attacks:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        self.active_attacks.clear()

        # 2. Comprehensive cross-host and cross-namespace process sweep
        kill_commands = [
            ["pkill", "-9", "-f", "hping3"],
            ["pkill", "-9", "-f", "nmap"],
            ["killall", "-9", "hping3"],
            ["killall", "-9", "nmap"],
            ["ip", "netns", "exec", "ns-attk-ddos", "killall", "-9", "hping3"],
            ["ip", "netns", "exec", "ns-attk-lateral", "killall", "-9", "nmap"],
            ["ip", "netns", "exec", "ns-web-01", "killall", "-9", "ping"]
        ]
        for cmd_item in kill_commands:
            try:
                c = self._clean_exec_cmd(cmd_item)
                subprocess.run(c, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

        # 3. Neutralize & restore attacker workloads back to healthy baseline in kernel and daemon
        attack_ips = ["10.20.0.51", "10.20.0.52", "10.20.0.11"]
        t_iso_neutralize = 0.0

        if self.live_mode and self.daemon:
            for ip in attack_ips:
                p = self.daemon.workloads.get(ip)
                if p:
                    # Mutate kernel policy back to STATE_TRUSTED (0)
                    t0 = time.perf_counter_ns()
                    self.daemon.mutate_kernel_policy(p, STATE_TRUSTED)
                    t1 = time.perf_counter_ns()
                    t_iso_neutralize = (t1 - t0) / 1000.0

                    # Reset runtime metrics & scores to quiescent nominal state
                    p.trust_score = 100.0
                    p.state = STATE_TRUSTED
                    p.last_pps = 0.0
                    p.last_syn_pps = 0.0
                    p.win_packets = 0
                    p.win_syns = 0
                    p.win_ports.clear()
                    p.win_targets.clear()
                    p.win_lateral_violations = 0
        else:
            for ip in attack_ips:
                if ip in self.sim_nodes:
                    self.sim_nodes[ip]["state"] = STATE_TRUSTED
                    self.sim_nodes[ip]["trust_score"] = 100.0
                    self.sim_nodes[ip]["pps"] = 0.0
                    self.sim_nodes[ip]["syn_pps"] = 0.0

        self.flow_particles.clear()
        self._record_audit("NEUTRALIZE", "All attack processes terminated & baseline datapath restored", t_iso_neutralize)


bridge = ClusterTelemetryBridge()


# ==============================================================================
# REST API Endpoints
# ==============================================================================

@app.on_event("startup")
async def startup_event():
    bridge.initialize_live()


@app.on_event("shutdown")
async def shutdown_event():
    bridge.stop_attacks()
    if bridge.live_mode and bridge.daemon:
        bridge.daemon.detach_all()


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = STATIC_DIR / "cluster.html"
    if not index_file.exists():
        return HTMLResponse("<h2>Error: dashboard/static/cluster.html not found</h2>", status_code=404)
    return FileResponse(str(index_file))


@app.get("/api/cluster/status")
async def get_cluster_status():
    return JSONResponse(bridge.get_snapshot())


@app.post("/api/cluster/mutate")
async def mutate_workload_state(req: MutateRequest):
    lat = bridge.mutate_workload(req.ip, req.action)
    return JSONResponse({"status": "success", "ip": req.ip, "action": req.action, "latency_us": lat})


@app.post("/api/cluster/isolate-lateral")
async def configure_lateral_isolation(req: LateralRuleRequest):
    lat = bridge.set_lateral_rule(req.src_ip, req.dst_ip, req.action)
    return JSONResponse({"status": "success", "src_ip": req.src_ip, "dst_ip": req.dst_ip, "action": req.action, "latency_us": lat})


@app.post("/api/cluster/attack")
async def trigger_attack(req: AttackRequest):
    bridge.launch_attack(req.vector, req.target_ip, req.rate)
    return JSONResponse({"status": "attack_launched", "vector": req.vector, "target": req.target_ip})


@app.post("/api/cluster/attack/stop")
async def stop_all_attacks():
    bridge.stop_attacks()
    return JSONResponse({"status": "attacks_stopped"})


# ==============================================================================
# WebSocket Real-Time Telemetry Streaming
# ==============================================================================

@app.websocket("/ws/cluster-telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            snapshot = bridge.get_snapshot()
            await websocket.send_text(json.dumps(snapshot))
            await asyncio.sleep(0.5)  # 2 Hz telemetry cadence
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[-] WebSocket Error: {e}")


def main():
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")

    print("\n" + "=" * 90)
    print("  KERNEL-LEVEL ZERO-TRUST TRAFFIC ISOLATION ENGINE (v2.0) — PRESENTATION PLANE")
    print(f"  Web Dashboard Active at: http://localhost:{port}")
    print("=" * 90)

    uvicorn.run("cluster_app:app", host=host, port=port, log_level="info", reload=False)


if __name__ == "__main__":
    main()

