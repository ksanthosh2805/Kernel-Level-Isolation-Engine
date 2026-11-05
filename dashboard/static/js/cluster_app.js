/*
 * Kernel-Level Zero-Trust Traffic Isolation Engine (v2.0)
 * 16-Node Enterprise Microservice Cluster Mesh — Presentation Plane Controller
 * High-performance real-time telemetry consumer, HTML5 East-West flow canvas, and Chart.js analytics.
 */

// Global Application State
const AppState = {
    ws: null,
    connected: false,
    liveMode: false,
    activeAttack: null,
    nodes: new Map(),
    auditLogs: [],
    flowParticles: [],
    sparkParticles: [],
    chartTrust: null,
    chartTraffic: null,
    lastDropCount: 0,
    lastDropTime: 0,
    trafficHistory: {
        labels: [],
        ingress: [],
        drops: [],
        lateral: []
    },
    maxHistoryPoints: 20
};

// Node Tier Layout for Topology Visualization
const TIER_MAPPING = {
    web: { name: "Tier 1: Web Frontend", color: "#06b6d4", ips: ["10.20.0.11", "10.20.0.12", "10.20.0.13", "10.20.0.14"] },
    api: { name: "Tier 2: Microservice API", color: "#8b5cf6", ips: ["10.20.0.21", "10.20.0.22", "10.20.0.23", "10.20.0.24"] },
    data: { name: "Tier 3: Core Data", color: "#10b981", ips: ["10.20.0.31", "10.20.0.32", "10.20.0.33", "10.20.0.34"] },
    threat: { name: "Tier 4: Clients & Threats", color: "#ef4444", ips: ["10.20.0.41", "10.20.0.42", "10.20.0.51", "10.20.0.52"] }
};

// ==============================================================================
// 1. Initialization & WebSocket Telemetry Stream
// ==============================================================================

document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    initCanvas();
    initEventListeners();
    connectWebSocket();

    // Resize canvas on window resize
    window.addEventListener("resize", () => {
        resizeCanvas();
    });
});

function connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws/cluster-telemetry`;

    const statusBadge = document.getElementById("connectionStatus");
    const statusText = document.getElementById("connectionText");

    if (statusBadge) {
        statusBadge.className = "badge badge-sim";
        statusText.innerText = "CONNECTING...";
    }

    try {
        AppState.ws = new WebSocket(wsUrl);

        AppState.ws.onopen = () => {
            AppState.connected = true;
            if (statusBadge) {
                statusBadge.className = "badge badge-live";
                statusText.innerText = "TELEMETRY LIVE (2 HZ)";
            }
        };

        AppState.ws.onmessage = (event) => {
            try {
                const payload = JSON.parse(event.data);
                processTelemetryPayload(payload);
            } catch (err) {
                console.error("[!] Error parsing WebSocket message:", err);
            }
        };

        AppState.ws.onclose = () => {
            AppState.connected = false;
            if (statusBadge) {
                statusBadge.className = "badge badge-quarantine";
                statusText.innerText = "RECONNECTING...";
            }
            // Auto reconnect after 2 seconds
            setTimeout(connectWebSocket, 2000);
        };

        AppState.ws.onerror = (err) => {
            console.warn("[!] WebSocket connection error:", err);
            AppState.ws.close();
        };
    } catch (e) {
        console.error("[!] Could not open WebSocket:", e);
        setTimeout(connectWebSocket, 3000);
    }
}

// ==============================================================================
// 2. Telemetry Processing & DOM Updates
// ==============================================================================

function processTelemetryPayload(payload) {
    if (!payload) return;

    AppState.liveMode = payload.live_mode || false;
    const modeBadge = document.getElementById("engineModeBadge");
    if (modeBadge) {
        if (AppState.liveMode) {
            modeBadge.className = "badge badge-live";
            modeBadge.innerHTML = `<span class="pulse-dot"></span> LIVE eBPF / XDP (${payload.ports_bound || 16}/16 PORTS)`;
        } else {
            modeBadge.className = "badge badge-sim";
            modeBadge.innerHTML = `<span class="pulse-dot"></span> SIMULATION MODE`;
        }
    }

    // Update Diagnostics KPI Metrics
    const diag = payload.diagnostics || {};
    const statFrames = document.getElementById("statFrames");
    const statDrops = document.getElementById("statDrops");
    const statLateral = document.getElementById("statLateral");
    const statHysteresis = document.getElementById("statHysteresis");
    const statConfinement = document.getElementById("statConfinement");

    if (statFrames) statFrames.innerText = (diag.intercepted || 0).toLocaleString();
    if (statDrops) statDrops.innerText = (diag.quarantine_drops || 0).toLocaleString();
    if (statLateral) statLateral.innerText = (diag.lateral_drops || 0).toLocaleString();

    // Calculate repeat offenders and blast radius confinement
    let repeatOffenders = 0;
    let quarantinedCount = 0;
    let healthyLegitCount = 0;
    const nodes = payload.nodes || [];

    nodes.forEach(node => {
        AppState.nodes.set(node.ip, node);
        if (node.offense_count_k > 0) repeatOffenders++;
        if (node.state === 2) quarantinedCount++;

        // Legitimate tiers: web (11-14), api (21-24), data (31-34), client (41-42)
        const last = parseInt(node.ip.split(".")[3]);
        if (last < 50 && node.state === 0) {
            healthyLegitCount++;
        }
    });

    if (statHysteresis) statHysteresis.innerText = `${repeatOffenders} Nodes`;

    // Confinement Ratio: B_confine = (14 healthy legit / 14 total legit) * 100%
    const confinementRatio = (healthyLegitCount / 14.0) * 100.0;
    if (statConfinement) {
        statConfinement.innerText = `${confinementRatio.toFixed(1)}%`;
        statConfinement.style.color = confinementRatio === 100.0 ? "var(--color-trusted)" : "var(--color-quarantined)";
    }

    // Update 16 Node Cards
    renderNodeCards(nodes);

    // Update Audit Stream
    if (payload.audit_log) {
        renderAuditStream(payload.audit_log);
    }

    // Update Analytics Charts
    updateCharts(nodes, diag);

    // Spawn animated canvas particles based on live traffic
    generateTrafficParticles(nodes, diag);
}

// Render the 16 Workload Cards organized into 4 Tier Rows
function renderNodeCards(nodes) {
    nodes.forEach(node => {
        const cardId = `node-card-${node.ip.replace(/\./g, "-")}`;
        let card = document.getElementById(cardId);

        if (!card) {
            // Cards are statically generated in HTML, but fallback if not found
            return;
        }

        // Strict Zero-Trust State Enforcement: Trust Score directly dictates security state
        const score = typeof node.trust_score === 'number' ? node.trust_score : 100.0;
        let effectiveState = typeof node.state === 'number' ? node.state : 0;
        if (score < 30.0) {
            effectiveState = 2; // QUARANTINED
        } else if (score < 70.0) {
            effectiveState = 1; // SUSPECT
        } else {
            effectiveState = 0; // TRUSTED
        }

        const stateClass = effectiveState === 2 ? "quarantined" : (effectiveState === 1 ? "suspect" : "trusted");
        const stateLabel = effectiveState === 2 ? "QUARANTINED [DROP]" : (effectiveState === 1 ? "SUSPECT [THROTTLED]" : "TRUSTED [PASS]");
        const badgeClass = effectiveState === 2 ? "badge-quarantine" : (effectiveState === 1 ? "badge-sim" : "badge-live");

        card.className = `node-card ${stateClass}`;

        // Badge
        const badgeElem = card.querySelector(".node-state-badge");
        if (badgeElem) {
            badgeElem.className = `badge ${badgeClass} node-state-badge`;
            badgeElem.innerText = stateLabel;
        }

        // Trust Score & Bar
        const scoreElem = card.querySelector(".trust-score-val");
        const fillElem = card.querySelector(".trust-fill");
        if (scoreElem) scoreElem.innerText = `${score.toFixed(1)}%`;
        if (fillElem) {
            fillElem.style.width = `${Math.min(100, Math.max(0, score))}%`;
            fillElem.className = `trust-fill fill-${stateClass}`;
        }

        // Hysteresis Offense & Healing
        const kCount = node.offense_count_k || 0;
        const healRate = typeof node.healing_rate === 'number' ? node.healing_rate : 6.0;
        const kElem = card.querySelector(".offense-k");
        const healElem = card.querySelector(".healing-rate-val");
        if (kElem) {
            const mult = kCount > 0 ? Math.pow(2, kCount - 1) : 1;
            kElem.innerText = `k=${kCount} (${mult}× penalty)`;
        }
        if (healElem) healElem.innerText = `+${healRate.toFixed(1)} pts/s`;

        // Metrics: Passes, Drops, Lat Drops, PPS
        const valPass = card.querySelector(".val-pass");
        const valDrops = card.querySelector(".val-drops");
        const valLat = card.querySelector(".val-lat");
        const valPps = card.querySelector(".val-pps");

        if (valPass) valPass.innerText = (node.passes || 0).toLocaleString();
        if (valDrops) valDrops.innerText = (node.drops || 0).toLocaleString();
        if (valLat) valLat.innerText = (node.lateral_drops || 0).toLocaleString();
        if (valPps) valPps.innerText = `${(node.pps || 0).toFixed(0)} pps`;
    });
}

// Render the Live Microsecond Audit Log
function renderAuditStream(auditLog) {
    const container = document.getElementById("auditStream");
    if (!container) return;

    container.innerHTML = "";
    if (Array.isArray(auditLog)) {
        auditLog.slice().reverse().forEach(entry => {
            if (!entry) return;
            const row = document.createElement("div");
            row.className = "audit-entry";
            const latVal = typeof entry.latency_us === 'number' ? entry.latency_us : 0.0;
            const latText = latVal > 0 ? `[${latVal.toFixed(2)} µs]` : "";
            row.innerHTML = `
                <span class="audit-ts">${entry.timestamp || "00:00:00"}</span>
                <span class="audit-entity">${entry.entity || "SYSTEM"}</span>
                <span class="audit-msg">${entry.message || ""}</span>
                <span class="audit-lat">${latText}</span>
            `;
            container.appendChild(row);
        });
    }
}

// ==============================================================================
// 3. HTML5 Canvas: Animated East-West Traffic Flow & Lateral Deflection
// ==============================================================================

let canvas, ctx;
let nodePositions = new Map();

function initCanvas() {
    canvas = document.getElementById("flowCanvas");
    if (!canvas) return;
    ctx = canvas.getContext("2d");
    resizeCanvas();
    requestAnimationFrame(renderCanvasLoop);
}

function resizeCanvas() {
    if (!canvas) return;
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;
    calculateNodeCoordinates();
}

function calculateNodeCoordinates() {
    if (!canvas) return;
    nodePositions.clear();

    const w = canvas.width;
    const h = canvas.height;

    // 4 Column Layout: Tier 4 (Clients/Threats) -> Tier 1 (Web) -> Tier 2 (API) -> Tier 3 (Data)
    const tiers = [
        { key: "threat", xPct: 0.12, ips: ["10.20.0.41", "10.20.0.42", "10.20.0.51", "10.20.0.52"] },
        { key: "web",    xPct: 0.38, ips: ["10.20.0.11", "10.20.0.12", "10.20.0.13", "10.20.0.14"] },
        { key: "api",    xPct: 0.64, ips: ["10.20.0.21", "10.20.0.22", "10.20.0.23", "10.20.0.24"] },
        { key: "data",   xPct: 0.88, ips: ["10.20.0.31", "10.20.0.32", "10.20.0.33", "10.20.0.34"] }
    ];

    tiers.forEach(tier => {
        const x = w * tier.xPct;
        const count = tier.ips.length;
        tier.ips.forEach((ip, idx) => {
            const y = (h * 0.2) + (idx * ((h * 0.65) / (count - 1)));
            nodePositions.set(ip, { x, y, tier: tier.key });
        });
    });
}

function generateTrafficParticles(nodes, diag) {
    // Generate routine benign traffic particles
    if (Math.random() < 0.35) {
        // Client -> Web
        spawnParticle("10.20.0.41", "10.20.0.11", "#06b6d4", false);
    }
    if (Math.random() < 0.35) {
        // Web -> API
        spawnParticle("10.20.0.11", "10.20.0.21", "#8b5cf6", false);
    }
    if (Math.random() < 0.35) {
        // API -> DB
        spawnParticle("10.20.0.21", "10.20.0.31", "#10b981", false);
    }

    // Check if attack pods are generating active attack traffic
    const attkLateral = AppState.nodes.get("10.20.0.51");
    const isLateralActive = AppState.activeAttack === "lateral_scan" || 
                           (attkLateral && (attkLateral.pps > 10.0 || attkLateral.syn_pps > 5.0));
    if (isLateralActive && attkLateral) {
        const isDropped = attkLateral.state === 2 || attkLateral.drops > 0;
        spawnParticle("10.20.0.51", "10.20.0.31", "#ef4444", isDropped);
    }

    const attkDdos = AppState.nodes.get("10.20.0.52");
    const isDdosActive = AppState.activeAttack === "volumetric_flood" || 
                         (attkDdos && (attkDdos.pps > 50.0 || attkDdos.syn_pps > 20.0));
    if (isDdosActive && attkDdos) {
        const isDropped = attkDdos.state === 2 || attkDdos.drops > 0;
        spawnParticle("10.20.0.52", "10.20.0.11", "#f43f5e", isDropped);
    }

    if (AppState.activeAttack === "web_db_bypass") {
        spawnParticle("10.20.0.11", "10.20.0.31", "#f59e0b", true);
    }
}

function spawnParticle(srcIp, dstIp, color, isBlocked) {
    // Hard cap particles to maintain silky-smooth 60 FPS in VM
    if (AppState.flowParticles.length >= 20) return;

    const src = nodePositions.get(srcIp);
    const dst = nodePositions.get(dstIp);
    if (!src || !dst) return;

    AppState.flowParticles.push({
        x: src.x,
        y: src.y,
        startX: src.x,
        startY: src.y,
        targetX: dst.x,
        targetY: dst.y,
        progress: 0.0,
        speed: 0.018 + Math.random() * 0.01,
        color: color,
        isBlocked: isBlocked,
        interceptProgress: isBlocked ? (0.35 + Math.random() * 0.15) : 1.0
    });
}

function createSparks(x, y, color) {
    if (AppState.sparkParticles.length >= 25) return;
    for (let i = 0; i < 4; i++) {
        const angle = Math.random() * Math.PI * 2;
        const spd = 1.0 + Math.random() * 2.0;
        AppState.sparkParticles.push({
            x: x,
            y: y,
            vx: Math.cos(angle) * spd,
            vy: Math.sin(angle) * spd,
            life: 1.0,
            decay: 0.06 + Math.random() * 0.04,
            color: color
        });
    }
}

function renderCanvasLoop() {
    if (!ctx || !canvas) return;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw Column Tier Headers
    ctx.font = "10px JetBrains Mono, monospace";
    ctx.textAlign = "center";
    ctx.fillStyle = "#64748b";

    const colHeaders = [
        { xPct: 0.12, text: "CLIENTS & ATTACKERS" },
        { xPct: 0.38, text: "TIER 1: WEB FRONTEND" },
        { xPct: 0.64, text: "TIER 2: MICROSERVICE APIS" },
        { xPct: 0.88, text: "TIER 3: CORE DATA STORE" }
    ];

    colHeaders.forEach(col => {
        ctx.fillText(col.text, canvas.width * col.xPct, 22);
    });

    // Draw Background Grid Lines between nodes (single batched stroke for high performance)
    ctx.strokeStyle = "rgba(255, 255, 255, 0.03)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    nodePositions.forEach((posA) => {
        nodePositions.forEach((posB) => {
            if (posB.x > posA.x) {
                ctx.moveTo(posA.x, posA.y);
                ctx.lineTo(posB.x, posB.y);
            }
        });
    });
    ctx.stroke();

    // Draw Virtual Switch Fabric & Kernel XDP Perimeter Boundary
    const xdpBoundaryX = canvas.width * 0.25;
    ctx.strokeStyle = "rgba(6, 182, 212, 0.25)";
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(xdpBoundaryX, 35);
    ctx.lineTo(xdpBoundaryX, canvas.height - 15);
    ctx.stroke();
    ctx.setLineDash([]);

    ctx.fillStyle = "rgba(6, 182, 212, 0.6)";
    ctx.font = "9px JetBrains Mono, monospace";
    ctx.textAlign = "center";
    ctx.fillText("XDP DRIVER ISOLATION PERIMETER", xdpBoundaryX, canvas.height - 6);

    // Update & Render Flow Particles
    for (let i = AppState.flowParticles.length - 1; i >= 0; i--) {
        const p = AppState.flowParticles[i];
        p.progress += p.speed;

        // Current position along cubic trajectory
        p.x = p.startX + (p.targetX - p.startX) * p.progress;
        p.y = p.startY + (p.targetY - p.startY) * p.progress;

        // Check if packet is blocked at isolation hook
        if (p.isBlocked && p.progress >= p.interceptProgress) {
            createSparks(p.x, p.y, p.color);
            AppState.flowParticles.splice(i, 1);
            continue;
        }

        if (p.progress >= 1.0) {
            AppState.flowParticles.splice(i, 1);
            continue;
        }

        // Render particle with glow
        ctx.fillStyle = p.color;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.isBlocked ? 3.5 : 2.5, 0, Math.PI * 2);
        ctx.fill();
    }

    // Render Deflection Sparks
    for (let i = AppState.sparkParticles.length - 1; i >= 0; i--) {
        const s = AppState.sparkParticles[i];
        s.x += s.vx;
        s.y += s.vy;
        s.life -= s.decay;

        if (s.life <= 0) {
            AppState.sparkParticles.splice(i, 1);
            continue;
        }

        ctx.fillStyle = s.color;
        ctx.globalAlpha = s.life;
        ctx.beginPath();
        ctx.arc(s.x, s.y, 1.8, 0, Math.PI * 2);
        ctx.fill();
        ctx.globalAlpha = 1.0;
    }

    // Draw Nodes
    nodePositions.forEach((pos, ip) => {
        const node = AppState.nodes.get(ip);
        const state = node ? node.state : 0;
        let color = "#10b981"; // trusted
        if (state === 1) color = "#f59e0b"; // suspect
        if (state === 2) color = "#ef4444"; // quarantined

        // Outer glow circle
        ctx.fillStyle = color;
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, 6, 0, Math.PI * 2);
        ctx.fill();

        // Node IP Label
        ctx.font = "8px JetBrains Mono, monospace";
        ctx.fillStyle = "#94a3b8";
        ctx.textAlign = "center";
        ctx.fillText(ip.split(".").slice(2).join("."), pos.x, pos.y + 16);
    });

    requestAnimationFrame(renderCanvasLoop);
}

// ==============================================================================
// 4. Chart.js Analytics Graphs
// ==============================================================================

function initCharts() {
    const ctxTrust = document.getElementById("chartTrust");
    const ctxTraffic = document.getElementById("chartTraffic");

    if (ctxTrust) {
        AppState.chartTrust = new Chart(ctxTrust, {
            type: "bar",
            data: {
                labels: Array.from({length: 16}, (_, i) => `Node ${i+1}`),
                datasets: [{
                    label: "Trust Score (%)",
                    data: Array(16).fill(100),
                    backgroundColor: "#10b981",
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        ticks: { color: "#64748b", font: { family: "JetBrains Mono", size: 10 } }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: "#94a3b8", font: { family: "JetBrains Mono", size: 9 }, maxRotation: 45 }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    if (ctxTraffic) {
        AppState.chartTraffic = new Chart(ctxTraffic, {
            type: "line",
            data: {
                labels: [],
                datasets: [
                    {
                        label: "Ingress PPS",
                        data: [],
                        borderColor: "#06b6d4",
                        backgroundColor: "rgba(6, 182, 212, 0.1)",
                        tension: 0.3,
                        fill: true
                    },
                    {
                        label: "Discard Rate (Drops/s)",
                        data: [],
                        borderColor: "#ef4444",
                        backgroundColor: "rgba(239, 68, 68, 0.15)",
                        tension: 0.3,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        ticks: { color: "#64748b", font: { family: "JetBrains Mono", size: 10 } }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: "#64748b", font: { family: "JetBrains Mono", size: 9 } }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: "#94a3b8", font: { family: "JetBrains Mono", size: 10 } }
                    }
                }
            }
        });
    }
}

function updateCharts(nodes, diag) {
    if (AppState.chartTrust && nodes.length > 0) {
        AppState.chartTrust.data.labels = nodes.map(n => n.alias.replace("ns-", ""));
        AppState.chartTrust.data.datasets[0].data = nodes.map(n => n.trust_score);
        AppState.chartTrust.data.datasets[0].backgroundColor = nodes.map(n => {
            if (n.trust_score < 30.0 || n.state === 2) return "#ef4444";
            if (n.trust_score < 70.0 || n.state === 1) return "#f59e0b";
            return "#10b981";
        });
        AppState.chartTrust.update();
    }

    if (AppState.chartTraffic) {
        const now = new Date().toLocaleTimeString();
        const nowMs = Date.now();
        let totalPps = 0;
        nodes.forEach(n => totalPps += (n.pps || 0));

        // Compute instantaneous discard rate (Drops/sec)
        const currentDrops = (diag.quarantine_drops || 0) + (diag.lateral_drops || 0);
        let dropRate = 0;
        if (AppState.lastDropTime > 0) {
            const dtSec = (nowMs - AppState.lastDropTime) / 1000.0;
            if (dtSec > 0 && currentDrops >= AppState.lastDropCount) {
                dropRate = (currentDrops - AppState.lastDropCount) / dtSec;
            }
        }
        AppState.lastDropCount = currentDrops;
        AppState.lastDropTime = nowMs;

        AppState.trafficHistory.labels.push(now);
        AppState.trafficHistory.ingress.push(Math.round(totalPps));
        AppState.trafficHistory.drops.push(Math.round(dropRate));

        if (AppState.trafficHistory.labels.length > AppState.maxHistoryPoints) {
            AppState.trafficHistory.labels.shift();
            AppState.trafficHistory.ingress.shift();
            AppState.trafficHistory.drops.shift();
        }

        AppState.chartTraffic.data.labels = AppState.trafficHistory.labels;
        AppState.chartTraffic.data.datasets[0].data = AppState.trafficHistory.ingress;
        AppState.chartTraffic.data.datasets[1].data = AppState.trafficHistory.drops;
        AppState.chartTraffic.update();
    }
}

// ==============================================================================
// 5. User Action Handlers (REST API Mutations & Attack Triggers)
// ==============================================================================

function initEventListeners() {
    // Attack Simulation Buttons
    const btnLateral = document.getElementById("btnAttackLateral");
    const btnDdos = document.getElementById("btnAttackDdos");
    const btnBypass = document.getElementById("btnAttackBypass");
    const btnStop = document.getElementById("btnAttackStop");

    if (btnLateral) btnLateral.addEventListener("click", () => triggerAttack("lateral_scan", "10.20.0.31"));
    if (btnDdos) btnDdos.addEventListener("click", () => triggerAttack("volumetric_flood", "10.20.0.11"));
    if (btnBypass) btnBypass.addEventListener("click", () => triggerAttack("web_db_bypass", "10.20.0.31"));
    if (btnStop) btnStop.addEventListener("click", stopAllAttacks);

    // East-West Matrix Policy Form
    const btnApplyEw = document.getElementById("btnApplyEw");
    if (btnApplyEw) {
        btnApplyEw.addEventListener("click", () => {
            const src = document.getElementById("ewSrcPod").value;
            const dst = document.getElementById("ewDstPod").value;
            const action = document.getElementById("ewAction").value;
            applyLateralRule(src, dst, action);
        });
    }

    // Event Delegation for Workload Card Action Buttons
    document.addEventListener("click", (e) => {
        const btn = e.target.closest(".btn-action");
        if (!btn) return;
        const ip = btn.getAttribute("data-ip");
        const action = btn.getAttribute("data-action");
        if (ip && action) {
            mutateNode(ip, action);
        }
    });
}

async function triggerAttack(vector, targetIp) {
    AppState.activeAttack = vector;

    // Highlight active attack button
    const btnMap = {
        "lateral_scan": document.getElementById("btnAttackLateral"),
        "volumetric_flood": document.getElementById("btnAttackDdos"),
        "web_db_bypass": document.getElementById("btnAttackBypass")
    };
    Object.values(btnMap).forEach(b => {
        if (b) b.style.outline = "none";
    });
    if (btnMap[vector]) {
        btnMap[vector].style.outline = "2px solid #ef4444";
    }

    try {
        const res = await fetch("/api/cluster/attack", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ vector: vector, target_ip: targetIp, rate: 500 })
        });
        const data = await res.json();
        console.log("[+] Attack triggered:", data);
    } catch (e) {
        console.error("[-] Failed to trigger attack:", e);
    }
}

async function stopAllAttacks() {
    const btnStop = document.getElementById("btnAttackStop");
    const origHtml = btnStop ? btnStop.innerHTML : "";

    if (btnStop) {
        btnStop.innerHTML = `<span class="btn-attack-title"><span>⏳</span> Neutralizing...</span><span class="btn-attack-desc">Stopping processes & resetting eBPF maps</span>`;
        btnStop.disabled = true;
    }

    // 1. Immediately reset client-side active attack state & particle buffers
    AppState.activeAttack = null;
    AppState.flowParticles = [];
    AppState.sparkParticles = [];

    // Reset outline on attack buttons
    ["btnAttackLateral", "btnAttackDdos", "btnAttackBypass"].forEach(id => {
        const b = document.getElementById(id);
        if (b) b.style.outline = "none";
    });

    // 2. Immediately restore DOM cards for attack pods to nominal baseline
    const targetIps = ["10.20.0.51", "10.20.0.52", "10.20.0.11"];
    targetIps.forEach(ip => {
        const cardId = `node-card-${ip.replace(/\./g, "-")}`;
        const card = document.getElementById(cardId);
        if (card) {
            card.className = "node-card trusted";
            const badge = card.querySelector(".node-state-badge");
            if (badge) {
                badge.className = "badge badge-live";
                badge.innerText = "TRUSTED";
            }
            const score = card.querySelector(".trust-score-val");
            if (score) score.innerText = "100.0%";
            const fill = card.querySelector(".trust-fill");
            if (fill) {
                fill.style.width = "100%";
                fill.className = "trust-fill fill-trusted";
            }
            const pps = card.querySelector(".val-pps");
            if (pps) pps.innerText = "0 pps";
        }

        const node = AppState.nodes.get(ip);
        if (node) {
            node.state = 0;
            node.state_name = "TRUSTED";
            node.trust_score = 100.0;
            node.pps = 0.0;
            node.syn_pps = 0.0;
        }
    });

    // 3. Dispatch server-side termination & kernel policy reset
    try {
        const res = await fetch("/api/cluster/attack/stop", {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        const data = await res.json();
        console.log("[+] Attacks stopped & datapath restored:", data);

        if (btnStop) {
            btnStop.innerHTML = `<span class="btn-attack-title"><span style="color:#10b981;">✓</span> Attacks Neutralized!</span><span class="btn-attack-desc">Datapath & trust scores restored to baseline</span>`;
        }

        // Add immediate visual feedback in audit stream
        const auditStream = document.getElementById("auditStream");
        if (auditStream) {
            const row = document.createElement("div");
            row.className = "audit-entry";
            row.innerHTML = `
                <span class="audit-ts">${new Date().toLocaleTimeString()}</span>
                <span class="audit-entity" style="color:#10b981;">NEUTRALIZE</span>
                <span class="audit-msg">All attack processes terminated & baseline datapath restored</span>
                <span class="audit-lat" style="color:#10b981;">[RESTORED]</span>
            `;
            auditStream.prepend(row);
        }
    } catch (e) {
        console.error("[-] Failed to stop attacks:", e);
        if (btnStop) {
            btnStop.innerHTML = `<span class="btn-attack-title"><span>⚠️</span> Error Stopping</span><span class="btn-attack-desc">${e.message}</span>`;
        }
    } finally {
        setTimeout(() => {
            if (btnStop) {
                btnStop.innerHTML = `<span class="btn-attack-title"><span>🛑</span> Emergency Neutralize</span><span class="btn-attack-desc">Kill attack processes & restore quiescent baseline</span>`;
                btnStop.disabled = false;
            }
        }, 2200);
    }
}

async function applyLateralRule(srcIp, dstIp, action) {
    try {
        const res = await fetch("/api/cluster/isolate-lateral", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ src_ip: srcIp, dst_ip: dstIp, action: action })
        });
        const data = await res.json();
        console.log("[+] East-West Rule Applied:", data);
    } catch (e) {
        console.error("[-] Failed to apply East-West rule:", e);
    }
}

async function mutateNode(ip, action) {
    try {
        const res = await fetch("/api/cluster/mutate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: ip, action: action })
        });
        const data = await res.json();
        console.log("[+] Workload mutated:", data);
    } catch (e) {
        console.error("[-] Failed to mutate workload:", e);
    }
}

