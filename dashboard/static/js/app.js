/**
 * Kernel-Level Zero-Trust Traffic Isolation Engine — Presentation Plane Controller
 * WebSocket Stream Consumer, Chart.js Time-Series Engine & Topology Canvas Animator
 */

document.addEventListener("DOMContentLoaded", () => {
    // State Store
    let ws = null;
    let isConnected = false;
    let maxChartPoints = 25;
    let chartTimestamps = [];
    let ppsData = { attacker: [], legit: [], victim: [] };
    let trustData = { attacker: [], legit: [], victim: [] };

    // Charts references
    let chartPps = null;
    let chartTrust = null;
    let chartPenalty = null;
    let chartLatency = null;

    // Topology Canvas setup
    const canvas = document.getElementById("topologyCanvas");
    const ctx = canvas.getContext("2d");
    let particles = [];
    let topologyState = {
        attackerState: 0, // 0: Trusted, 1: Suspect, 2: Quarantined
        legitPps: 2.0,
        attackerPps: 1.0
    };

    // =========================================================================
    // Chart.js Initialization
    // =========================================================================

    function initCharts() {
        Chart.defaults.color = "#94a3b8";
        Chart.defaults.font.family = "'Inter', sans-serif";

        // Chart 1: Ingress PPS Time-Series
        const ctxPps = document.getElementById("chartPps").getContext("2d");
        chartPps = new Chart(ctxPps, {
            type: "line",
            data: {
                labels: chartTimestamps,
                datasets: [
                    {
                        label: "Node C (Attacker)",
                        borderColor: "#ef4444",
                        backgroundColor: "rgba(239, 68, 68, 0.1)",
                        data: ppsData.attacker,
                        tension: 0.3,
                        borderWidth: 2,
                        fill: true,
                        pointRadius: 2
                    },
                    {
                        label: "Node B (Legitimate)",
                        borderColor: "#10b981",
                        backgroundColor: "transparent",
                        data: ppsData.legit,
                        tension: 0.3,
                        borderWidth: 2,
                        pointRadius: 2
                    },
                    {
                        label: "Node A (Victim Target)",
                        borderColor: "#06b6d4",
                        backgroundColor: "transparent",
                        data: ppsData.victim,
                        tension: 0.3,
                        borderWidth: 1.5,
                        borderDash: [4, 4],
                        pointRadius: 1
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                scales: {
                    x: { grid: { color: "rgba(255, 255, 255, 0.05)" } },
                    y: {
                        beginAtZero: true,
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        title: { display: true, text: "Packets / Sec (PPS)" }
                    }
                },
                plugins: {
                    legend: { position: "top", labels: { boxWidth: 12 } }
                }
            }
        });

        // Chart 2: Workload Trust Score Trajectory (0 - 100%)
        const ctxTrust = document.getElementById("chartTrust").getContext("2d");
        chartTrust = new Chart(ctxTrust, {
            type: "line",
            data: {
                labels: chartTimestamps,
                datasets: [
                    {
                        label: "Node C Trust Score",
                        borderColor: "#f59e0b",
                        backgroundColor: "rgba(245, 158, 11, 0.15)",
                        data: trustData.attacker,
                        tension: 0.2,
                        borderWidth: 2.5,
                        fill: true,
                        pointRadius: 3
                    },
                    {
                        label: "Node B Trust Score",
                        borderColor: "#10b981",
                        backgroundColor: "transparent",
                        data: trustData.legit,
                        tension: 0.1,
                        borderWidth: 1.5,
                        pointRadius: 0
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                scales: {
                    x: { grid: { color: "rgba(255, 255, 255, 0.05)" } },
                    y: {
                        min: 0,
                        max: 100,
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        title: { display: true, text: "Trust Gauge (%)" }
                    }
                },
                plugins: {
                    legend: { position: "top", labels: { boxWidth: 12 } }
                }
            }
        });

        // Chart 3: Threat Penalty Distribution (Stacked Bar)
        const ctxPenalty = document.getElementById("chartPenalty").getContext("2d");
        chartPenalty = new Chart(ctxPenalty, {
            type: "bar",
            data: {
                labels: ["Node A (Victim)", "Node B (Legit)", "Node C (Attacker)"],
                datasets: [
                    {
                        label: "Volumetric Flood (P_pps)",
                        backgroundColor: "#ef4444",
                        data: [0, 0, 0]
                    },
                    {
                        label: "TCP SYN Flood (P_syn)",
                        backgroundColor: "#f97316",
                        data: [0, 0, 0]
                    },
                    {
                        label: "Port Reconnaissance (P_scan)",
                        backgroundColor: "#8b5cf6",
                        data: [0, 0, 0]
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { stacked: true, grid: { display: false } },
                    y: {
                        stacked: true,
                        min: 0,
                        max: 100,
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        title: { display: true, text: "Penalty Points" }
                    }
                },
                plugins: {
                    legend: { position: "top", labels: { boxWidth: 12 } }
                }
            }
        });

        // Chart 4: Mitigation Latency Comparison (T_isolate in µs)
        const ctxLatency = document.getElementById("chartLatency").getContext("2d");
        chartLatency = new Chart(ctxLatency, {
            type: "bar",
            data: {
                labels: [
                    "eBPF / XDP (Our Engine)",
                    "Traditional iptables / nftables",
                    "User-Space Proxy (Envoy / Istio)"
                ],
                datasets: [{
                    label: "Mitigation Latency T_isolate (Microseconds - Logarithmic)",
                    data: [38.35, 7500.0, 25000.0],
                    backgroundColor: [
                        "#06b6d4",
                        "#64748b",
                        "#475569"
                    ],
                    borderRadius: 6
                }]
            },
            options: {
                indexAxis: "y",
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        type: "logarithmic",
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        title: { display: true, text: "Microseconds (µs) — Lower is Faster" }
                    },
                    y: { grid: { display: false } }
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                if (context.dataIndex === 0) {
                                    return "38.35 µs (0.038 ms) — 195.5x Faster";
                                } else if (context.dataIndex === 1) {
                                    return "7,500 µs (7.5 ms)";
                                } else {
                                    return "25,000 µs (25.0 ms)";
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    // =========================================================================
    // WebSocket Connection Manager
    // =========================================================================

    function connectWebSocket() {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            isConnected = true;
            document.getElementById("connectionStatus").className = "badge-mode badge-live";
            document.getElementById("connectionText").textContent = "CONNECTED (LIVE WS)";
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                handleTelemetryData(data);
            } catch (err) {
                console.error("Telemetry parse error:", err);
            }
        };

        ws.onclose = () => {
            isConnected = false;
            document.getElementById("connectionStatus").className = "badge-mode badge-sim";
            document.getElementById("connectionText").textContent = "RECONNECTING...";
            setTimeout(connectWebSocket, 1500);
        };

        ws.onerror = (err) => {
            ws.close();
        };
    }

    // =========================================================================
    // Telemetry Data Ingestion & DOM Rendering
    // =========================================================================

    function handleTelemetryData(data) {
        // Engine mode badge
        const modeBadge = document.getElementById("engineModeBadge");
        if (data.engine_mode === "LIVE_KERNEL_EBPF") {
            modeBadge.textContent = "KERNEL DATAPATH (eBPF/XDP)";
            modeBadge.className = "badge-mode badge-live";
        } else {
            modeBadge.textContent = "SIMULATOR / LAB MODE";
            modeBadge.className = "badge-mode badge-sim";
        }

        // Global counters
        document.getElementById("statFrames").textContent = Number(data.global_counters.frames_intercepted).toLocaleString();
        document.getElementById("statDrops").textContent = Number(data.global_counters.quarantined_drops).toLocaleString();
        document.getElementById("statThrottles").textContent = Number(data.global_counters.suspect_throttles).toLocaleString();

        // Update Node Cards
        let attackerNode = null;
        let legitNode = null;
        let victimNode = null;

        data.nodes.forEach(node => {
            if (node.ip === "10.10.0.30") attackerNode = node;
            if (node.ip === "10.10.0.20") legitNode = node;
            if (node.ip === "10.10.0.10") victimNode = node;

            renderNodeCard(node);
        });

        // Push to Charts Time Series
        const timeLabel = data.timestamp;
        chartTimestamps.push(timeLabel);
        if (chartTimestamps.length > maxChartPoints) chartTimestamps.shift();

        if (attackerNode) {
            ppsData.attacker.push(attackerNode.pps);
            trustData.attacker.push(attackerNode.trust_score);
            topologyState.attackerState = attackerNode.state_id;
            topologyState.attackerPps = attackerNode.pps;
        }
        if (legitNode) {
            ppsData.legit.push(legitNode.pps);
            trustData.legit.push(legitNode.trust_score);
            topologyState.legitPps = legitNode.pps;
        }
        if (victimNode) {
            ppsData.victim.push(victimNode.pps);
            trustData.victim.push(victimNode.trust_score);
        }

        if (ppsData.attacker.length > maxChartPoints) ppsData.attacker.shift();
        if (ppsData.legit.length > maxChartPoints) ppsData.legit.shift();
        if (ppsData.victim.length > maxChartPoints) ppsData.victim.shift();

        if (trustData.attacker.length > maxChartPoints) trustData.attacker.shift();
        if (trustData.legit.length > maxChartPoints) trustData.legit.shift();
        if (trustData.victim.length > maxChartPoints) trustData.victim.shift();

        // Update Chart 1 & 2
        if (chartPps) chartPps.update();
        if (chartTrust) chartTrust.update();

        // Update Chart 3: Penalties
        if (chartPenalty && attackerNode && legitNode && victimNode) {
            chartPenalty.data.datasets[0].data = [
                victimNode.penalties.pps,
                legitNode.penalties.pps,
                attackerNode.penalties.pps
            ];
            chartPenalty.data.datasets[1].data = [
                victimNode.penalties.syn,
                legitNode.penalties.syn,
                attackerNode.penalties.syn
            ];
            chartPenalty.data.datasets[2].data = [
                victimNode.penalties.scan,
                legitNode.penalties.scan,
                attackerNode.penalties.scan
            ];
            chartPenalty.update();
        }

        // Render Transitions Audit Feed
        renderAuditTable(data.transitions);

        // Highlight Active Simulation Button
        highlightActiveAttackButton(data.active_attack);
    }

    function renderNodeCard(node) {
        const cardId = `card-${node.ip.replace(/\./g, "-")}`;
        const card = document.getElementById(cardId);
        if (!card) return;

        // Reset classes
        card.className = `node-card glass-panel ${node.state.toLowerCase()}`;

        // State Badge
        const badge = card.querySelector(".state-badge");
        badge.className = `state-badge state-${node.state.toLowerCase()}`;
        badge.innerHTML = `<span class="pulse-dot"></span> ${node.state}`;

        // Trust Score & Gauge
        const scoreVal = card.querySelector(".trust-score-val");
        scoreVal.textContent = `${node.trust_score.toFixed(1)}%`;

        const fill = card.querySelector(".trust-gauge-fill");
        fill.style.width = `${node.trust_score}%`;
        fill.className = `trust-gauge-fill fill-${node.state.toLowerCase()}`;

        // Metrics
        card.querySelector(".metric-pps").textContent = node.pps.toFixed(1);
        card.querySelector(".metric-syn").textContent = node.syn_rate.toFixed(1);
        card.querySelector(".metric-ports").textContent = node.unique_ports;
        card.querySelector(".metric-drops").textContent = Number(node.drops).toLocaleString();

        // Action button toggle
        const btnToggle = card.querySelector(".btn-toggle-action");
        if (node.state === "QUARANTINED") {
            btnToggle.textContent = "RESTORE WORKLOAD";
            btnToggle.className = "btn btn-success btn-toggle-action";
            btnToggle.setAttribute("data-action", "allow");
        } else {
            btnToggle.textContent = "QUARANTINE WORKLOAD";
            btnToggle.className = "btn btn-danger btn-toggle-action";
            btnToggle.setAttribute("data-action", "block");
        }
    }

    function renderAuditTable(transitions) {
        const tbody = document.getElementById("auditTableBody");
        if (!transitions || transitions.length === 0) return;

        let html = "";
        transitions.forEach(item => {
            const isQuarantine = item.new_state === "QUARANTINED";
            const isHeal = item.new_state === "TRUSTED";
            const badgeClass = isQuarantine ? "state-quarantined" : (isHeal ? "state-trusted" : "state-suspect");

            html += `
                <tr>
                    <td class="audit-time">${item.timestamp}</td>
                    <td class="audit-node">${item.node_name} (${item.ip})</td>
                    <td><span class="state-badge ${badgeClass}">${item.new_state}</span></td>
                    <td class="audit-lat">${item.t_isolate_us ? item.t_isolate_us.toFixed(2) + ' µs' : '—'}</td>
                    <td><strong>${item.trust_score.toFixed(1)}%</strong></td>
                    <td style="color: var(--text-secondary);">${item.reason}</td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    }

    function highlightActiveAttackButton(activeAttack) {
        const cards = document.querySelectorAll(".sim-card");
        cards.forEach(card => card.classList.remove("active-sim"));

        if (!activeAttack) return;
        const targetCard = document.querySelector(`.sim-card[data-attack="${activeAttack}"]`);
        if (targetCard) targetCard.classList.add("active-sim");
    }

    // =========================================================================
    // REST API Actions (Attacks & Overrides)
    // =========================================================================

    // Attack triggers
    document.querySelectorAll(".btn-sim").forEach(btn => {
        btn.addEventListener("click", async (e) => {
            const attackType = e.currentTarget.getAttribute("data-attack");
            try {
                await fetch("/api/attack/start", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ attack_type: attackType })
                });
            } catch (err) {
                console.error("Attack trigger failed:", err);
            }
        });
    });

    // Emergency Stop
    document.getElementById("btnStopAll").addEventListener("click", async () => {
        try {
            await fetch("/api/attack/stop", { method: "POST" });
        } catch (err) {
            console.error("Stop attack failed:", err);
        }
    });

    // Policy Override (Block / Allow)
    document.querySelectorAll(".btn-toggle-action").forEach(btn => {
        btn.addEventListener("click", async (e) => {
            const ip = e.currentTarget.getAttribute("data-ip");
            const action = e.currentTarget.getAttribute("data-action");

            try {
                await fetch("/api/policy/override", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ ip: ip, action: action })
                });
            } catch (err) {
                console.error("Policy override failed:", err);
            }
        });
    });

    // =========================================================================
    // Interactive SVG/Canvas Topology Particle Animator
    // =========================================================================

    function resizeCanvas() {
        const container = canvas.parentElement;
        canvas.width = container.clientWidth;
        canvas.height = container.clientHeight;
    }

    window.addEventListener("resize", resizeCanvas);
    resizeCanvas();

    class PacketParticle {
        constructor(sourceNode, targetNode, type, state) {
            this.x = sourceNode.x;
            this.y = sourceNode.y;
            this.targetX = targetNode.x;
            this.targetY = targetNode.y;
            this.progress = 0;
            this.speed = 0.015 + Math.random() * 0.01;
            this.type = type; // "legit" or "attacker"
            this.state = state; // 0: trusted, 1: suspect, 2: quarantined
            this.shattered = false;
        }

        update() {
            this.progress += this.speed;

            // XDP Hook is at progress = 0.55
            if (this.type === "attacker" && this.state === 2 && this.progress >= 0.55) {
                this.shattered = true;
            }

            // Interpolate position
            this.x = this.x + (this.targetX - this.x) * this.speed * 2.5;
            this.y = this.y + (this.targetY - this.y) * this.speed * 2.5;

            return this.progress < 1.0 && !this.shattered;
        }

        draw(ctx) {
            ctx.save();
            if (this.type === "legit") {
                ctx.fillStyle = "#10b981";
                ctx.shadowColor = "#10b981";
            } else if (this.state === 2) {
                ctx.fillStyle = "#ef4444";
                ctx.shadowColor = "#ef4444";
            } else if (this.state === 1) {
                ctx.fillStyle = "#f59e0b";
                ctx.shadowColor = "#f59e0b";
            } else {
                ctx.fillStyle = "#06b6d4";
                ctx.shadowColor = "#06b6d4";
            }

            ctx.shadowBlur = 8;
            ctx.beginPath();
            ctx.arc(this.x, this.y, 4, 0, Math.PI * 2);
            ctx.fill();

            // If shattered at XDP hook, draw impact spark
            if (this.shattered) {
                ctx.fillStyle = "#ef4444";
                ctx.beginPath();
                ctx.arc(this.x, this.y, 8, 0, Math.PI * 2);
                ctx.stroke();
            }
            ctx.restore();
        }
    }

    function animateTopology() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        const w = canvas.width;
        const h = canvas.height;

        // Node Coordinates
        const nodeAttacker = { x: w * 0.15, y: h * 0.35, label: "Node C (10.10.0.30)", color: "#ef4444" };
        const nodeLegit = { x: w * 0.15, y: h * 0.70, label: "Node B (10.10.0.20)", color: "#10b981" };
        const bridgeXdp = { x: w * 0.55, y: h * 0.50, label: "br-xdp [XDP HOOK: SKB]", color: "#8b5cf6" };
        const nodeVictim = { x: w * 0.85, y: h * 0.50, label: "Node A (10.10.0.10)", color: "#06b6d4" };

        // Draw Interconnect Links
        ctx.lineWidth = 2;
        ctx.strokeStyle = "rgba(255, 255, 255, 0.08)";

        // Attacker -> Bridge
        ctx.beginPath();
        ctx.moveTo(nodeAttacker.x, nodeAttacker.y);
        ctx.lineTo(bridgeXdp.x, bridgeXdp.y);
        ctx.stroke();

        // Legit -> Bridge
        ctx.beginPath();
        ctx.moveTo(nodeLegit.x, nodeLegit.y);
        ctx.lineTo(bridgeXdp.x, bridgeXdp.y);
        ctx.stroke();

        // Bridge -> Victim
        ctx.beginPath();
        ctx.moveTo(bridgeXdp.x, bridgeXdp.y);
        ctx.lineTo(nodeVictim.x, nodeVictim.y);
        ctx.stroke();

        // Spawn particles
        if (Math.random() < 0.3) {
            particles.push(new PacketParticle(nodeLegit, bridgeXdp, "legit", 0));
        }
        if (Math.random() < (topologyState.attackerPps > 50 ? 0.8 : 0.2)) {
            particles.push(new PacketParticle(nodeAttacker, bridgeXdp, "attacker", topologyState.attackerState));
        }

        // Bridge forwarder to victim
        if (Math.random() < 0.25) {
            particles.push(new PacketParticle(bridgeXdp, nodeVictim, "legit", 0));
        }

        // Update & draw particles
        particles = particles.filter(p => {
            const alive = p.update();
            p.draw(ctx);
            return alive;
        });

        // Draw Node Markers
        [nodeAttacker, nodeLegit, bridgeXdp, nodeVictim].forEach(node => {
            ctx.save();
            ctx.fillStyle = "#0d121f";
            ctx.strokeStyle = node.color;
            ctx.lineWidth = 3;
            ctx.shadowColor = node.color;
            ctx.shadowBlur = 12;

            ctx.beginPath();
            ctx.arc(node.x, node.y, 14, 0, Math.PI * 2);
            ctx.fill();
            ctx.stroke();

            // Label
            ctx.font = "11px 'JetBrains Mono', monospace";
            ctx.fillStyle = "#f8fafc";
            ctx.textAlign = "center";
            ctx.shadowBlur = 0;
            ctx.fillText(node.label, node.x, node.y + 28);
            ctx.restore();
        });

        // Draw XDP Drop Barrier if Attacker is Quarantined
        if (topologyState.attackerState === 2) {
            ctx.save();
            const barrierX = (nodeAttacker.x + bridgeXdp.x) * 0.55;
            const barrierY = (nodeAttacker.y + bridgeXdp.y) * 0.55;

            ctx.strokeStyle = "#ef4444";
            ctx.lineWidth = 4;
            ctx.shadowColor = "#ef4444";
            ctx.shadowBlur = 15;
            ctx.beginPath();
            ctx.moveTo(barrierX - 12, barrierY - 12);
            ctx.lineTo(barrierX + 12, barrierY + 12);
            ctx.stroke();

            ctx.fillStyle = "#ef4444";
            ctx.font = "bold 10px 'JetBrains Mono', monospace";
            ctx.fillText("XDP_DROP", barrierX, barrierY - 14);
            ctx.restore();
        }

        requestAnimationFrame(animateTopology);
    }

    // =========================================================================
    // Boot Initialization
    // =========================================================================
    initCharts();
    connectWebSocket();
    requestAnimationFrame(animateTopology);
});
