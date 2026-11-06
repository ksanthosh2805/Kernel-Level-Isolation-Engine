import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import os

os.makedirs('/home/daemon_targaryen/kernel-isolation-engine/paper/figures', exist_ok=True)

# 1. Fig 1: Architecture
fig, ax = plt.subplots(figsize=(7, 4.2), dpi=300)
ax.axis('off')

# Kernel Space Box
rect_kernel = plt.Rectangle((0.05, 0.45), 0.9, 0.50, fill=True, color='#fdf2f2', ec='#e06666', linestyle='--', linewidth=1.5)
ax.add_patch(rect_kernel)
ax.text(0.50, 0.91, 'Linux Kernel Space (eBPF/XDP Driver Fast-Path)', ha='center', va='center', fontsize=11, fontweight='bold', color='#b82525')

# User Space Box
rect_user = plt.Rectangle((0.05, 0.05), 0.9, 0.35, fill=True, color='#f0f4f8', ec='#4a86e8', linestyle='--', linewidth=1.5)
ax.add_patch(rect_user)
ax.text(0.50, 0.36, 'User Space & Testbed Mesh Plane', ha='center', va='center', fontsize=11, fontweight='bold', color='#1c4587')

# Helper for drawing blocks
def draw_box(x, y, w, h, text, color, ec, text_color='black', fontsize=9):
    box = plt.Rectangle((x, y), w, h, fill=True, color=color, ec=ec, linewidth=1.2, zorder=3)
    ax.add_patch(box)
    ax.text(x + w/2, y + h/2, text, ha='center', va='center', fontsize=fontsize, fontweight='bold', color=text_color, zorder=4)

draw_box(0.08, 0.65, 0.18, 0.12, 'Ingress NIC\nDriver Frame', '#cfe2f3', '#6fa8dc')
draw_box(0.38, 0.65, 0.22, 0.12, 'eBPF/XDP\nDatapath Filter', '#f4cccc', '#cc0000')
draw_box(0.72, 0.72, 0.18, 0.10, 'XDP_DROP\n(≈ 40 ns)', '#e06666', '#990000', text_color='white')
draw_box(0.72, 0.56, 0.18, 0.10, 'XDP_PASS\n(Kernel Stack)', '#b6d7a8', '#38761d', text_color='#1b4412')

draw_box(0.18, 0.50, 0.18, 0.10, 'eBPF\nPolicy Map', '#fce5cd', '#e69138')
draw_box(0.48, 0.50, 0.18, 0.10, 'BPF Ring Buffer\n(Lockless 256KB)', '#d9d2e9', '#674ea7')

draw_box(0.62, 0.14, 0.26, 0.15, 'Trust Decay Daemon\n(User Space Controller)', '#d0e0e3', '#45818e')
draw_box(0.15, 0.14, 0.32, 0.15, '16-Node Multi-Tier\nMicroservice Mesh (ip netns)', '#e6b8af', '#a64d79')

# Connective arrows
arrow_props = dict(arrowstyle="->", lw=1.5, color='#333333', zorder=5)
ax.annotate('', xy=(0.38, 0.71), xytext=(0.26, 0.71), arrowprops=arrow_props)
ax.annotate('', xy=(0.72, 0.77), xytext=(0.60, 0.71), arrowprops=arrow_props)
ax.annotate('', xy=(0.72, 0.61), xytext=(0.60, 0.71), arrowprops=arrow_props)
ax.annotate('', xy=(0.27, 0.60), xytext=(0.40, 0.65), arrowprops=arrow_props)
ax.annotate('', xy=(0.57, 0.60), xytext=(0.52, 0.65), arrowprops=arrow_props)

# Cross boundaries
ax.annotate('', xy=(0.75, 0.29), xytext=(0.57, 0.50), arrowprops=dict(arrowstyle="->", lw=1.5, color='#674ea7', zorder=5))
ax.text(0.68, 0.40, 'Telemetry', fontsize=8, color='#674ea7', fontweight='bold')

ax.annotate('', xy=(0.27, 0.50), xytext=(0.65, 0.29), arrowprops=dict(arrowstyle="->", lw=1.5, color='#cc0000', linestyle='--', zorder=5))
ax.text(0.42, 0.43, 'Atomic Mutation', fontsize=8, color='#cc0000', fontweight='bold')

plt.tight_layout()
plt.savefig('/home/daemon_targaryen/kernel-isolation-engine/paper/figures/fig1_architecture.png', bbox_inches='tight', dpi=300)
plt.close()

# 2. Fig 2: CPU Bar Chart
fig, ax = plt.subplots(figsize=(4.5, 3.2), dpi=300)
labels = ['Baseline', 'iptables', 'eBPF/XDP']
total_cpu = [2.5, 77.5, 67.7]
softirq_cpu = [0.1, 95.7, 65.8]

x = np.arange(len(labels))
width = 0.32

rects1 = ax.bar(x - width/2, total_cpu, width, label='Total CPU', color='#4a86e8', edgecolor='#1c4587', linewidth=1)
rects2 = ax.bar(x + width/2, softirq_cpu, width, label='Softirq CPU', color='#e06666', edgecolor='#b82525', linewidth=1)

ax.set_ylabel('CPU Utilization (%)', fontsize=10, fontweight='bold')
ax.set_title('Host CPU & Softirq Load During Volumetric Attack', fontsize=10, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(labels, fontsize=9, fontweight='bold')
ax.set_ylim(0, 115)
ax.grid(axis='y', linestyle=':', alpha=0.6)
ax.legend(loc='upper left', fontsize=8)

for bar in rects1:
    h = bar.get_height()
    ax.annotate(f'{h:.1f}%', xy=(bar.get_x() + bar.get_width() / 2, h),
                xytext=(0, 2), textcoords="offset points", ha='center', va='bottom', fontsize=7.5, fontweight='bold')
for bar in rects2:
    h = bar.get_height()
    ax.annotate(f'{h:.1f}%', xy=(bar.get_x() + bar.get_width() / 2, h),
                xytext=(0, 2), textcoords="offset points", ha='center', va='bottom', fontsize=7.5, fontweight='bold')

plt.tight_layout()
plt.savefig('/home/daemon_targaryen/kernel-isolation-engine/paper/figures/fig2_cpu.png', bbox_inches='tight', dpi=300)
plt.close()

# 3. Fig 3: Latency Comparison
fig, ax = plt.subplots(figsize=(4.5, 3.2), dpi=300)
metrics = ['Mean', 'Median (P50)', '95th % (P95)']
iptables_lat = [3311.39, 3097.26, 5000.57]
ebpf_lat = [1.32, 1.16, 1.73]

x = np.arange(len(metrics))
width = 0.35

rects1 = ax.bar(x - width/2, iptables_lat, width, label='Linux iptables', color='#e06666', edgecolor='#b82525', linewidth=1)
rects2 = ax.bar(x + width/2, ebpf_lat, width, label='eBPF/XDP Datapath', color='#6aa84f', edgecolor='#274e13', linewidth=1)

ax.set_ylabel('Mutation Latency (µs)', fontsize=10, fontweight='bold')
ax.set_title('Policy Mutation Latency (T_mutate) Benchmark', fontsize=10, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(metrics, fontsize=9, fontweight='bold')
ax.set_ylim(0, 5800)
ax.grid(axis='y', linestyle=':', alpha=0.6)
ax.legend(loc='upper left', fontsize=8)

for bar in rects1:
    h = bar.get_height()
    ax.annotate(f'{h:.0f} µs', xy=(bar.get_x() + bar.get_width() / 2, h),
                xytext=(0, 2), textcoords="offset points", ha='center', va='bottom', fontsize=7.5, fontweight='bold')
for bar in rects2:
    h = bar.get_height()
    ax.annotate(f'{h:.2f} µs\n(2508×)', xy=(bar.get_x() + bar.get_width() / 2, h),
                xytext=(0, 4), textcoords="offset points", ha='center', va='bottom', fontsize=7, fontweight='bold', color='#274e13')

plt.tight_layout()
plt.savefig('/home/daemon_targaryen/kernel-isolation-engine/paper/figures/fig3_latency.png', bbox_inches='tight', dpi=300)
plt.close()

# 4. Fig 4: Hysteresis Curve
fig, ax = plt.subplots(figsize=(4.5, 3.2), dpi=300)
cycles = ['k=1', 'k=2', 'k=3', 'k=4', 'k=5']
recovery_time = [11.67, 23.33, 46.67, 93.33, 186.67]

ax.plot(cycles, recovery_time, marker='o', color='#3d85c6', linewidth=2.2, markersize=6, label='T_recovery(k) = 11.67 * 2^(k-1)')
ax.set_ylabel('Quiescent Recovery Duration (seconds)', fontsize=10, fontweight='bold')
ax.set_xlabel('Violation Cycle (k)', fontsize=10, fontweight='bold')
ax.set_title('Anti-Flapping Hysteresis Escalation Trajectory', fontsize=10, fontweight='bold')
ax.set_ylim(0, 210)
ax.grid(True, linestyle=':', alpha=0.6)
ax.legend(loc='upper left', fontsize=8)

for i, (c, r) in enumerate(zip(cycles, recovery_time)):
    escalation = f"({2**i}×)" if i > 0 else "(1×)"
    ax.annotate(f'{r:.1f}s\n{escalation}', xy=(c, r), xytext=(0, 6), textcoords="offset points",
                ha='center', va='bottom', fontsize=7.5, fontweight='bold', color='#0b5394')

plt.tight_layout()
plt.savefig('/home/daemon_targaryen/kernel-isolation-engine/paper/figures/fig4_hysteresis.png', bbox_inches='tight', dpi=300)
plt.close()

print("[✓] Generated high-resolution publication figures in paper/figures/")
