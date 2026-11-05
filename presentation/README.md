# Capstone Viva Defense Presentation Package
## Kernel-Level Zero-Trust Network Traffic Isolation Engine (eBPF/XDP)

Welcome to the **Academic Presentation & Viva Voce Defense Package**. This directory contains the complete slide deck, speaker scripts, architectural diagrams, and oral delivery guides prepared specifically for the final-year capstone engineering defense.

---

## 📁 Presentation Assets Directory

| File | Purpose | Audience / Use Case |
| :--- | :--- | :--- |
| [`CAPSTONE_VIVA_SLIDES.md`](file:///home/daemon_targaryen/kernel-isolation-engine/presentation/CAPSTONE_VIVA_SLIDES.md) | **Master 20-Slide Presentation Document** containing slide layouts, LaTeX equations, ASCII diagrams, word-for-word speaker notes, key takeaways, and anticipated faculty traps. | Reading, reviewing, and offline study before viva day. |
| [`interactive_slides.html`](file:///home/daemon_targaryen/kernel-isolation-engine/presentation/interactive_slides.html) | **Obsidian Dark-Mode Interactive HTML Presentation Deck** with keyboard navigation, live progress bar, toggleable speaker notes drawer, and print-to-PDF support. | Live projection on projector/screen during oral defense. |
| [`ELEVATOR_PITCHES.md`](file:///home/daemon_targaryen/kernel-isolation-engine/presentation/ELEVATOR_PITCHES.md) | **Oral Delivery Scripts**: 10-second hook, 30-second pitch, 60-second defense opener, 3-minute technical walkthrough, and 5 examiner persona strategies. | Memorizing punchlines and verbal introductions. |

---

## 🎮 How to Run the Interactive Presentation Deck

To launch the presentation deck on your screen or projector:

### Method 1: Direct Browser Launch
Open the file directly in Firefox, Chrome, or Chromium:

```bash
firefox presentation/interactive_slides.html &
# OR
google-chrome presentation/interactive_slides.html &
```

### Method 2: Served via Python HTTP Server
```bash
python3 -m http.server 9000 --directory presentation
# Open browser at: http://localhost:9000/interactive_slides.html
```

---

## ⌨️ Presentation Keyboard Shortcuts

| Key | Action |
| :---: | :--- |
| `▶` (Right Arrow) / `Space` / `Page Down` | Advance to **Next Slide** |
| `◀` (Left Arrow) / `Page Up` | Return to **Previous Slide** |
| `S` | **Toggle Speaker Notes Drawer** (Slide up/down word-for-word delivery script) |
| `F` | **Toggle Fullscreen Mode** (F11 presentation view) |
| `Home` | Jump to **Slide 1 (Title Slide)** |
| `End` | Jump to **Slide 20 (Viva Voce Q&A Directory)** |

---

## 🖨️ How to Export to PDF Handout
The interactive deck includes a print stylesheet (`@media print`):
1. Open `interactive_slides.html` in Firefox or Chrome.
2. Press `Ctrl + P` (Print).
3. Set **Destination** to `Save as PDF`.
4. Ensure **Background Graphics** is checked.
5. Click **Save** — this generates a clean multi-page slide handout for examiners!

---

## 🎯 4-Step Live Defense Demonstration Protocol
During your defense, after presenting Slide 17/18, switch to your live terminal to blow the committee away:

1. **Terminal 1**: Show the 16 running namespaces:
   ```bash
   ip netns list && ip link show br-xdp-v2
   ```
2. **Terminal 2**: Start the Presentation Plane server:
   ```bash
   sudo python3 dashboard/cluster_app.py
   ```
3. **Browser**: Open `http://localhost:8000` to show the 60 FPS Canvas particle visualizer and live trust gauges.
4. **Trigger Attack & Instant Neutralization**:
   - In UI, click **Volumetric SYN Flood** $\rightarrow$ Watch trust score decay to 0.0%, state badge switch to `QUARANTINED [DROP]`, and $T_{\text{isolate}} < 30\,\mu\text{s}$.
   - Click **Emergency Neutralize** $\rightarrow$ Watch process-group `killpg` terminate the flood and restore baseline in microseconds.

