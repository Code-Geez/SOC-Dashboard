# Enterprise Blue-Team SOC & SOAR Platform

A lightweight, highly visual Python/Flask-based Security Operations Center (SOC) and Security Orchestration, Automation, and Response (SOAR) dashboard. It features multi-stage attack correlation, MITRE ATT&CK mapping, PCAP inspection, and live OS kernel hooking via `journalctl`.

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Flask](https://img.shields.io/badge/Framework-Flask-red)

---

## Features

- **Global Threat Radar** — Visualizes incoming attacks on a live map using Leaflet.js
- **Attack-Chain Correlation** — Groups individual alerts into structured Incidents based on the Cyber Kill Chain
- **SOAR Playbook Automation** — Simulates automated incident containment (Firewall blocks, EDR isolation) via an animated terminal
- **Live OS Integration** — Hooks into Linux `journalctl` to detect real-world `su`, `sudo`, and `ssh` brute-force attacks
- **MITRE ATT&CK Matrix** — Dynamic heatmap that lights up based on active threat techniques (T1110, T1059, etc.)
- **PCAP / Hex Dump Inspection** — Allows analysts to perform deep-packet inspection on malicious payloads

---

## Project Structure

```
SOC-Dashboard/
├── requirements.txt         # Python dependencies
├── attack_simulator.py      # Generates background noise and APT attack chains
├── app.py                   # Flask backend, correlation engine, and OS hook
├── static/
│   ├── css/style.css        # Dark-mode SOC UI styling
│   └── js/dashboard.js      # Frontend logic, Leaflet map, and AJAX polling
└── templates/
    └── index.html           # Main dashboard UI
```

A `simulated_logs.txt` file is auto-created in the project root when the attack simulator runs.

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/SOC-Dashboard.git
cd SOC-Dashboard
pip install -r requirements.txt
```

---

## How to Run

The platform can run in two modes:

### 1. Simulator Mode (default)

**Terminal 1 — Attack Simulator:**
```bash
python3 attack_simulator.py
```

**Terminal 2 — SOC Backend:**
```bash
python3 app.py
```

Access the dashboard at **http://127.0.0.1:5000**

### 2. Live OS Mode

The backend hooks into Linux kernel auth logs via `journalctl`. Run as root to enable live detection:

```bash
sudo python3 app.py
```

Then toggle the switch in the dashboard to **LIVE KALI OS MODE**.

---

## Usage

1. Open the dashboard. Background reconnaissance traffic appears on the Global Map.
2. Click **Launch Simulation** to trigger a multi-stage attack chain.
3. Watch the MITRE Matrix light up and incidents appear in the SOAR Playbooks tab.
4. Click **Execute Automated Playbook** on any incident to simulate containment.
5. Toggle to **LIVE KALI OS MODE** and attempt a failed `su` or `sudo` on the host machine to see real-time alerts.

---

## Dependencies

- Flask 3.0+
- Werkzeug 3.0+

---

*Created for educational, portfolio, and blue-team training purposes.*
