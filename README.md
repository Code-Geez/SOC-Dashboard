# 🛡️ Enterprise Blue-Team SOC & SOAR Platform

A lightweight, highly visual Python/Flask-based Security Operations Center (SOC) and Security Orchestration, Automation, and Response (SOAR) dashboard. 

This project simulates an enterprise-grade blue-team environment. It features multi-stage attack correlation, MITRE ATT&CK mapping, PCAP inspection, and **Live OS Kernel Hooking** to detect real-time attacks on a Kali Linux host.

![SOC Dashboard](https://img.shields.io/badge/Status-Active-success)
![Python](https://img.shields.io/badge/Python-3.x-blue)
![Flask](https://img.shields.io/badge/Framework-Flask-red)

---

## ✨ Key Features

* 🌍 **Global Threat Radar:** Visualizes incoming attacks on a live map using Leaflet.js.
* 🔗 **Attack-Chain Correlation:** Groups individual alerts into structured Incidents based on the Cyber Kill Chain.
* 🤖 **SOAR Playbook Automation:** Simulates automated incident containment (Firewall blocks, EDR isolation) via an animated terminal.
* 💻 **Live OS Integration (Kali Linux):** Hooks directly into Linux `journalctl` to detect real-world `su`, `sudo`, and `ssh` brute-force attacks against your local machine.
* 📊 **MITRE ATT&CK Matrix:** A dynamic heatmap that lights up based on active threat techniques (T1110, T1059, etc.).
* 🔬 **PCAP / Hex Dump Inspection:** Allows analysts to perform deep-packet inspection on malicious payloads.

---

## 📂 Project Structure
```text
soc_dashboard/
├── requirements.txt         # Python dependencies
├── attack_simulator.py      # Generates background noise and APT attack chains
├── app.py                   # The Flask Backend, Correlation Engine, and OS Hooker
├── static/
│   ├── css/style.css        # Dark-mode SOC UI styling
│   └── js/dashboard.js      # Frontend logic, Leaflet map, and AJAX polling
└── templates/
    └── index.html           # Main dashboard UI

🚀 Installation & Setup

1. Clone the repository:
code Bash

git clone https://github.com/YOUR_USERNAME/soc_dashboard.git
cd soc_dashboard

2. Install dependencies:
code Bash

pip install -r requirements.txt

🎮 How to Run

Because the platform hooks into the Linux kernel to monitor local authentication logs, the backend must be run as root.

Terminal 1 (The Attack Simulator):
code Bash

python3 attack_simulator.py

Terminal 2 (The SOC Backend):
code Bash

sudo python3 app.py

Access the Dashboard:
Open your web browser and navigate to http://127.0.0.1:5000
🎯 Demonstration Guide
1. Simulator Mode & SOAR Automation

    Open the dashboard. You will see background reconnaissance traffic on the Global Map.

    Click Launch Simulation in the top right.

    Watch the MITRE Matrix light up red.

    Go to the SOAR Playbooks tab, expand the active incident, and click Execute Automated Playbook to watch the containment script run.

2. Live OS Hooking (Hack Yourself!)

    Flip the top toggle switch to LIVE KALI OS MODE. (The dashboard will clear and turn red).

    Open a terminal on your Kali machine and type su root.

    Type the wrong password.

    Look at the dashboard—it instantly intercepts the kernel log and generates a CRITICAL Privilege Escalation alert!

Disclaimer: Created for educational, portfolio, and blue-team training purposes.
