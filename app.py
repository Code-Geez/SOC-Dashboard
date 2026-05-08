from flask import Flask, render_template, jsonify, request
import os, re, time, threading, subprocess, json, urllib.request
from datetime import datetime

app = Flask(__name__)

DISCORD_WEBHOOK_URL = ""
VT_API_KEY = ""

SIMULATED_LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'simulated_logs.txt')
MODE = "SIMULATED"
alerts =[]
incidents = {}
endpoints_state = {"WIN-DC01": "Clean", "HR-LAPTOP": "Clean", "FINANCE-PC": "Clean", "WEB-SERVER-01": "Clean", "DB-PROD-01": "Clean", "KALI-LOCAL": "Clean"}
last_sim_pos = 0
incident_counter = 1

GEO_DB = {
    "185.15.59.222": {"lat": 55.7558, "lng": 37.6173, "country": "Russia"},
    "198.51.100.23": {"lat": 39.9042, "lng": 116.4074, "country": "China"},
    "203.0.113.44":  {"lat": 39.0742, "lng": 125.7625, "country": "North Korea"},
    "8.8.8.8":       {"lat": 37.7749, "lng": -122.4194, "country": "US"},
    "127.0.0.1":     {"lat": 38.8951, "lng": -77.0364, "country": "Localhost"}
}

KILL_CHAIN = {
    "Port Scan Behavior": {"stage": "Reconnaissance", "mitre": "T1046"},
    "SSH Brute Force Detected": {"stage": "Initial Access", "mitre": "T1110"},
    "Suspicious PowerShell Command": {"stage": "Execution", "mitre": "T1059"},
    "Reverse Shell Indicator": {"stage": "Execution", "mitre": "T1059"},
    "Registry Run Key Modified": {"stage": "Persistence", "mitre": "T1547"},
    "Failed Privilege Escalation": {"stage": "Privilege Escalation", "mitre": "T1068"}
}

def send_discord_alert(inc_id, ip, target, threat_type):
    if not DISCORD_WEBHOOK_URL: return
    data = {
        "content": f"🚨 **CRITICAL INCIDENT DETECTED: {inc_id}** 🚨",
        "embeds":[{
            "title": threat_type, "color": 16711680,
            "fields":[
                {"name": "Attacker IP", "value": ip, "inline": True},
                {"name": "Target Host", "value": target, "inline": True},
                {"name": "Status", "value": "Awaiting SOAR Playbook Execution", "inline": False}
            ],
            "footer": {"text": "Nexus SOAR Platform"}
        }]
    }
    try:
        req = urllib.request.Request(DISCORD_WEBHOOK_URL, data=json.dumps(data).encode(), headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}, method='POST')
        urllib.request.urlopen(req, timeout=3)
    except Exception as e: print(f"[!] Discord Webhook Failed: {e}")

def generate_hex_dump(payload_str):
    raw_bytes = payload_str.encode('utf-8')
    hex_dump = ""
    for i in range(0, len(raw_bytes), 16):
        chunk = raw_bytes[i:i+16]
        hex_dump += f"{i:08X}  {' '.join(f'{b:02X}' for b in chunk):<48}  |{''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)}|\n"
    return hex_dump

def register_alert(timestamp, threat_type, severity, ip, host, raw_action):
    global incident_counter
    meta = KILL_CHAIN.get(threat_type, {"stage": "Unknown", "mitre": "Unknown"})
    geo = GEO_DB.get(ip, {"lat": 0, "lng": 0, "country": "Unknown"})
    pcap = generate_hex_dump(f"IP {ip} > {host} : {raw_action}")

    alert = {"id": f"ALT-{len(alerts)+1}", "timestamp": timestamp, "type": threat_type, "severity": severity, "ip": ip, "host": host, "stage": meta['stage'], "mitre": meta['mitre'], "geo": geo, "pcap": pcap, "raw": raw_action}
    alerts.insert(0, alert)
    
    if host in endpoints_state and severity in ["HIGH", "CRITICAL"]: endpoints_state[host] = "Compromised"

    if ip not in incidents or incidents[ip]['status'] == 'RESOLVED':
        incidents[ip] = {"id": f"INC-{incident_counter:04d}", "ip": ip, "target": host, "status": "Active", "severity": severity, "confidence": 30, "events":[], "stages": set(), "mitre_ids": set()}
        incident_counter += 1

    inc = incidents[ip]
    inc['events'].insert(0, alert)
    inc['stages'].add(meta['stage'])
    inc['mitre_ids'].add(meta['mitre'])
    inc['confidence'] = min(100, inc['confidence'] + 15)
    
    is_new_critical = False
    if len(inc['stages']) >= 3:
        if inc['severity'] != "CRITICAL": is_new_critical = True
        inc['severity'] = "CRITICAL"
        inc['type'] = "MULTI-STAGE ATTACK DETECTED"
    else:
        if severity in ["HIGH", "CRITICAL"]: 
            if inc['severity'] != severity and severity == "CRITICAL": is_new_critical = True
            inc['severity'] = severity
        inc['type'] = threat_type

    if is_new_critical: send_discord_alert(inc['id'], ip, host, inc['type'])
    if len(alerts) > 200: alerts.pop()

def analyze_sim_log(line):
    match = re.search(r'\[(.*?)\] \[(.*?)\] \[(.*?)\] \[(.*?)\] (.*)', line)
    if not match: return
    timestamp, level, ip, host, action = match.groups()
    if level == "INFO": return
    
    threat_type, severity = "", "LOW"
    if "Connection refused" in action: threat_type, severity = "Port Scan Behavior", "LOW"
    elif "Failed password" in action: threat_type, severity = "SSH Brute Force Detected", "HIGH"
    elif "powershell.exe" in action: threat_type, severity = "Suspicious PowerShell Command", "HIGH"
    elif "/dev/tcp/" in action: threat_type, severity = "Reverse Shell Indicator", "CRITICAL"
    elif "Registry modified" in action: threat_type, severity = "Registry Run Key Modified", "HIGH"
    elif "sudo: 3 incorrect" in action: threat_type, severity = "Failed Privilege Escalation", "CRITICAL"

    if threat_type: register_alert(timestamp, threat_type, severity, ip, host, action)

def analyze_live_log(line):
    line_lower = line.lower()
    ip_match = re.search(r'[0-9]+(?:\.[0-9]+){3}', line)
    ip = ip_match.group(0) if ip_match else "127.0.0.1"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    threat_type, severity = "", "LOW"
    if "su:" in line_lower or "sudo:" in line_lower or "su[" in line_lower:
        if "authentication failure" in line_lower or "incorrect password" in line_lower or "failed" in line_lower:
            threat_type, severity = "Failed Privilege Escalation", "CRITICAL"
    elif "sshd" in line_lower or "ssh" in line_lower:
        if "failed password" in line_lower or "authentication failure" in line_lower:
            threat_type, severity = "SSH Brute Force Detected", "HIGH"
    
    if threat_type: register_alert(timestamp, threat_type, severity, ip, "KALI-LOCAL", line.strip())

def tail_journalctl():
    try:
        proc = subprocess.Popen(['journalctl', '-f', '-n', '0'], stdout=subprocess.PIPE, text=True)
        for line in iter(proc.stdout.readline, ''):
            if MODE == "LIVE": analyze_live_log(line)
    except Exception as e: print(f"[!] Kernel Hook Error: {e}")

def read_logs():
    global last_sim_pos
    if MODE == "SIMULATED":
        if not os.path.exists(SIMULATED_LOG_FILE): return
        with open(SIMULATED_LOG_FILE, 'r') as f:
            f.seek(0, 2)
            if f.tell() < last_sim_pos: last_sim_pos = 0
            f.seek(last_sim_pos)
            for line in f.readlines(): analyze_sim_log(line)
            last_sim_pos = f.tell()

@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/toggle_mode', methods=['POST'])
def toggle_mode():
    global MODE, alerts, incidents, endpoints_state
    MODE = request.json.get('mode', 'SIMULATED')
    alerts.clear()
    incidents.clear()
    endpoints_state = {k: "Clean" for k in endpoints_state}
    return jsonify({"status": "success", "mode": MODE})

@app.route('/api/vt/<ip>')
def get_virustotal(ip):
    if not VT_API_KEY or ip == "127.0.0.1" or ip.startswith("192.168.") or ip.startswith("10."):
        malicious = 0
        if ip in["185.15.59.222", "198.51.100.23", "203.0.113.44"]: malicious = 68
        return jsonify({"stats": {"malicious": malicious, "harmless": 20, "suspicious": 2, "undetected": 4}, "network": "Simulated ISP Network", "country": GEO_DB.get(ip, {}).get("country", "Unknown")})
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    req = urllib.request.Request(url, headers={'x-apikey': VT_API_KEY})
    try:
        response = urllib.request.urlopen(req, timeout=5)
        data = json.loads(response.read().decode('utf-8'))
        stats = data['data']['attributes']['last_analysis_stats']
        network = data['data']['attributes'].get('network', 'Unknown Network')
        country = data['data']['attributes'].get('country', 'Unknown')
        return jsonify({"stats": stats, "network": network, "country": country})
    except Exception as e:
        return jsonify({"error": str(e), "stats": {"malicious": 0, "harmless": 0}})

@app.route('/api/data')
def get_data():
    read_logs()
    active_incs =[i for i in incidents.values() if i['status'] != 'RESOLVED']
    score = max(0, min(100, 100 - (len(active_incs) * 5) - (sum(1 for i in active_incs if i['severity'] == 'CRITICAL') * 10)))
    
    formatted_incs =[]
    for inc in sorted(incidents.values(), key=lambda x: x['confidence'], reverse=True):
        f_inc = inc.copy()
        f_inc['stages'] = list(inc['stages'])
        f_inc['mitre_ids'] = list(inc['mitre_ids'])
        formatted_incs.append(f_inc)

    return jsonify({"alerts": alerts[:50], "incidents": formatted_incs, "endpoints": endpoints_state, "score": score, "mode": MODE})

@app.route('/api/incident/<ip>/action', methods=['POST'])
def incident_action(ip):
    action = request.json.get('action')
    if ip in incidents and action == "RESOLVE":
        incidents[ip]['status'] = "RESOLVED"
        if not any(i['target'] == incidents[ip]['target'] and i['status'] != 'RESOLVED' for i in incidents.values()):
            endpoints_state[incidents[ip]['target']] = "Clean"
    return jsonify({"success": True})

@app.route('/api/demo_attack')
def trigger_demo():
    if MODE == "LIVE": return jsonify({"status": "Disabled in LIVE mode"})
    def execute_chain():
        ip, host = "185.15.59.222", "WIN-DC01"
        chain =["Connection refused on port 3389", "Failed password for admin from 185.15.59.222 port 22", "Executed: powershell.exe -enc SQBFAFgA", "sudo: 3 incorrect password attempts"]
        with open(SIMULATED_LOG_FILE, 'a') as f:
            for act in chain:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [WARN] [{ip}] [{host}] {act}\n")
                time.sleep(1)
    threading.Thread(target=execute_chain).start()
    return jsonify({"status": "Launched"})

if __name__ == '__main__':
    threading.Thread(target=tail_journalctl, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=False)
