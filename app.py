from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from functools import wraps
import os, re, time, threading, subprocess, json, urllib.request, sqlite3
from datetime import datetime
from dotenv import load_dotenv

# --- LOAD SECRETS ---
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback-secret-key-if-missing")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")

# --- FILE PATHS & STATE ---
SIMULATED_LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'simulated_logs.txt')
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'codegeez_soar.db')

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

# --- DATABASE ENGINE (SQLITE) ---
db_lock = threading.Lock()

def init_db():
    with db_lock:
        with sqlite3.connect(DB_FILE, timeout=10) as conn:
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, json_data TEXT)')
            c.execute('CREATE TABLE IF NOT EXISTS incidents (ip TEXT PRIMARY KEY, json_data TEXT)')
            c.execute('CREATE TABLE IF NOT EXISTS endpoints (host TEXT PRIMARY KEY, state TEXT)')
            conn.commit()

def load_db():
    global alerts, incidents, endpoints_state, incident_counter
    try:
        with db_lock:
            with sqlite3.connect(DB_FILE, timeout=10) as conn:
                c = conn.cursor()
                
                c.execute('SELECT json_data FROM alerts ORDER BY id ASC')
                for row in c.fetchall(): alerts.insert(0, json.loads(row[0]))
                    
                c.execute('SELECT ip, json_data FROM incidents')
                for row in c.fetchall():
                    ip, data = row[0], json.loads(row[1])
                    data['stages'] = set(data['stages'])
                    data['mitre_ids'] = set(data['mitre_ids'])
                    incidents[ip] = data
                    
                c.execute('SELECT host, state FROM endpoints')
                for row in c.fetchall(): endpoints_state[row[0]] = row[1]

                if incidents:
                    max_id = max([int(inc['id'].split('-')[1]) for inc in incidents.values()])
                    incident_counter = max_id + 1
    except Exception as e: print(f"[*] Starting fresh database. ({e})")

def save_alert_db(alert):
    with db_lock:
        with sqlite3.connect(DB_FILE, timeout=10) as conn:
            conn.cursor().execute('INSERT OR REPLACE INTO alerts (id, json_data) VALUES (?, ?)', (alert['id'], json.dumps(alert)))

def save_incident_db(ip, inc):
    inc_copy = inc.copy()
    inc_copy['stages'] = list(inc['stages'])
    inc_copy['mitre_ids'] = list(inc['mitre_ids'])
    with db_lock:
        with sqlite3.connect(DB_FILE, timeout=10) as conn:
            conn.cursor().execute('INSERT OR REPLACE INTO incidents (ip, json_data) VALUES (?, ?)', (ip, json.dumps(inc_copy)))

def save_endpoint_db(host, state):
    with db_lock:
        with sqlite3.connect(DB_FILE, timeout=10) as conn:
            conn.cursor().execute('INSERT OR REPLACE INTO endpoints (host, state) VALUES (?, ?)', (host, state))

def clear_db():
    with db_lock:
        with sqlite3.connect(DB_FILE, timeout=10) as conn:
            conn.cursor().execute('DELETE FROM alerts')
            conn.cursor().execute('DELETE FROM incidents')
            conn.commit()

# --- AUTHENTICATION DECORATOR ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- AUTH ROUTES ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('username') == 'admin' and request.form.get('password') == 'codegeez2026':
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid Operator ID or Passcode.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

# --- CORE LOGIC ---
def send_discord_alert(inc_id, ip, target, threat_type):
    if not DISCORD_WEBHOOK_URL: return
    data = {"content": f"🚨 **CRITICAL INCIDENT DETECTED: {inc_id}** 🚨", "embeds":[{"title": threat_type, "color": 16711680, "fields":[{"name": "Attacker IP", "value": ip, "inline": True}, {"name": "Target Host", "value": target, "inline": True}, {"name": "Status", "value": "Awaiting SOAR Playbook Execution", "inline": False}], "footer": {"text": "Code Ge'ez SOAR Platform"}}]}
    try: urllib.request.urlopen(urllib.request.Request(DISCORD_WEBHOOK_URL, data=json.dumps(data).encode(), headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}, method='POST'), timeout=3)
    except Exception as e: print(f"[!] Discord Webhook Failed: {e}")

def generate_hex_dump(payload_str):
    raw_bytes = payload_str.encode('utf-8')
    return "".join(f"{i:08X}  {' '.join(f'{b:02X}' for b in raw_bytes[i:i+16]):<48}  |{''.join(chr(b) if 32 <= b <= 126 else '.' for b in raw_bytes[i:i+16])}|\n" for i in range(0, len(raw_bytes), 16))

def register_alert(timestamp, threat_type, severity, ip, host, raw_action):
    global incident_counter
    meta = KILL_CHAIN.get(threat_type, {"stage": "Unknown", "mitre": "Unknown"})
    alert = {"id": f"ALT-{len(alerts)+1}", "timestamp": timestamp, "type": threat_type, "severity": severity, "ip": ip, "host": host, "stage": meta['stage'], "mitre": meta['mitre'], "geo": GEO_DB.get(ip, {"lat": 0, "lng": 0, "country": "Unknown"}), "pcap": generate_hex_dump(f"IP {ip} > {host} : {raw_action}"), "raw": raw_action}
    
    alerts.insert(0, alert)
    save_alert_db(alert)
    
    if host in endpoints_state and severity in ["HIGH", "CRITICAL"]: 
        endpoints_state[host] = "Compromised"
        save_endpoint_db(host, "Compromised")

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

    save_incident_db(ip, inc)

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
    
    threat_type, severity = "", "LOW"
    if "su:" in line_lower or "sudo:" in line_lower or "su[" in line_lower:
        if "authentication failure" in line_lower or "incorrect password" in line_lower or "failed" in line_lower:
            threat_type, severity = "Failed Privilege Escalation", "CRITICAL"
    elif "sshd" in line_lower or "ssh" in line_lower:
        if "failed password" in line_lower or "authentication failure" in line_lower:
            threat_type, severity = "SSH Brute Force Detected", "HIGH"
    
    if threat_type: register_alert(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), threat_type, severity, ip, "KALI-LOCAL", line.strip())

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

# --- PROTECTED ROUTES ---
@app.route('/')
@login_required
def index(): return render_template('index.html')

@app.route('/api/toggle_mode', methods=['POST'])
@login_required
def toggle_mode():
    global MODE, alerts, incidents, endpoints_state
    MODE = request.json.get('mode', 'SIMULATED')
    alerts.clear()
    incidents.clear()
    endpoints_state = {k: "Clean" for k in endpoints_state}
    clear_db()
    return jsonify({"status": "success", "mode": MODE})

@app.route('/api/vt/<ip>')
@login_required
def get_virustotal(ip):
    if not VT_API_KEY or ip == "127.0.0.1" or ip.startswith("192.168.") or ip.startswith("10."):
        malicious = 68 if ip in["185.15.59.222", "198.51.100.23", "203.0.113.44"] else 0
        return jsonify({"stats": {"malicious": malicious, "harmless": 20, "suspicious": 2, "undetected": 4}, "network": "Simulated ISP Network", "country": GEO_DB.get(ip, {}).get("country", "Unknown")})
    try:
        data = json.loads(urllib.request.urlopen(urllib.request.Request(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={'x-apikey': VT_API_KEY}), timeout=5).read().decode('utf-8'))
        return jsonify({"stats": data['data']['attributes']['last_analysis_stats'], "network": data['data']['attributes'].get('network', 'Unknown Network'), "country": data['data']['attributes'].get('country', 'Unknown')})
    except Exception as e: return jsonify({"error": str(e), "stats": {"malicious": 0, "harmless": 0}})

@app.route('/api/data')
@login_required
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
@login_required
def incident_action(ip):
    action = request.json.get('action')
    if ip in incidents and action == "RESOLVE":
        incidents[ip]['status'] = "RESOLVED"
        save_incident_db(ip, incidents[ip])
        if not any(i['target'] == incidents[ip]['target'] and i['status'] != 'RESOLVED' for i in incidents.values()):
            endpoints_state[incidents[ip]['target']] = "Clean"
            save_endpoint_db(incidents[ip]['target'], "Clean")
    return jsonify({"success": True})

@app.route('/api/demo_attack')
@login_required
def trigger_demo():
    if MODE == "LIVE": return jsonify({"status": "Disabled in LIVE mode"})
    def execute_chain():
        chain =["Connection refused on port 3389", "Failed password for admin from 185.15.59.222 port 22", "Executed: powershell.exe -enc SQBFAFgA", "sudo: 3 incorrect password attempts"]
        with open(SIMULATED_LOG_FILE, 'a') as f:
            for act in chain:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}][WARN][185.15.59.222] [WIN-DC01] {act}\n")
                time.sleep(1)
    threading.Thread(target=execute_chain).start()
    return jsonify({"status": "Launched"})

if __name__ == '__main__':
    init_db()
    load_db()
    threading.Thread(target=tail_journalctl, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=False)
