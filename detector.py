import docker
import time
import json
from datetime import datetime

# הגדרת פקודות חשודות
SUSPICIOUS_COMMANDS = ['bash', 'sh', 'curl', 'wget', 'nc', 'nmap']
LOG_FILE = "alerts.json"

def log_alert(alert_data):
    """רישום ההתראה לקובץ JSON מובנה"""
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(alert_data) + "\n")

def monitor_container(container_name="web-target", auto_kill=True):
    client = docker.from_env()
    
    try:
        container = client.containers.get(container_name)
    except docker.errors.NotFound:
        print(f"[-] Container '{container_name}' not found. Make sure it is running.")
        return

    print(f"[*] Starting Runtime Security & Remediation Engine for: {container_name}")
    print(f"[*] Monitored Commands: {SUSPICIOUS_COMMANDS}")
    print(f"[*] Active Remediation (Auto-Kill): {'ENABLED' if auto_kill else 'DISABLED'}")
    print("-" * 70)

    seen_pids = set()

    while True:
        try:
            top_info = container.top()
            processes = top_info['Processes']
            titles = top_info['Titles']
            
            cmd_index = titles.index('CMD')
            pid_index = titles.index('PID')

            for proc in processes:
                pid = proc[pid_index]
                cmd = proc[cmd_index]

                if pid not in seen_pids:
                    seen_pids.add(pid)

                    for suspicious in SUSPICIOUS_COMMANDS:
                        if suspicious in cmd:
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            
                            alert = {
                                "timestamp": timestamp,
                                "container_id": container.short_id,
                                "container_name": container_name,
                                "process_id": pid,
                                "command": cmd,
                                "threat_type": "Unauthorized Interactive/Utility Execution",
                                "severity": "CRITICAL",
                                "action_taken": "NONE"
                            }

                            print(f"\n[ALERT - THREAT DETECTED] [{timestamp}]")
                            print(f"  Container: {container_name} ({container.short_id})")
                            print(f"  PID: {pid} | CMD: {cmd}")
                            print(f"  Severity: CRITICAL")

                            # מנגנון תגובה אקטיבי - הריגת התהליך הזדוני בלבד
                            if auto_kill:
                                try:
                                    kill_res = container.exec_run(f"kill -9 {pid}")
                                    alert["action_taken"] = "PROCESS_TERMINATED"
                                    print(f"  [REMEDIATION] Terminated PID {pid} via SIGKILL.")
                                except Exception as err:
                                    alert["action_taken"] = f"FAILED_TO_KILL: {err}"
                                    print(f"  [REMEDIATION FAILED] {err}")

                            log_alert(alert)
                            print(f"  [AUDIT] Logged alert to {LOG_FILE}")
                            print("-" * 70)

            time.sleep(1)

        except docker.errors.APIError as e:
            print(f"[-] Container error or stopped: {e}")
            break
        except KeyboardInterrupt:
            print("\n[*] Stopping monitor.")
            break

if __name__ == "__main__":
    monitor_container(auto_kill=True)