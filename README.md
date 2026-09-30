Markdown
# Container Runtime Anomaly Detector & Active Remediation (CRAD)

A lightweight container runtime security engine designed to detect and remediate anomalous process execution in real time within containerized environments.

## Overview
In production cloud environments, scanning container images prior to deployment (static security) is insufficient to prevent zero-day exploits, runtime misconfigurations, or dynamic remote code execution (RCE). 

**CRAD** continuously monitors running containers for anomalous process execution, enforces security baselines, triggers immediate active remediation (terminating unauthorized processes via `SIGKILL`), and generates structured JSON audit trails for SIEM ingestion.

## Key Features
* **Real-time Runtime Monitoring:** Continuously tracks process execution inside target containers via the Docker Engine API.
* **Threat Detection Engine:** Flags unauthorized utilities and interactive shells (`bash`, `sh`, `curl`, `wget`, `nc`, `nmap`) executed inside single-purpose workloads (e.g., web servers).
* **Automated Active Remediation:** Immediately kills malicious processes (`SIGKILL`) without terminating the entire host container, preventing denial-of-service to legitimate traffic.
* **Audit & SIEM Integration:** Logs structured alerts in JSON format containing timestamp, container ID, PID, executed command, severity, and remediation status.

## Architecture & Threat Scenario

+----------------------------------------------------+
| Compromised Container (e.g. Nginx Web Server)      |
| -> Attacker spawns interactive Shell (/bin/bash)   |
+----------------------------------------------------+
|
v (Process Inspection)
+----------------------------------------------------+
| CRAD Engine (Python / Docker API)                  |
| 1. Detects violation against Baseline Policy       |
| 2. Issues SIGKILL to malicious PID                |
| 3. Writes alert to alerts.json                     |
+----------------------------------------------------+

<img width="1294" height="579" alt="image" src="https://github.com/user-attachments/assets/0f16854f-cecb-4ade-a476-d265ad378095" />



## Quick Start

### 1. Prerequisites
* Docker Desktop running on Linux/WSL2/Windows.
* Python 3.8+

### 2. Setup & Installation
Clone the repository and install dependencies:
```bash
git clone [https://github.com/](https://github.com/)<YOUR-USERNAME>/container-runtime-security.git
cd container-runtime-security
pip install -r requirements.txt
3. Run Target Container
Deploy a sample web server container:

Bash
docker run -d --name web-target -p 8080:80 nginx
4. Start the Detector
Bash
python detector.py
5. Simulate Attack
In a separate terminal, attempt to spawn an interactive shell:

Bash
docker exec -it web-target /bin/bash
The shell session will be immediately terminated by CRAD, and an alert entry will be appended to alerts.json.

Author
Ariel Hemed - https://github.com/arielhemed-spec | www.linkedin.com/in/ariel-hemed-041975292
