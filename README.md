# 🛡️ CyberAegis-Wifi: Advanced Wireless Auditor & SOC Forensics Tool

**CyberAegis-Wifi** is a specialized security framework developed for **SOC (Security Operations Center)** teams to evaluate wireless network resilience against deauthentication attacks and audit **802.11w (Management Frame Protection)** implementation.



---

## 🌟 Core Functionalities

### 1. 🛡️ MFP (802.11w) Vulnerability Assessment
Detects whether an Access Point (AP) has **Management Frame Protection** enabled. Without MFP, an attacker can easily disconnect any client from the network using forged deauthentication frames.

### 2. 🔍 Real-time Network Intelligence
* **SSID/BSSID Discovery:** Identifies hidden and broadcasted networks.
* **Client-AP Mapping:** Visualizes which devices are connected to which AP.
* **Channel Analysis:** Monitors traffic across the 2.4GHz/5GHz spectrum.

### 3. 📜 Digital Forensics & SOC Logging
Unlike basic scripts, CyberAegis generates a standardized `cyberaegis_audit.log`. This file follows forensic standards, recording timestamps, MAC addresses, and security flags for post-incident investigation.



---

## 🚀 Deployment Guide

### Prerequisites
* **OS:** Kali Linux / Parrot OS
* **Hardware:** Wireless Adapter with Monitor Mode & Packet Injection support.
* **Python:** 3.x with Scapy library.

### Installation & Execution
```bash
# Clone the repository
git clone [https://github.com/s4m-404/CyberAegis-Wifi.git](https://github.com/s4m-404/CyberAegis-Wifi.git)
cd CyberAegis-Wifi

# Install Dependencies
pip3 install -r requirements.txt

# Run the Auditor
sudo python3 main.py -i wlan0mon
---

## 👤 Author & Developer

🏆 Name: `s4m_4o4`  
🛠️ Role: Ethical Hacker & SOC Analyst  
🌐 GitHub: [@s4m-404](https://github.com/s4m-404)

> "Building tools to secure the invisible waves." 🛡️

---

## 📜 Legal Disclaimer
This tool is strictly for **educational purposes** and **authorized security auditing**. Unauthorized use of this tool against networks without prior consent is illegal. The developer (**s4m_4o4**) is not responsible for any misuse.
