# 🛡️ CyberAegis-Wifi: Advanced Wireless Auditor

**CyberAegis-Wifi** is a professional-grade security tool designed for **SOC (Security Operations Center)** analysts and researchers to audit Wi-Fi network resilience.



## 🌟 Key Features
* **MFP Detection:** Checks if the target AP supports 802.11w (Management Frame Protection).
* **Forensic Logging:** Automatically generates `cyberaegis_audit.log` for post-attack analysis.
* **Real-time Monitoring:** Sniffs and identifies hidden SSIDs and client-AP relationships.

## 🛠️ How to Use
1. **Enable Monitor Mode:** `sudo airmon-ng start wlan0`
2. **Run Auditor:** ```bash
   sudo python3 main.py -i wlan0mon
