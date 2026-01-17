#!/usr/bin/env python3

import os
import sys
import signal
import logging
import argparse
import threading
from datetime import datetime
from typing import Dict, Generator, List, Union
from collections import defaultdict
import copy

# Scapy core imports
from scapy.layers.dot11 import RadioTap, Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11ReassoResp, Dot11AssoResp, \
    Dot11QoS, Dot11Deauth, Dot11
from scapy.all import *
from time import sleep

# --- SOC AUDIT LOGGING SETUP ---
# Idhu forensics-ku romba mukkiyam. Project-ah professional-ah kaatum.
logging.basicConfig(
    filename='cyberaegis_audit.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# --- TERMINAL BANNER ---
BANNER = """
 ██████╗██╗   ██╗██████╗ ███████╗██████╗  █████╗ ███████╗ ██████╗ ██╗███████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████║█████╗  ██║  ███╗██║███████╗
██║       ╚██╔╝  ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██║   ██║██║╚════██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██║███████╗╚██████╔╝██║███████║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
      >> [ Wireless Resilience Auditor & SOC Forensics Tool ] <<
"""

class CyberAegisAuditor:
    _ABORT = False

    def __init__(self, interface, ssid=None, bssid=None):
        self.interface = interface
        self.target_ssid_name = ssid
        self.target_bssid = bssid
        self.target_mfp = "Scanning..."
        self.found_targets = {}

    def log_audit(self, msg, level="info"):
        """Saves logs for SOC Forensics and displays them"""
        if level == "info":
            logging.info(msg)
            print(f"[*] {msg}")
        else:
            logging.error(msg)
            print(f"[!] {msg}")

    def detect_mfp(self, pkt):
        """ADVANCED: 802.11w Management Frame Protection Detection"""
        if pkt.haslayer(Dot11Beacon):
            rsn = pkt.getlayer(Dot11Elt, ID=48)
            if rsn and len(rsn.info) >= 18:
                # Check MFP bits in RSN Capabilities (Byte 16)
                if (rsn.info[16] & 0x40) or (rsn.info[16] & 0x80):
                    return "PROTECTED (802.11w)"
            return "VULNERABLE (No MFP)"
        return "Unknown"

    def ap_sniff_cb(self, pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore') or "Hidden"
            bssid = pkt.addr3
            mfp_status = self.detect_mfp(pkt)
            
            if bssid not in self.found_targets:
                self.found_targets[bssid] = {'ssid': ssid, 'mfp': mfp_status}
                self.log_audit(f"Discovered: {ssid} [{bssid}] - Security: {mfp_status}")

    def run_audit(self):
        print(f"[*] Starting audit on interface: {self.interface}")
        sniff(iface=self.interface, prn=self.ap_sniff_cb, timeout=10)
        # Add deauth logic here based on discovered targets...

def main():
    print(BANNER)
    if os.geteuid() != 0:
        print("[!] Error: This tool must be run as ROOT.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='CyberAegis Wireless Auditor')
    parser.add_argument('-i', '--interface', required=True, help='Monitor mode interface')
    args = parser.parse_args()

    auditor = CyberAegisAuditor(args.interface)
    auditor.run_audit()

if __name__ == "__main__":
    main()
