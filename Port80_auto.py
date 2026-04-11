#!/usr/bin/env python3

##############################################
## Freeworld - Allergic to aluminum baby   ##
## Port 80 Auto Scanner                    ##
## Usage: python3 scan80.py <IP>           ##
##############################################

import subprocess
import sys
import os
import time

if len(sys.argv) < 2:
    print("Usage: python3 scan80.py <IP>")
    sys.exit(1)

TARGET = sys.argv[1]
OUTPUT_DIR = f"/root/oscp/scans/{TARGET}"
REPORT = f"{OUTPUT_DIR}/port80_report.txt"
WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

def open_terminal(command):
    subprocess.Popen([
        "xterm", "-title", command[:30], "-e",
        f"bash -c '{command}; echo DONE; sleep 5'"
    ])

def append_report(title, filepath):
    with open(REPORT, "a") as r:
        r.write(f"\n{'='*50}\n")
        r.write(f"## {title}\n")
        r.write(f"{'='*50}\n")
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                r.write(f.read())
        else:
            r.write(f"[-] Output file not found: {filepath}\n")

def main():
    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Initialize report
    with open(REPORT, "w") as r:
        r.write(f"{'='*50}\n")
        r.write(f"Port 80 Scan Report\n")
        r.write(f"Target: {TARGET}\n")
        r.write(f"{'='*50}\n")

    print(f"\n[*] Starting Port 80 scans against {TARGET}")
    print(f"[*] Output directory: {OUTPUT_DIR}")
    print(f"[*] Report: {REPORT}\n")

    # WhatWeb fingerprinting — runs first since its quick
    whatweb_out = f"{OUTPUT_DIR}/whatweb_80.txt"
    whatweb_cmd = (
        f"whatweb -a 3 http://{TARGET} "
        f"--log-verbose={whatweb_out}"
    )
    print("[*] Opening WhatWeb terminal...")
    open_terminal(whatweb_cmd)
    time.sleep(2)

    # Nmap deep dive with vuln scripts
    nmap_out = f"{OUTPUT_DIR}/nmap_80.txt"
    nmap_cmd = (
        f"nmap -sC -sV -p 80 --script vuln {TARGET} "
        f"-oN {nmap_out}"
    )
    print("[*] Opening Nmap terminal...")
    open_terminal(nmap_cmd)
    time.sleep(2)

    # Gobuster
    gobuster_out = f"{OUTPUT_DIR}/gobuster_80.txt"
    gobuster_cmd = (
        f"gobuster dir -u http://{TARGET} "
        f"-w {WORDLIST} "
        f"-x php,html,txt,bak "
        f"-o {gobuster_out}"
    )
    print("[*] Opening Gobuster terminal...")
    open_terminal(gobuster_cmd)
    time.sleep(2)

    # Feroxbuster
    ferox_out = f"{OUTPUT_DIR}/feroxbuster_80.txt"
    ferox_cmd = (
        f"feroxbuster -u http://{TARGET} "
        f"-w {WORDLIST} "
        f"-x php,html,txt,bak "
        f"--depth 3 "
        f"-o {ferox_out}"
    )
    print("[*] Opening Feroxbuster terminal...")
    open_terminal(ferox_cmd)
    time.sleep(2)

    # Nikto
    nikto_out = f"{OUTPUT_DIR}/nikto_80.txt"
    nikto_cmd = (
        f"nikto -h http://{TARGET} "
        f"-o {nikto_out}"
    )
    print("[*] Opening Nikto terminal...")
    open_terminal(nikto_cmd)

    # Wait for scans to finish then build report
    print("\n[*] Scans running in separate terminals...")
    print("[*] Waiting for scans to complete before building report...")
    print("[*] Press ENTER when all terminal scans are done")
    input()

    # Build final report
    print("\n[*] Building report...")
    append_report("WHATWEB Fingerprint", whatweb_out)
    append_report("NMAP Deep Dive + Vuln Scan", nmap_out)
    append_report("GOBUSTER Directory Scan", gobuster_out)
    append_report("FEROXBUSTER Recursive Scan", ferox_out)
    append_report("NIKTO Web Scan", nikto_out)

    print(f"\n[+] Report saved to: {REPORT}")
    print(f"[+] View it with: cat {REPORT}")
    print(f"[+] Or: less {REPORT}")

if __name__ == "__main__":
    main()
