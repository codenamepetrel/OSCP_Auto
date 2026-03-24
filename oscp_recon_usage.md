# oscp_recon.py — Usage Cheatsheet

> Full OSCP recon automation suite. Run as root for UDP scans and ICMP probes.

---

## Quick Reference

| Goal | Command |
|---|---|
| Scan single host | `sudo python3 oscp_recon.py 192.168.49.101` |
| Find alive hosts only | `sudo python3 oscp_recon.py --subnet 192.168.49.0/24 --ping-only` |
| Scan whole subnet | `sudo python3 oscp_recon.py --subnet 192.168.49.0/24` |
| Skip UDP | `sudo python3 oscp_recon.py 192.168.49.101 --no-udp` |
| Add AutoRecon in background | `sudo python3 oscp_recon.py 192.168.49.101 --autorecon` |
| AutoRecon only | `sudo python3 oscp_recon.py 192.168.49.101 --autorecon-only` |
| Capture proof screenshot | `sudo python3 oscp_recon.py 192.168.49.101 --screenshot` |
| Log a credential | `sudo python3 oscp_recon.py 192.168.49.101 --add-cred admin Pass123 SMB ""` |
| Build exam report | `sudo python3 oscp_recon.py --report` |

---

## Single Host Scans

### Standard full scan (TCP + UDP)
```bash
sudo python3 oscp_recon.py 192.168.49.101
```
Runs RustScan → Nmap TCP detail → Nmap UDP top-200 → AD module if ports trigger → scaffolds folder → writes notes.md cheatsheet → prompts for creds.

---

### Skip UDP (faster, good for initial sweep)
```bash
sudo python3 oscp_recon.py 192.168.49.101 --no-udp
```
Skips the Nmap UDP top-200 scan. Use when you want speed over completeness. Always go back and run UDP manually if you get stuck.

---

### Custom output root
```bash
sudo python3 oscp_recon.py 192.168.49.101 --root /opt/labs
```
Output goes to `/opt/labs/192.168.49.101/` instead of the default `~/oscp/machines/`.

---

### With AutoRecon running in parallel
```bash
sudo python3 oscp_recon.py 192.168.49.101 --autorecon
```
Fires AutoRecon in the background immediately while RustScan and Nmap run normally. Both work in parallel — you get your `notes.md` fast while AutoRecon does its deep scan behind the scenes.

Monitor AutoRecon progress:
```bash
tail -f ~/oscp/machines/192.168.49.101/autorecon/autorecon.log
```

---

### AutoRecon only (skip RustScan/Nmap entirely)
```bash
sudo python3 oscp_recon.py 192.168.49.101 --autorecon-only
```
Skips RustScan and Nmap completely — hands everything to AutoRecon and blocks until it finishes. Folder is still scaffolded. Re-run without `--autorecon-only` afterwards to generate the port cheatsheet once you know what ports are open.

---

### Capture proof.txt screenshot
```bash
sudo python3 oscp_recon.py 192.168.49.101 --screenshot
```
After the scan finishes, prompts you to paste your `proof.txt` value, saves it to `flags/proof.txt` with a timestamp, then takes a full-screen screenshot to `screenshots/proof_<ip>_<timestamp>.png` using `scrot`. Install scrot if needed:
```bash
sudo apt install scrot
```

---

### Combine flags freely
```bash
# Full scan + AutoRecon background + screenshot at end
sudo python3 oscp_recon.py 192.168.49.101 --autorecon --screenshot

# Fast scan — no UDP, no AutoRecon
sudo python3 oscp_recon.py 192.168.49.101 --no-udp

# Custom root + no UDP
sudo python3 oscp_recon.py 192.168.49.101 --root /opt/labs --no-udp
```

---

## Subnet / Network Scans

### Host discovery only — find alive hosts first
```bash
sudo python3 oscp_recon.py --subnet 192.168.49.0/24 --ping-only
```
Runs a fast nmap ping sweep using ICMP + TCP SYN probes on ports 80, 443, 22, and 445. **No port scanning.** Just tells you who is alive.

Output files written immediately:
- `~/oscp/machines/live_hosts.txt` — plain list of alive IPs
- `~/oscp/machines/subnet_map.md` — summary table

Use this first every time you hit a new network. Then kick off full scans once you know your targets.

---

### Full subnet scan (discover + scan all alive hosts)
```bash
sudo python3 oscp_recon.py --subnet 192.168.49.0/24
```
Step 1 — ping sweep to find alive hosts.
Step 2 — runs full RustScan → Nmap → AD check → scaffold → cheatsheet on every live host in parallel.
Step 3 — writes `subnet_map.md` with all results linked.

Prompts once for a domain name. If any host has AD ports (88, 389, 445) it applies that domain automatically without asking again per host.

---

### Control parallel threads
```bash
# Default is 3 threads
sudo python3 oscp_recon.py --subnet 192.168.49.0/24 --threads 3

# More aggressive — 5 parallel hosts at once
sudo python3 oscp_recon.py --subnet 192.168.49.0/24 --threads 5

# Single-threaded — one host at a time (safest, quietest)
sudo python3 oscp_recon.py --subnet 192.168.49.0/24 --threads 1
```
Don't go above 5 threads — RustScan + Nmap running simultaneously on many hosts generates a lot of traffic and can trigger IDS or cause scan failures.

---

### Subnet scan — skip UDP (faster)
```bash
sudo python3 oscp_recon.py --subnet 192.168.49.0/24 --no-udp
```
Drops the Nmap UDP scan on every host. Cuts subnet scan time roughly in half. Good for an initial pass.

---

### Subnet scan — pre-supply AD domain (no prompt)
```bash
sudo python3 oscp_recon.py --subnet 192.168.49.0/24 --domain corp.local
```
Skips the interactive domain prompt entirely. Every host with AD/SMB ports automatically gets AD enumeration against `corp.local`. Use when you already know the domain name (e.g. from a previous box in the same set).

---

### Subnet scan + AutoRecon on each host
```bash
sudo python3 oscp_recon.py --subnet 192.168.49.0/24 --autorecon
```
Fires AutoRecon in the background for every live host alongside the normal scan. Each host gets its own AutoRecon log at `~/oscp/machines/<ip>/autorecon/autorecon.log`.

---

### Full subnet — all options combined
```bash
sudo python3 oscp_recon.py --subnet 192.168.49.0/24 \
  --domain corp.local \
  --threads 3 \
  --no-udp \
  --root /opt/oscp/exam
```

---

## Credential Management

### Log a credential during or after a scan
```bash
# Format: --add-cred <user> <password_or_hash> <service> <notes>
sudo python3 oscp_recon.py 192.168.49.101 --add-cred administrator 'P@ssw0rd' SMB ""
sudo python3 oscp_recon.py 192.168.49.101 --add-cred svc_backup 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c' WinRM "NTLM hash"
sudo python3 oscp_recon.py 192.168.49.101 --add-cred john 'password123' SSH "found in /home/john/.bash_history"
```
All credentials are written to `~/oscp/machines/creds.md` as a shared Markdown table visible across all machines. Includes password reuse reminders.

---

## Report Building

### Generate full exam report
```bash
sudo python3 oscp_recon.py --report
```
Crawls every IP folder under `~/oscp/machines/`, stitches all `notes.md` files together with a table of contents, embeds screenshots and flags inline, and appends the full credential summary. Output: `~/oscp/machines/exam_report.md`.

If `pandoc` is installed it offers to convert to PDF automatically:
```bash
sudo apt install pandoc wkhtmltopdf
sudo python3 oscp_recon.py --report
```

---

## Output Structure

Every scan creates this folder structure:

```
~/oscp/machines/
├── creds.md                  ← shared credential tracker (all machines)
├── subnet_map.md             ← subnet scan results (subnet mode only)
├── live_hosts.txt            ← plain list of alive IPs (subnet mode only)
├── exam_report.md            ← stitched exam report (--report)
│
└── 192.168.49.101/
    ├── notes.md              ← per-port attack cheatsheet (auto-generated)
    ├── nmap/
    │   ├── tcp_detail.nmap   ← nmap TCP detail scan
    │   ├── tcp_detail.xml
    │   ├── tcp_detail.gnmap
    │   ├── udp_top200.nmap   ← nmap UDP top-200
    │   ├── udp_top200.xml
    │   └── udp_top200.gnmap
    ├── exploits/             ← drop exploit code here
    ├── screenshots/          ← proof screenshots saved here
    ├── flags/                ← proof.txt values saved here
    ├── scripts/              ← custom scripts for this target
    ├── ad_enum/              ← AD module output
    │   ├── kerbrute_users.txt
    │   ├── enum4linux_ng.json
    │   ├── asrep_hashes.txt
    │   └── ad_attacks.md     ← AD-specific attack notes
    └── autorecon/            ← AutoRecon output (--autorecon)
        └── autorecon.log
```

---

## All Flags Reference

| Flag | Applies To | Description |
|---|---|---|
| `<ip>` | Single | Target IP address |
| `--subnet CIDR` | Subnet | e.g. `192.168.49.0/24` |
| `--root PATH` | Both | Override output root dir |
| `--no-udp` | Both | Skip UDP scan |
| `--autorecon` | Both | Run AutoRecon in background |
| `--autorecon-only` | Single | Skip RustScan/Nmap, AutoRecon only |
| `--screenshot` | Single | Capture proof.txt screenshot |
| `--add-cred U P S N` | Single | Log a credential to creds.md |
| `--threads N` | Subnet | Parallel scan threads (default: 3) |
| `--ping-only` | Subnet | Host discovery only, no port scan |
| `--domain DOMAIN` | Subnet | AD domain — skips interactive prompt |
| `--report` | Global | Build exam report from all machines |

---

## Tips

- Always run `--ping-only` first on a new subnet to map the network before committing to full scans
- Run single-IP mode interactively when you hit an AD box — the AD module prompts for ldapdomaindump creds and gives you a full BloodHound checklist
- Keep `--threads 3` or lower during the exam — you don't want scan noise causing missed ports
- Use `--no-udp` for your initial pass then re-run UDP manually on interesting hosts (`161/SNMP`, `500/IKE`, `53/DNS`)
- `--autorecon` parallel mode is best on exam day — you get your cheatsheet immediately while AutoRecon runs its deep scan
- After every box: `--add-cred` + `--screenshot` before moving on — exam reports need both
