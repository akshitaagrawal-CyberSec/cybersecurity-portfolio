# Home SOC Lab: Wazuh SIEM + Sysmon

A home Security Operations Center lab built to practice SIEM deployment, endpoint logging, alert triage, investigation and hardening, following the same workflow a Tier 1 SOC analyst uses.

## Goal
Deploy an open-source SIEM, forward detailed Windows endpoint telemetry to it, generate security-relevant activity, then detect, investigate and map that activity to MITRE ATT&CK, and remediate the root cause.

## Lab Architecture

```
Windows 11 endpoint (Sysmon + Wazuh agent)  --logs-->  Wazuh SIEM on Ubuntu Server  -->  Wazuh Dashboard
        192.168.85.134                                        192.168.85.133
```

| Component | Details |
|---|---|
| Hypervisor | VMware Workstation Pro, isolated NAT network |
| SIEM server | Ubuntu Server 24.04 LTS, Wazuh 4.14 all-in-one (indexer, manager, dashboard), 8 GB RAM, 2 vCPU |
| Endpoint | Windows 11 Enterprise (evaluation), 6 GB RAM, 2 vCPU, virtual TPM |
| Endpoint telemetry | Sysmon (SwiftOnSecurity config) + Windows Security/System event logs |

## Tools
Wazuh · Sysmon · VMware Workstation · Ubuntu Server · Windows 11 · PowerShell · Bash · SSH · MITRE ATT&CK · CIS Benchmarks

## Setup
- Verified the Ubuntu ISO with SHA-256 before installing.
- Expanded the LVM root volume from 24 GB to 48 GB so the Wazuh indexer has room for log storage.
- Managed the server remotely over SSH.
- Deployed Wazuh all-in-one and confirmed the indexer, manager, Filebeat and dashboard services.
- Installed Sysmon on Windows and deployed the Wazuh agent.
- Configured the agent to collect the `Microsoft-Windows-Sysmon/Operational` channel and verified collection in the agent log.
- Took VM snapshots at each milestone for repeatable testing.

## Detections

| # | Activity | Log source | Wazuh rule | MITRE ATT&CK |
|---|---|---|---|---|
| 1 | Repeated wrong-password logons | Windows Security 4625 | 60122 (L5) | T1110.001 Password Guessing (Wazuh mapped T1531) |
| 2 | File created / modified / deleted in a monitored folder | Wazuh FIM (syscheck) | 554 (L5), 550 (L7), 553 (L7) | T1565.001 Stored Data Manipulation |
| 3 | Executables written to System32 / Temp | Sysmon Event ID 11 | 92217 (L6) | Investigated, benign |

### Detection 1: Failed logons (password guessing)
- Entered a wrong password 6 times at the login screen for `user1`, about 3 seconds apart, then logged in successfully.
- Evidence: logonType 2 (interactive), source 127.0.0.1, subStatus `0xc000006a` (valid username, wrong password).
- Wazuh does not alert on routine successful logons, so I confirmed the follow-up successful logon (4624) directly in the endpoint's Security log, showing the account was accessed after the failures.
- Wazuh mapped the rule to T1531; based on the behavior I classified it as **T1110.001 Password Guessing**.
- Compliance tags: PCI DSS 10.2.4/10.2.5, NIST 800-53 AC-7.

### Detection 2: File Integrity Monitoring
- Added `C:\Lab\Sensitive` to Wazuh syscheck with real-time monitoring.
- Created, modified and deleted `payroll.txt`; each change alerted within seconds.
- The modification alert showed MD5/SHA-1/SHA-256, size and mtime changes (MD5 `87689b…` → `312b91…`).
- Compliance tags: PCI DSS 11.5, NIST 800-53 SI-7.

### Investigation: Sysmon file-creation alerts (rule 92217)
- 11 "Executable file dropped in folder commonly used by malware" alerts in two bursts.
- Burst 1: `MpSigStub.exe` (Microsoft Defender updater) wrote `mpengine.dll` to `C:\Windows\Temp\{GUID}\` right after network connectivity was restored.
- Burst 2: `SecurityHealthSetup.exe` created a new `SecurityHealthHost.exe` under `System32\SecurityHealth\`.
- Both ran as NT AUTHORITY\SYSTEM with valid Microsoft Authenticode signatures.
- **Verdict:** benign true positives (Defender and Windows Security updates). Tuning candidate: allow-list signed Microsoft update processes for this rule.

## Hardening: CIS Benchmark (Wazuh SCA)
- Wazuh SCA audited the endpoint against the **CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0** (482 checks): baseline **123 passed / 350 failed (26%)**, typical for a default install.
- Root cause for Detection 1: no account lockout threshold (26006), duration (26005) or reset window (26007), and lockout events not audited (26145).
- Remediation:

```powershell
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15
auditpol /set /subcategory:"Account Lockout" /failure:enable
```

- Re-scan verified all four checks passing (127 passed / 346 failed).

## Troubleshooting
- **Installer hang / RCU CPU stall warnings:** diagnosed a vCPU scheduling issue on a hybrid Intel CPU; reduced the VM from 4 to 2 vCPUs and reinstalled successfully.
- **Sysmon channel not collected:** my first config edit silently failed; I verified with `Select-String`, fixed the insertion point in `ossec.conf`, and confirmed via the agent log.
- **Dashboard unreachable after resume:** `ip a` showed NO-CARRIER on both VMs; restarted the VMware NAT/DHCP services, reconnected the virtual NICs, and resynced the server clock.
- **Vulnerability detection empty:** the manager log showed the CVE feed download failed with a DNS error during the outage; after restoring connectivity and restarting the manager, the feed updated and a re-scan was triggered.

## What I Learned
- The difference between an **event** and an **alert**, and why SIEMs alert only above a severity threshold.
- How to pivot from an alert to the endpoint's own logs to answer "did the attacker get in?"
- Not to accept tool MITRE mappings at face value.
- How FIM uses hash baselines, and why PCI DSS requires it.
- Detect → find root cause (CIS audit) → remediate → verify is the full security lifecycle.
- Time sync and network health matter: wrong clocks and dropped NICs directly break investigations.

## Screenshots
_(Upload images to `01-home-soc-lab/screenshots/` and link them here.)_
- Wazuh dashboard with the active agent
- Failed logon alerts and expanded 4625 alert
- FIM alerts (554 / 550 / 553) and the hash change
- CIS SCA score before and after
- Sysmon 92217 investigation fields

## Next Steps
- Active Directory lab: detect Kerberoasting and password spraying
- Write custom Wazuh rules and tune noisy alerts
