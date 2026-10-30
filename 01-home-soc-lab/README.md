# Home SOC Lab with Wazuh and Sysmon

I built this lab to get real hands-on time with a SIEM before applying for SOC analyst roles. Reading about alerts is one thing, but I wanted to actually generate activity on a Windows machine, watch it show up in a SIEM, and figure out what happened from the logs.

## What's in the lab

Everything runs in VMware Workstation on my laptop, on a NAT network so the lab stays separate from my home network.

- **Wazuh server:** Ubuntu Server 24.04 running Wazuh 4.14 (all-in-one install: indexer, manager and dashboard). 8 GB RAM, 2 vCPUs.
- **Windows endpoint:** Windows 11 Enterprise (evaluation) with Sysmon and the Wazuh agent installed. 6 GB RAM, 2 vCPUs.

The Windows VM sends its Security, System and Sysmon logs to the Wazuh server, and I use the Wazuh dashboard to search and investigate alerts.

```
Windows 11 (Sysmon + Wazuh agent)  -->  Wazuh server (Ubuntu)  -->  Dashboard
     192.168.85.134                        192.168.85.133
```

## Setting it up

A few things I did during setup that turned out to matter:

- Checked the Ubuntu ISO's SHA-256 hash against the official one before installing.
- The Ubuntu installer only gave the root volume about 24 GB of my 50 GB disk, so I extended the LVM volume to use all of it. Wazuh's indexer needs that space for logs.
- Managed the server over SSH from my laptop instead of typing into the VM console.
- Installed Sysmon with the SwiftOnSecurity config, then added the Sysmon event channel to the Wazuh agent's `ossec.conf`. Out of the box, the agent doesn't collect Sysmon logs.
- Took snapshots after each milestone so I could roll back if I broke something.

## What I tested

### 1. Failed logins

I typed the wrong password six times at the Windows login screen for my test account (`user1`), then logged in correctly.

Wazuh picked up all six failures (Event ID 4625, rule 60122). Looking at the alert details:

- `logonType 2` meant the attempts were made at the keyboard, not over the network.
- `subStatus 0xc000006a` meant the username was valid and only the password was wrong. If an attacker knows a real username, that's a more targeted attack than one guessing names too.

Wazuh didn't alert on the successful login afterward, which makes sense since normal logins happen all the time. So I checked the Windows Security log directly and found the 4624 success event about five minutes after the failures. In a real case, that sequence would be a sign the account may have been compromised.

One thing I noticed: Wazuh mapped this alert to MITRE T1531 (Account Access Removal). Based on what actually happened, I think T1110.001 (Password Guessing) is the better fit.

### 2. File Integrity Monitoring

I set Wazuh to watch a folder (`C:\Lab\Sensitive`) in real time, then created, edited and deleted a file in it. All three changes alerted within a few seconds:

- 554: file added
- 550: file modified (the MD5 and SHA-256 hashes changed, along with size and modified time)
- 553: file deleted

Wazuh tagged the modification alert with PCI DSS 11.5, the requirement that covers change detection on important files.

### 3. Investigating Sysmon alerts I didn't trigger

While I was working, Wazuh raised 11 alerts saying an executable had been dropped in a folder commonly used by malware (rule 92217, from Sysmon Event ID 11). I looked into these:

- The first group came from `MpSigStub.exe` writing `mpengine.dll` into `C:\Windows\Temp`. That's Microsoft Defender updating its engine, and it happened right after my VM's network came back online.
- The second group came from `SecurityHealthSetup.exe` writing a new version of `SecurityHealthHost.exe` in System32. That's the Windows Security app updating itself.

Both ran as SYSTEM, and I checked that the files had valid Microsoft digital signatures. So these were harmless: the rule fired correctly, but on normal update activity. If I were running this long-term, I'd tune the rule to ignore signed Microsoft updaters.

## Fixing the root cause

Wazuh also runs a CIS benchmark check on endpoints. My Windows VM scored 26% (123 passed, 350 failed out of 482 checks), which is normal for a fresh install.

The failed checks explained my first test: there was no account lockout policy at all, so someone could guess passwords forever, and lockout events weren't being logged either. I fixed both:

```powershell
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15
auditpol /set /subcategory:"Account Lockout" /failure:enable
```

After a re-scan, those four checks passed (127 passed, 346 failed).

## Things that went wrong (and what I learned from them)

- **The Wazuh installer froze.** The console was full of "RCU stall" messages. The VM wasn't getting proper CPU time on my laptop's Intel chip, so I lowered it from 4 vCPUs to 2 and the install finished.
- **My first config change didn't work.** I added the Sysmon channel with a PowerShell command, but it silently didn't match anything in the file. I only caught it because I checked the agent log instead of assuming it worked.
- **The dashboard stopped loading after I resumed the VMs.** `ip a` showed the network interface as NO-CARRIER on both VMs. Restarting VMware's NAT and DHCP services and reconnecting the virtual network cards fixed it. I also had to resync the server's clock, which matters because alert timestamps depend on it.
- **Vulnerability detection showed nothing.** The Wazuh log showed the CVE database download had failed with a DNS error during that same network outage. After the network was back, I restarted the manager and the download completed.

## Takeaways

- Not every event becomes an alert, and that's on purpose. Sometimes you have to go back to the endpoint's logs to get the full story.
- Tool labels like MITRE mappings are a starting point, not the final answer.
- Finding something is only half the job. The CIS check helped me fix the actual cause.
- Small infrastructure problems, like a wrong clock or a dropped network connection, can quietly break an investigation.

## What's next

An Active Directory lab, where I'll look at detecting password spraying and Kerberoasting, and writing my own Wazuh rules.
