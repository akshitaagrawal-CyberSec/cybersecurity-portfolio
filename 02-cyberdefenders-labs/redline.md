# RedLine

**Platform:** CyberDefenders | **Category:** Endpoint forensics | **Difficulty:** Easy
**Tools:** Volatility 3, strings, grep, VirusTotal | **Environment:** Kali Linux VM

## Scenario

A Windows 10 workstation was suspected of an infostealer infection. I was given a memory dump and asked to trace what the attacker did, identify the malware, and collect indicators of compromise (IOCs).

## How I worked through it

I followed the order I'd use on a SOC alert: find the suspicious process, check what it talked to, check how it hid, then enrich the IOCs.

### 1. Confirm what I was looking at

```
vol -q -f MemoryDump.mem windows.info
```

This confirmed the dump loaded and gave me the OS version and the time the snapshot was taken. Everything I found happened before that time.

### 2. Find the suspicious process

```
vol -q -f MemoryDump.mem windows.pstree > pstree.txt
```

I read the process tree looking for anything odd in its name, path, parent, or start time. What made one process stand out:

- It ran from a random-named folder inside a user's `AppData\Local\Temp`. Legitimate software normally runs from `System32` or `Program Files`.
- Its name didn't belong to Windows or to any installed software.
- Its parent process had already exited, which is typical of a dropper that launches a payload and quits.
- A second copy started about 30 minutes later under `svchost.exe`, which suggests persistence. I didn't confirm the mechanism.
- It had a child process that I checked against what normal Windows would launch.

A VPN client and its helper were also running. They were launched by the user from `Program Files`, so I treated them as normal software but kept them in mind.

### 3. Check network activity

```
vol -q -f MemoryDump.mem windows.netscan > netscan.txt
grep -E "<suspect name or PIDs>" netscan.txt
```

Filtering for the suspect's PIDs showed an outbound web connection to an external address. It used plain HTTP on port 80, which blends in with normal browsing. The connection's source address looked like the VPN adapter's, so the traffic probably went through the tunnel. I didn't fully verify that. The VPN processes also exited seconds after the connection, which I noted as a possible link.

### 4. Check for injected or unpacked code

```
vol -q -f MemoryDump.mem windows.malfind --pid <suspect PID>
```

Malfind flagged a private memory region with unusual permissions. Normal program code can be run but not written to, and it is backed by a file on disk. This region could be written to and run, had no file behind it, and started with the `MZ` header that marks a Windows executable. That suggests the real payload was unpacked or injected at runtime, and that the file on disk was only a wrapper.

### 5. Recover the full web request

```
strings -a -n 8 MemoryDump.mem | grep -F "<C2 IP>" | sort -u
```

Most matches were truncated fragments, because strings in memory get cut off or overwritten. I kept only the complete URL that ended in a script file.

### 6. Enrich the IOC

I looked up the remote IP on VirusTotal. Many vendors flagged it as malicious, and threat-intel sources tied it to RedLine and to malware payload delivery.

## MITRE ATT&CK mapping

- **T1071.001**: Application Layer Protocol, Web Protocols (HTTP to the C2 server)
- **T1055**: Process Injection (suspected, based on the writable and executable region with an MZ header)

## Detection and response ideas

- Alert on executables launched from `AppData\Local\Temp`, for example Sysmon Event ID 1 with a path filter in Wazuh.
- Alert on outbound connections to known-bad IPs, for example Sysmon Event ID 3 checked against a threat-intel list.
- Block the C2 IP at the firewall, and search other hosts for the file name and the connection.
- Isolate the host and look for the persistence mechanism.
- Treat any credentials saved in the browser on this machine as stolen and reset them.

## What I learned

- How to read a process tree and spot an anomaly by path, parent, and timing.
- Memory forensics can show things disk logs miss, like injected code and recent network connections.
- One clue is weak, but several together make a convincing case. Some of my conclusions (persistence, the VPN link) are inferences, and I marked them that way.
