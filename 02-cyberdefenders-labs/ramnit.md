# Ramnit

**Platform:** CyberDefenders | **Category:** Endpoint forensics | **Difficulty:** Easy
**Tools:** Volatility 3, grep, sha1sum, VirusTotal | **Environment:** Kali Linux VM

## Scenario

An intrusion detection alert pointed to suspicious behavior on a Windows 10 workstation. I was given a memory dump and asked to find the malware, trace its network activity, and collect IOCs to block.

## How I worked through it

### 1. Confirm the dump

```
vol -q -f memory.dmp windows.info
```

This gave me the OS version and the time of the snapshot, which is the cutoff for everything I found.

### 2. Find the suspicious process

```
vol -q -f memory.dmp windows.pstree > pstree.txt
```

Most of the tree looked like normal Windows. One process stood out:

- It was launched by `explorer.exe`, so a user ran it.
- It ran from the `Downloads` folder and was still running when the snapshot was taken, which an installer shouldn't be.
- It had no child processes, even though a real installer would start some.
- It was 32-bit on a 64-bit system, a weak clue on its own.

Its name matched a legitimate installer, so the name alone proved nothing. I checked the network activity and the file itself.

### 3. Check network activity

```
vol -q -f memory.dmp windows.netscan > netscan.txt
grep -E "<process name>|<PID>" netscan.txt
```

The process made an outbound connection about one second after it started. It used an unusual port, not a normal web port, to an address that wasn't the vendor's. I looked up the IP on VirusTotal. It showed zero detections, but more than ten malware files had contacted it. A clean score on an IP doesn't mean it's safe, so I checked its relations too.

### 4. Extract the file and hash it

My first attempt used the process-dump option:

```
vol -q -f memory.dmp -o dumped windows.pslist --pid <PID> --dump
```

That rebuilds the program from memory as it was running, so its hash didn't match the original file. What worked was extracting the files Windows had cached:

```
vol -q -f memory.dmp -o dumpfiles windows.dumpfiles --pid <PID>
sha1sum dumpfiles/*<process name>*
```

Lesson: where you extract a file from decides its hash. A runtime copy and the on-disk copy can differ.

### 5. Enrich with threat intelligence

I looked up the hash on VirusTotal. Almost every vendor flagged it, and the family names pointed to Ramnit. The Details page gave the compile timestamp, and the Relations tab listed the domains and URLs the sample contacts. Some of those were ordinary Microsoft domains (time sync and similar), so I separated normal background traffic from the malicious ones.

## MITRE ATT&CK mapping

- **T1036**: Masquerading (a malicious file named like a legitimate installer)
- **T1071**: Application Layer Protocol (communication with the C2 server)
- **T1105**: Ingress Tool Transfer (the sample downloads further files)

## Detection and response ideas

- Alert on executables running from `Downloads` that make outbound connections within seconds of starting.
- Block the C2 IP and domain at the firewall and DNS, then search other hosts for connections to them.
- Search the environment for the file hash.
- Isolate the host and remove the file.

## What I learned

- A process name can be copied, so path, parent, timing, and network behavior are what confirm it.
- How a file is extracted from memory changes its hash.
- Threat intel needs careful reading. A zero score on an IP didn't mean clean, and not every contacted domain was malicious.
