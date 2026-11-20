# Home SOC Lab: Splunk Detection Engineering

## Why I built this
My resume had Splunk listed as a skill but nothing to back it up. So I built a small pipeline from scratch: a Windows 11 box forwarding logs to a Splunk server on Ubuntu. Instead of running a canned attack simulation tool, I manually carried out four different attacker techniques myself and wrote my own detections for each one, mapped to MITRE ATT&CK.

This is a companion to my [Wazuh/Sysmon lab](https://github.com/akshitaagrawal-CyberSec/cybersecurity-portfolio/tree/main/01-home-soc-lab). I picked different techniques here on purpose so the two projects don't overlap.

## Setup
- Windows 11 Enterprise endpoint running Sysmon (customized SwiftOnSecurity config) + Splunk Universal Forwarder
- Ubuntu Server 24.04 running Splunk Enterprise
- Forwarder ships Security log + Sysmon log over port 9997 into a `windows` index

## 1. Scheduled task running encoded PowerShell (T1053.005 + T1059.001)
Created a scheduled task that launches a Base64-encoded, hidden PowerShell command. Scheduled tasks survive reboots, so this is a common way attackers set up persistence. Encoding the command just means it doesn't look like plain text if someone glances at the task.

Caught it with Sysmon's process creation log (Event ID 1). Pulled the command line out and flagged anything containing `-enc` or `-EncodedCommand`. Saved as a High-severity alert.

## 2. Registry Run key running encoded PowerShell (T1547.001 + T1059.001)
Same idea, different persistence spot. Added a value under `HKCU\...\CurrentVersion\Run` pointing to an encoded command. This one's worth knowing because it doesn't need admin rights at all, just a normal logged-in user.

Caught via Sysmon's registry event log (Event ID 13), flagging any Run key path paired with an encoded PowerShell value. High severity.

## 3. Standalone encoded PowerShell execution (T1059.001)
No persistence this time, just ran the encoded command directly, like an attacker doing quick recon right after landing on a box. This detection is broader than #1 and #2 since it catches encoded PowerShell no matter how it got launched, not just when it's tucked inside a scheduled task or registry key.

## 4. Security log cleared (T1070.001)
Ran `wevtutil cl Security` to simulate an attacker wiping the log to cover their tracks. The funny part: clearing the log generates its own event (ID 1102, "The audit log was cleared"), right into the log that was just emptied. There's no way to erase the evidence that you erased the evidence.

Set this one to Critical. A cleared Security log is one of the strongest single red flags you can get.

## Attempted: LSASS credential dumping (T1003.001)
This one didn't fully work, and I think that's worth documenting rather than hiding. I tried the classic `rundll32.exe`/`comsvcs.dll` trick to dump LSASS's memory (where Windows caches credentials). Windows Defender's AMSI blocked it immediately. I disabled real-time protection to get past that. The command said it worked, but silently didn't, because Tamper Protection was blocking it at a deeper level. Turned that off through the GUI (can't be scripted, on purpose), tried again, still nothing, and even Task Manager's own "create dump file" on lsass.exe got an Access Denied, running as full Administrator. That's almost certainly LSASS's built-in process protection (PPL) doing its job.

I also tried to build a Splunk detection for the access attempt itself (Sysmon Event ID 10), confirmed the rule loaded correctly, and tested it against an unprotected process (Notepad) as a control, which worked for the dump but still didn't generate a Sysmon event. So the rule itself was fine; something about this specific VM setup wasn't letting that particular event type fire. Didn't chase it further than that, but the attack path and every layer of defense that stopped it along the way are documented.

## Things that tripped me up (the useful part)
- **Splunk's sampling setting** was silently limiting my searches to 10% of events, so identical queries returned different results depending on luck. Took a while to notice the dropdown.
- **The `EventCode` field didn't work** for anything coming through the Sysmon channel, because that channel was configured with `renderXml=true` (raw XML logs). Had to manually pull the event ID out of the raw XML with `rex` instead of trusting the built-in field. Same field worked fine on the Security log channel, which wasn't using raw XML. Good reminder to actually check a field exists before building a query around it.
- Sysmon won't let you stop its own service through normal commands, a small anti-tampering feature, which I only found out by trying.

## Screenshots
See `screenshots/` for the saved alerts and matching search results.
