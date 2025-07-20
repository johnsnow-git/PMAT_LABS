PMAT Labs Malware Analysis Write-Up

 Overview

This write-up documents hands-on analysis of multiple malware samples using both static and dynamic techniques. The work was done as part of the PMAT Labs training, covering everything from basic indicators to advanced reverse engineering.

 Tools Used

Basic Analysis:

VirusTotal

sha256sum / md5sum

FLOSS

PEStudio

PEView

Procmon

Wireshark

TCPView

Netcat

Inetsim

Advanced Analysis:

Cutter

dnSpy

x32dbg

oledump.py

Python scripting

🚦 Malware Behavior Observed

1. Dropper Behavior

CMD execution: ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q "%s"

Favicon.ico used as potential second-stage payload

Downloads and executes files silently via InternetOpenUrlA and ShellExec

2. RAT & Reverse Shells

Opens a listening socket on port 5555

Command injection capabilities

Uses base64 and PowerShell for payload delivery

TCPView and Procmon confirmed connection attempts

3. Persistence Techniques

Writes binaries to startup directories:

C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\

Uses CreateRemoteThread to inject shellcode

 File Analysis Highlights

Static Indicators:

Floss revealed suspicious strings and encoded payloads

PE header showed standard Windows API imports

Non-packed binaries (raw vs virtual size nearly equal)

Dynamic Indicators:

Powershell reverse shell with execution policy bypass

TLS handshake initiated to callback domains over port 8443

DNS callouts like aaaa.kadusus.local

Advanced Reverse Engineering

With Cutter & Debugger:

Identified process injection logic

Decompiled payloads showing:

Memory allocation (VirtualAllocEx)

Shellcode write (WriteProcessMemory)

Execution (CreateRemoteThread)

With dnSpy:

Decompiled .NET malware (embedDLL.dll)

Observed AES decryption using hardcoded keys

Files dropped: embed.xml, embed.vbs

Persistence via registry Run key

Scripting & Delivery Mechanisms

Powershell reverse TCP shell heavily obfuscated and base64 encoded

VBS used with ShellExecute for payload execution

HTA malware with embedded VBScript and JavaScript chains

Notable Samples Analyzed

Malware.Unknown.exe.malz - Dropper

putty.exe (trojanized) - Reverse Shell Payload

rat.unknown.exe - Reverse Shell Listener

unknown.exe.malz - Exfiltrates using HTTP GET

wannacry variant - SMB propagation & ransomware behavior

Key Learning Points

Importance of multi-stage analysis (network, host, code)

Malware often uses legitimate tools and LOLBins (like PowerShell)

Observing behavior in a safe, controlled sandbox is essential

Reverse engineering and unpacking is critical for advanced threat detection

References

Taggart Tech (YouTube & Twitch)

TCM Security Academy


