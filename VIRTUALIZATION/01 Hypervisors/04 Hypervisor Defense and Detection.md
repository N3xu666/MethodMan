# Hypervisor Defense and Detection

## 1. Overview

Defending hypervisors requires a layered approach: hardening the management plane, monitoring for anomalous API calls, and segmenting the virtual network. This file focuses on the defensive side - controls, detection, and incident response for ESXi, Hyper-V, and Proxmox.

## 2. Reconnaissance / Enumeration (Defensive)

Attackers enumerate hypervisors by scanning management ports (443, 902, 5985/5986, 8006). Defenders should:

- Maintain an inventory of all hypervisor management interfaces.
- Scan your own management VLANs regularly to detect unauthorized exposure.
- Use `nmap` from an untrusted network to confirm management ports are filtered.

## 3. Common Attack Vectors (Defensive View)

- **Default credentials:** enforce strong passwords and MFA.
- **Unpatched CVEs:** subscribe to VMware, Microsoft, and Proxmox security advisories.
- **Snapshot abuse:** audit snapshot creation and deletion.
- **Virtual network sniffing:** disable promiscuous mode on production vSwitches.

## 4. Exploitation Recipes (Detection Examples)

### Detecting CVE-2021-21972 exploitation

```bash
# vCenter log entry for vROPS upload
grep -i "uploadova" /var/log/vmware/vpxd/vpxd.log
grep -i "vropspluginui" /var/log/vmware/vrops/vrops.log
```

### Detecting ESXi default credential use

```bash
# ESXi shell log
grep -i "login" /var/log/shell.log | grep -i "root"
```

### Detecting Hyper-V snapshot export

```powershell
# Windows Event Log - Hyper-V Worker
Get-WinEvent -LogName "Microsoft-Windows-Hyper-V-Worker-Admin" | Where-Object { $_.Id -eq 18500 }
```

## 5. Post-Exploitation (Defensive Response)

If a hypervisor is compromised:

1. Isolate the host from the management network.
2. Snapshot all VMs for forensic analysis.
3. Rebuild the hypervisor from a known-good image.
4. Rotate all credentials (vCenter SSO, ESXi root, Hyper-V Administrator).
5. Review audit logs for lateral movement.

## 6. Preventive Controls (Defensive)

- **Patch management:** apply critical hypervisor patches within 48 hours.
- **Network segmentation:** management interfaces on a dedicated VLAN, never internet-facing.
- **MFA:** enforce MFA for vCenter SSO, ESXi SSH, Hyper-V WinRM, and Proxmox web UI.
- **Least privilege:** role-based access control (RBAC) for all hypervisor management.
- **Disable unused services:** CIM, SMB, SSH, ESXi Shell, WinRM, SPICE proxy.
- **Certificate management:** replace default self-signed certificates with internal CA.
- **Backup:** encrypt hypervisor configuration backups and store offline.
- **Logging:** forward hypervisor logs to a SIEM in real time.

## 7. Detection Controls (Defensive)

- **vCenter:** monitor `com.vmware.vapi` events (`UploadOva`, `SetTargetObject`, `Login`).
- **ESXi:** monitor `/var/log/shell.log`, `/var/log/hostd.log`, `/var/log/vmkernel.log`.
- **Hyper-V:** monitor `Microsoft-Windows-Hyper-V-Worker-Admin`, `Microsoft-Windows-Hyper-V-VMMS-Admin`.
- **Proxmox:** monitor `/var/log/pve/tasks/`, `/var/log/pveproxy/access.log`.
- **Network IDS:** alert on scans against 443, 902, 5985/5986, 8006 on management VLANs.
- **SIEM correlation:** a successful login from a new IP followed by a snapshot creation is high-fidelity.

## 8. Verification

- Run `nmap -p 443,902,5985,5986,8006 <management-ip>` from an untrusted network; all should be filtered.
- Check ESXi firewall: `esxcli network firewall ruleset list`.
- Check Hyper-V firewall: `Get-NetFirewallRule -DisplayName "Windows Remote Management*"`.
- Check Proxmox firewall: `pve-firewall status`.
- Verify MFA enforcement in vCenter SSO and Proxmox.

## 9. OSCP Notes

- OSCP exam scope does not include hypervisor defense directly. However, understanding hypervisor hardening is valuable for the report's "Recommendations" section.
- Document the controls you would recommend for a compromised environment.

## 10. Production Notes

- **Change management:** hypervisor hardening changes require a maintenance window.
- **Backup:** vCenter `vdcbackup`, Proxmox `/etc/pve/`, Hyper-V host configuration.
- **Monitoring:** integrate hypervisor logs into SIEM. Alert on anomalous API calls.
- **Incident response:** assume all VMs on a compromised host are compromised. Isolate, snapshot, rebuild.
- **Tabletop exercises:** run regular incident response drills for hypervisor compromise.

## 11. References

- VMware Security Configuration Guide - https://core.vmware.com/security-configuration-guide
- Microsoft Hyper-V Security - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/security/
- Proxmox Security - https://pve.proxmox.com/wiki/Security
- NIST SP 800-125 - https://csrc.nist.gov/publications/detail/sp/800-125/final
- CIS Benchmarks for VMware and Microsoft - https://www.cisecurity.org/cis-benchmarks
