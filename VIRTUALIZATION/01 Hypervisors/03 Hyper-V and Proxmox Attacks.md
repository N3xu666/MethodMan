# Hyper-V and Proxmox Attacks

## 1. Overview

Hyper-V (Microsoft) and Proxmox VE (open-source, based on KVM and LXC) are two widely used Type 1 hypervisors. Both have a management plane that is a high-value target.

Attack surface:

- **Hyper-V:** WinRM (5985/5986), SMB (445), RDP (3389), Hyper-V Management API (2179), SCVMM (8100, 8101, 8102).
- **Proxmox VE:** web UI (8006), SSH (22), SPICE proxy (3128), Ceph (6789, 3300), corosync (5405).

Common attack paths:

1. Default or weak credentials on Proxmox root or Hyper-V Administrator.
2. Unpatched CVEs in Hyper-V (CVE-2024-38080) or Proxmox (CVE-2024-24205).
3. WinRM or SSH exposed to the network.
4. Snapshot abuse and VHDX/VMA extraction.
5. Cluster compromise (Proxmox corosync, Hyper-V failover cluster).

## 2. Reconnaissance / Enumeration

### Offensive

```bash
# Hyper-V host discovery
nmap -p 135,445,5985,5986,2179,3389 -sV <target>

# Proxmox discovery
nmap -p 22,8006,3128,5405,6789 -sV <target>

# Proxmox version
curl -k -s https://<target>:8006/ | grep -i "version\|proxmox"

# Hyper-V check via WinRM
curl -s -o /dev/null -w "%{http_code}" http://<target>:5985/wsman
```

### Defensive

- Restrict WinRM (5985/5986) to a management VLAN.
- Disable SSH on Proxmox unless actively used.
- Monitor for scans against 8006 (Proxmox) and 5985/5986 (Hyper-V).

## 3. Common Attack Vectors

- **Default credentials:** Proxmox root with a weak password, Hyper-V Administrator with a weak password.
- **CVE-2024-38080:** Hyper-V elevation of privilege (CVSS 7.8).
- **CVE-2024-24205:** Proxmox VE authentication bypass (CVSS 8.8).
- **WinRM exposure:** unencrypted WinRM allows credential interception.
- **VHDX/VMA extraction:** snapshots and disk images can be downloaded and mounted.
- **Cluster compromise:** Proxmox corosync or Hyper-V failover cluster can be targeted for lateral movement.

## 4. Exploitation Recipes

### CVE-2024-38080 (Hyper-V EoP)

```powershell
# Check patch level
Get-HotFix | Where-Object { $_.HotFixID -eq "KB5037771" }

# If unpatched, a local attacker can escalate to SYSTEM
# (Exploit code is not public; this is a detection check)
```

### CVE-2024-24205 (Proxmox Auth Bypass)

```bash
# Check Proxmox version
curl -k -s https://<target>:8006/api2/json/version

# If vulnerable, a crafted request bypasses authentication
curl -k -X POST "https://<target>:8006/api2/json/access/ticket" \
  -d "username=root@pam&password=any"
```

### Proxmox default credentials

```bash
# Try root with common passwords
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target>

# Or use the web UI
curl -k -X POST "https://<target>:8006/api2/json/access/ticket" \
  -d "username=root@pam&password=<PASSWORD>"
```

### Hyper-V snapshot extraction

```powershell
# List snapshots (requires Hyper-V Administrator)
Get-VMSnapshot -VMName <vmname>

# Export a snapshot
Export-VMSnapshot -VMName <vmname> -Name <snapshotname> -Path C:\export

# Mount the VHDX locally
Mount-VHD -Path C:\export\snapshot.vhdx
```

## 5. Post-Exploitation

- **VHDX/VMA extraction:** mount the disk image to access guest filesystem.
- **Cluster secrets:** Proxmox corosync authkey allows joining the cluster.
- **Hyper-V host compromise:** access to all VMs on the host, including domain controllers.
- **Snapshot abuse:** restore old snapshots to bypass security controls.

## 6. Preventive Controls (Defensive)

- **Patch management:** apply Microsoft and Proxmox security updates promptly.
- **Network segmentation:** management interfaces on a dedicated VLAN.
- **MFA:** enable MFA for Proxmox web UI and Hyper-V WinRM (via Windows Hello for Business or smart card).
- **Least privilege:** no daily use of `root` (Proxmox) or `Administrator` (Hyper-V).
- **Disable unused services:** WinRM, SSH, SPICE proxy.
- **Certificate management:** replace default self-signed certificates.

## 7. Detection Controls (Defensive)

- **Proxmox audit logs:** `/var/log/pve/tasks/` and `/var/log/pveproxy/access.log`.
- **Hyper-V event logs:** `Microsoft-Windows-Hyper-V-Worker-Admin`, `Microsoft-Windows-Hyper-V-VMMS-Admin`.
- **Network IDS:** alert on scans against 8006 (Proxmox) and 5985/5986 (Hyper-V).
- **SIEM correlation:** a new WinRM login followed by `Export-VMSnapshot` is a high-fidelity alert.

## 8. Verification

- `nmap -p 5985,5986,8006 <target>` from an untrusted network should show filtered/closed.
- Proxmox: `pve-firewall status` should show the firewall active.
- Hyper-V: `Get-NetFirewallRule -DisplayName "Windows Remote Management*"` should show blocked.
- Review Proxmox `/var/log/pveproxy/access.log` for failed logins.

## 9. OSCP Notes

- OSCP exam scope does not include Hyper-V or Proxmox exploitation directly. However, a compromised hypervisor can be a pivot point.
- Screenshot the Proxmox version and successful login.
- Document the exact CVE and patch level.

## 10. Production Notes

- **Change management:** hypervisor patches require a maintenance window.
- **Backup:** Proxmox cluster configuration (`/etc/pve/`) and Hyper-V host configuration must be backed up.
- **Monitoring:** integrate Proxmox and Hyper-V logs into SIEM.
- **Incident response:** if a hypervisor is compromised, assume all VMs are compromised. Isolate, snapshot for forensics, rebuild.

## 11. References

- Proxmox Security Advisories - https://www.proxmox.com/en/proxmox-virtual-environment/security
- CVE-2024-38080 NVD - https://nvd.nist.gov/vuln/detail/CVE-2024-38080
- CVE-2024-24205 NVD - https://nvd.nist.gov/vuln/detail/CVE-2024-24205
- Microsoft Hyper-V Security - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/security/
