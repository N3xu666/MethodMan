# Management Plane Security

## 1. Overview

The management plane is the control layer for the hypervisor: vCenter Server, SCVMM (System Center Virtual Machine Manager), Proxmox cluster, and their APIs. Compromising the management plane gives an attacker control over every VM on every host in the cluster.

This file focuses on the management plane itself: authentication, authorization, API security, and automation risks.

## 2. Reconnaissance / Enumeration (Offensive)

- **vCenter:** port 443 (vSphere Client, vAPI), 443 (SSO), 443 (vROPS plugin).
- **SCVMM:** ports 8100, 8101, 8102 (WinRM), 443 (SCVMM console).
- **Proxmox:** port 8006 (web UI, API), 3128 (SPICE proxy).
- **API enumeration:** `curl -k https://<vcenter>/api/vcenter/vm` (vAPI), `curl -k https://<proxmox>:8006/api2/json/nodes` (Proxmox API).
- **Certificate inspection:** default certificates often reveal the internal hostname and domain.

## 3. Common Attack Vectors

- **SSO misconfiguration:** vCenter SSO with default `administrator@vsphere.local` and weak password.
- **API token leakage:** hardcoded API tokens in automation scripts, CI/CD pipelines, or Terraform state.
- **SCVMM service account:** over-privileged service account used for SCVMM management.
- **Proxmox API tokens:** long-lived API tokens without IP restrictions.
- **Insecure automation:** Terraform or Ansible playbooks with hardcoded credentials and no vault.

## 4. Exploitation Recipes

### vCenter SSO default credentials

```bash
# Try default SSO credentials
curl -k -X POST "https://<vcenter>/rest/com/vmware/cis/session" \
  -u "administrator@vsphere.local:<PASSWORD>"
```

### Proxmox API token abuse

```bash
# List nodes using a leaked API token
curl -k -H "Authorization: PVEAPIToken=root@pam!tokenid=secret" \
  https://<proxmox>:8006/api2/json/nodes
```

### SCVMM service account discovery

```powershell
# Check SCVMM service account
Get-SCVMMServer | Select-Object -Property VMHostGroup, UserRole
```

### CI/CD pipeline credential extraction

```bash
# Check environment variables in a compromised CI runner
env | grep -i "vcenter\|proxmox\|scvmm\|api_token"
```

## 5. Post-Exploitation

- **Full cluster control:** from vCenter or Proxmox cluster, create, delete, or snapshot any VM.
- **Data exfiltration:** download VMDK or VMA files from any datastore.
- **Lateral movement:** deploy a new VM with a reverse shell on the management network.
- **Persistence:** create a new SSO user with administrative privileges.

## 6. Preventive Controls (Defensive)

- **MFA for all management plane access:** vCenter SSO, SCVMM, Proxmox web UI.
- **Least privilege:** service accounts must have the minimum required role. No `administrator@vsphere.local` for daily use.
- **API token restrictions:** short-lived tokens, IP allowlists, and regular rotation.
- **Secrets management:** use HashiCorp Vault, Azure Key Vault, or AWS Secrets Manager for automation credentials. Never hardcode.
- **Network segmentation:** management plane on a dedicated VLAN, with strict firewall rules.
- **Audit logging:** enable vCenter events, Proxmox task logs, and SCVMM audit logs. Forward to SIEM.

## 7. Detection Controls (Defensive)

- **vCenter:** monitor `com.vmware.cis.session` events for failed logins and new sessions from unknown IPs.
- **Proxmox:** monitor `/var/log/pveproxy/access.log` and `/var/log/pve/tasks/`.
- **SCVMM:** monitor Windows Event Log `Microsoft-System Center Virtual Machine Manager`.
- **SIEM correlation:** a new SSO session followed by a VM creation or snapshot is high-fidelity.
- **API monitoring:** alert on `POST /api/vcenter/vm` or `POST /api2/json/nodes/{node}/qemu` from unusual IPs.

## 8. Verification

- Verify MFA is enforced: `vSphere Client -> Administration -> Single Sign On -> Configuration`.
- Check API token restrictions: `vSphere Client -> Administration -> Access Control -> API Tokens`.
- Verify SCVMM service account: `Get-SCVMMServer | Select-Object -Property UserRole`.
- Check Proxmox API token permissions: `pveum token list`.
- Run `nmap` from an untrusted network against the management VLAN; all ports should be filtered.

## 9. OSCP Notes

- OSCP exam scope does not include management plane exploitation directly. However, the management plane is often the highest-value target in a real engagement.
- Document the management plane architecture and recommended controls in the report's "Recommendations" section.

## 10. Production Notes

- **Secret rotation:** rotate vCenter SSO passwords, Proxmox API tokens, and SCVMM service account credentials every 90 days.
- **Automation security:** review Terraform and Ansible playbooks for hardcoded secrets before every deployment.
- **Incident response:** if the management plane is compromised, assume all VMs are compromised. Isolate the management network, rotate all credentials, and rebuild.
- **Compliance:** map management plane controls to CIS Benchmarks and NIST SP 800-53.

## 11. References

- VMware vSphere Security Configuration Guide - https://core.vmware.com/security-configuration-guide
- Proxmox API Tokens - https://pve.proxmox.com/wiki/User_Management#API_Tokens
- Microsoft SCVMM Security - https://learn.microsoft.com/en-us/system-center/vmm/security/
- NIST SP 800-53 - https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- CIS Benchmarks for VMware - https://www.cisecurity.org/cis-benchmarks
