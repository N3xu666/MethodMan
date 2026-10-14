# Linux Infrastructure

Offensive and defensive reference for Linux hosts: permissions model,
enumeration, local privilege escalation, container escapes, credential
discovery, and persistence. This subcategory covers standalone and
enterprise Linux systems (servers, workstations, containers).

This subcategory uses the two-track format (Offensive / Defensive). See
the parent [INFRASTRUCTURE README](../README.md) for the format skeleton.

## Files

| # | File | Focus |
|---|------|-------|
| 01 | [Linux Fundamentals](./01%20Linux%20Fundamentals.md) | Permissions, SUID/SGID, capabilities, systemd, kernel, namespaces |
| 02 | [Enumeration and Misconfigurations](./02%20Enumeration%20and%20Misconfigurations.md) | linPEAS, LinEnum, pspy, configs, cron, sudoers |
| 03 | [Local Privilege Escalation](./03%20Local%20Privilege%20Escalation.md) | SUID/SGID, sudo, capabilities, cron, PATH, kernel exploits |
| 04 | [Container and Namespace Escapes](./04%20Container%20and%20Namespace%20Escapes.md) | Docker, LXC, host mounts, privileged containers, Kubernetes basics |
| 05 | [Credentials and Secret Discovery](./05%20Credentials%20and%20Secret%20Discovery.md) | SSH keys, history, env vars, configs, agent forwarding |
| 06 | [Persistence and Defense](./06%20Persistence%20and%20Defense.md) | cron, systemd, SSH keys, PAM, auditd, hardening |

## Scope

**In scope:**

- Linux servers (RHEL/CentOS/Rocky, Debian/Ubuntu, SUSE, Alpine).
- Linux workstations.
- Containerized workloads (Docker, Podman, LXC/LXD).
- Kubernetes nodes and pods (attack surface from a compromised pod).
- Standalone and domain-joined Linux (SSSD, Winbind) - host-level attacks.

**Out of scope:**

- Active Directory attacks from Linux (Kerberos tooling on Linux) - see
  `01 Active Directory`.
- Cloud-hosted Linux (AWS EC2, Azure VM, GCP CE specific features) -
  see the CLOUD category.
- Hypervisor-level escapes - see the VIRTUALIZATION category.

## Related Resources

- [MITRE ATT&CK - Enterprise: Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
- [MITRE ATT&CK - Enterprise: Persistence](https://attack.mitre.org/tactics/TA0003/)
- [GTFOBins](https://gtfobins.github.io/) - Unix binaries abuse reference
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [PayloadsAllTheThings - Linux Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)