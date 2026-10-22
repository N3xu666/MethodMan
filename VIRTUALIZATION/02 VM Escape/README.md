# VM Escape

Escape from a guest virtual machine or sandbox to the host, hypervisor, or neighboring guests. This subcategory covers the attack surface of virtualization platforms (QEMU/KVM, VMware, Hyper-V), container runtimes, and sandboxes, plus the defensive controls that detect and prevent escapes.

## Format

Two-track (Offensive / Defensive). Every file covers both the attack path and the corresponding detection and prevention controls.

## Scope

- Hypervisor and emulator escapes (QEMU, KVM, VirtualBox, VMware, Hyper-V).
- Container escapes (Docker, containerd, runc, Kubernetes node breakout).
- Sandbox escapes (browser sandboxes, application sandboxes, seccomp/AppArmor/SELinux bypass).
- Guest-to-host and guest-to-guest attack paths.
- Detection: hypervisor introspection, syscall anomaly detection, container runtime monitoring.

## Files

| # | File | Format |
|---|------|--------|
| 01 | [VM Escape Fundamentals](./01%20VM%20Escape%20Fundamentals.md) | Two-track |
| 02 | [QEMU and KVM Escapes](./02%20QEMU%20and%20KVM%20Escapes.md) | Two-track |
| 03 | [VMware and Hyper-V Escapes](./03%20VMware%20and%20Hyper-V%20Escapes.md) | Two-track |
| 04 | [Container Escape Techniques](./04%20Container%20Escape%20Techniques.md) | Two-track |
| 05 | [Sandbox Evasion and Detection](./05%20Sandbox%20Evasion%20and%20Detection.md) | Two-track |

## Certification Alignment

- Offensive Security: OSCP (privilege escalation context), OSEP (evasion).
- Vendor: VMware VCP-DCV, Microsoft AZ-800/AZ-801 (Hyper-V security context).
- Cloud: CKA/CKS (container escape, node breakout).

## References

- QEMU security advisories - https://www.qemu.org/security/
- Linux kernel KVM documentation - https://www.kernel.org/doc/html/latest/virt/kvm/
- VMware Security Advisories - https://www.vmware.com/security/advisories
- Microsoft Hyper-V security documentation - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/security/
- OWASP Container Security Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- NIST SP 800-190 Application Container Security Guide - https://csrc.nist.gov/publications/detail/sp/800-190/final