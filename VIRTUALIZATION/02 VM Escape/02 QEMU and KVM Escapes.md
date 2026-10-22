# QEMU and KVM Escapes

This file covers escape techniques against QEMU (the device emulator) and KVM (the Linux kernel hypervisor module), the dominant open-source virtualization stack. QEMU handles device emulation and runs as a user-space process on the host; KVM provides CPU and memory virtualization in the host kernel. A bug in either component can allow a guest to execute code on the host.

## 1. Overview

The QEMU/KVM stack has two distinct escape surfaces:

- **QEMU user-space process** - emulates disk, network, USB, VGA, and other devices. A malicious guest can send crafted I/O requests that trigger memory corruption in the QEMU process. Escaping QEMU gives code execution in the context of the QEMU process on the host (usually `qemu-system-x86_64`, often running as `libvirt-qemu` or `root`).
- **KVM kernel module** - handles VM entry/exit, memory-mapped I/O, MSR access, and interrupt injection. A bug in KVM is triggered by a guest instruction and executes in kernel context on the host. This is a direct kernel-level escape.

Both surfaces are attractive to attackers because a compromised guest VM (e.g., a multi-tenant cloud instance) can attempt to break out to the host and attack other tenants or the cloud control plane.

## 2. QEMU Device Emulation Attack Surface

QEMU emulates dozens of devices. Each device model parses untrusted input from the guest. Common vulnerable device models include:

- **Disk controllers:** IDE, AHCI, SCSI (virtio-scsi, LSI), NVMe.
- **Network adapters:** e1000, e1000e, rtl8139, virtio-net.
- **USB controllers:** UHCI, EHCI, xHCI.
- **Video adapters:** VGA, VMware SVGA, QXL.
- **Serial/parallel ports:** 16550 UART, parallel port.
- **Other:** fw_cfg, ACPI, PCI config space.

A typical QEMU escape bug is an out-of-bounds write in a device model handler. The guest sends a request with a crafted length or index, QEMU fails to validate it, and writes attacker-controlled data past the end of a heap buffer. This can lead to code execution in the QEMU process.

## 3. KVM Kernel Attack Surface

KVM is a Linux kernel module (`kvm.ko`, `kvm-intel.ko`, `kvm-amd.ko`). The guest can trigger KVM code paths by:

- Executing privileged instructions (e.g., `CPUID`, `RDMSR`, `WRMSR`, `IN`/`OUT`).
- Accessing MMIO regions that trap to KVM.
- Triggering VM exits (e.g., EPT violations, interrupt window).
- Using nested virtualization (if enabled).

A bug in KVM's handling of these events can lead to kernel memory corruption on the host. Examples include:

- Unvalidated MSR values causing out-of-bounds access in KVM's MSR bitmap.
- Incorrect handling of nested VM exits leading to use-after-free.
- Integer overflow in MMIO instruction decoding.

## 4. Common Attack Vectors

### 4.1 Device Model Heap Overflow

The guest sends a crafted request to an emulated device (e.g., a disk write with an oversized sector count). QEMU fails to validate the length and overflows a heap buffer. The attacker controls the overflow data and can overwrite adjacent heap objects, potentially leading to code execution.

### 4.2 Use-After-Free in Device Hotplug

The guest triggers a device unplug event while an I/O operation is in progress. QEMU frees the device state but a subsequent operation uses the freed pointer. This can lead to arbitrary write or code execution.

### 4.3 Virtio Descriptor Chain Abuse

Virtio devices use descriptor chains in shared memory. A malicious guest can craft a descriptor chain with loops or invalid addresses. If the host-side virtio backend does not validate the chain correctly, it can read/write arbitrary host memory.

### 4.4 KVM MSR Handling

The guest executes `WRMSR` with a crafted value. KVM's MSR handling code fails to validate the value, leading to an out-of-bounds write in a kernel data structure. This is a direct kernel escape.

## 5. Exploitation Recipes

### 5.1 Triggering a QEMU Device Bug

```bash
# Inside the guest, send a crafted request to the emulated device.
# Example: overflow the e1000 receive descriptor ring.
# (PoC code would be specific to the CVE.)
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
# (no output - the bug is triggered, QEMU may crash or the guest may hang)
```

### 5.2 Escaping QEMU Process Context

Once code execution is achieved in the QEMU process, the attacker can:

- Read host files accessible to the QEMU user (e.g., `/etc/passwd`, SSH keys).
- Access other VM disk images if permissions allow.
- Attempt to escalate to root if QEMU runs as root (common in some configurations).
- Pivot to the host network.

## 6. Defensive Controls

- **Run QEMU as an unprivileged user** (`libvirt-qemu`, `qemu`), not as root.
- **Use sVirt / SELinux / AppArmor** to confine the QEMU process.
- **Disable unused devices** in the VM configuration (`-nodefaults`, remove USB/VGA if not needed).
- **Enable KVM hardening** (e.g., `kvm.nx_huge_pages`, `kvm-intel.ept=1`).
- **Patch QEMU and KVM promptly**; most escape bugs are fixed in stable releases.
- **Use hardware-assisted isolation** (IOMMU, VT-d) to confine device DMA.

## 7. Detection Controls

- **Monitor QEMU process behavior:** unexpected `execve`, `mmap` with `PROT_EXEC`, outbound network connections from the QEMU process.
- **KVM tracepoints:** `kvm_exit`, `kvm_msr`, `kvm_mmio` events can reveal unusual guest behavior.
- **Crash analysis:** a QEMU segfault or KVM oops triggered by a guest is a strong signal of an escape attempt.
- **Integrity monitoring:** verify the QEMU binary and KVM module hashes.

## 8. Verification

To verify isolation:

- Run a QEMU VM with an old, known-vulnerable device model and confirm the PoC triggers a crash in the QEMU process (not the guest).
- Check that QEMU runs as an unprivileged user: `ps aux | grep qemu`.
- Confirm SELinux/AppArmor confinement: `sestatus`, `aa-status`.

## 9. Production Notes

- In cloud environments, QEMU/KVM escapes are rare but catastrophic; assume host compromise if a guest is malicious.
- Use dedicated hosts for high-value tenants, or strong isolation (confidential computing, hardware partitioning).
- Monitor for guest-triggered QEMU crashes; they are often the first sign of an escape attempt.

## 10. References

- QEMU security advisories - https://www.qemu.org/security/
- Linux KVM documentation - https://www.kernel.org/doc/html/latest/virt/kvm/
- CVE-2019-14378 (QEMU SLiRP heap overflow) - https://nvd.nist.gov/vuln/detail/CVE-2019-14378
- CVE-2020-14364 (QEMU USB out-of-bounds) - https://nvd.nist.gov/vuln/detail/CVE-2020-14364
- CVE-2021-3750 (KVM nested virtualization UAF) - https://nvd.nist.gov/vuln/detail/CVE-2021-3750
- NIST SP 800-125A - https://csrc.nist.gov/publications/detail/sp/800-125a/final