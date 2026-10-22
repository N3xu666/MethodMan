# VM Escape Fundamentals

This file covers the foundational concepts of virtual machine escape: the isolation boundary between guest and host, the attack surface it exposes, and the general categories of escape techniques. It is the entry point for the rest of the VM Escape subcategory.

## 1. Overview

A virtual machine (VM) is an isolated execution environment. The guest OS runs inside a hypervisor-managed container that is supposed to prevent any guest code from affecting the host or other guests. **VM escape** is any technique that breaks this isolation boundary and allows code executing inside a guest to run on the host, access host memory, or attack neighboring VMs.

The escape boundary is implemented by the hypervisor (also called the virtual machine monitor, VMM) together with hardware virtualization extensions (Intel VT-x, AMD-V). Every emulated device, every virtual CPU instruction, and every memory-mapped I/O operation is a potential crossing point that must be validated by the hypervisor.

## 2. Why It Matters

VM escape is a high-impact class of vulnerability. A single guest VM compromise that escalates to a host escape can expose:

- All other VMs on the same hypervisor (multi-tenant cloud, internal virtualization clusters).
- Host credentials, hypervisor management keys, and storage backends.
- The entire virtualization layer, including the ability to create or destroy VMs.

In cloud environments, a successful escape can violate the provider-customer trust boundary. In enterprise environments, it can break the segmentation between production and development workloads that share a hypervisor.

## 3. The Isolation Boundary

The hypervisor provides isolation across four main interfaces.

### 3.1 CPU and Memory

Hardware virtualization extensions (VT-x, AMD-V) create a new privilege level (VMX root / non-root) that separates the hypervisor from the guest. The guest cannot execute privileged instructions directly; they trap to the hypervisor. Memory isolation is enforced by a second-level address translation (Intel EPT, AMD NPT), which maps guest physical addresses to host physical addresses.

An escape in this layer usually involves a bug in the hypervisor's handling of a trapped instruction or a bug in the EPT/NPT management.

### 3.2 Emulated Devices

The guest sees virtual devices (disk controllers, network adapters, USB controllers, video adapters). The hypervisor or a device emulator (e.g., QEMU) handles guest I/O requests. Emulated devices are the largest attack surface for VM escape because they parse untrusted input from the guest.

### 3.3 Paravirtualized Interfaces

Modern hypervisors use paravirtualized drivers (virtio for QEMU/KVM, VMQ for Hyper-V, VMXNET3 for VMware) that reduce emulation overhead by giving the guest a direct shared-memory interface. A bug in the guest driver or in the host-side backend of these interfaces can allow a malicious guest to corrupt host memory.

### 3.4 Management Interfaces

The hypervisor exposes management APIs (libvirt, VMware vSphere API, Hyper-V WMI) used by administrators to create, configure, and manage VMs. A management interface bug is not a "classic" VM escape but it allows a guest with control over its own configuration (via a compromised management agent) to escalate.

## 4. Attack Surface Map

| Surface | Examples | Typical Bugs |
|---------|----------|--------------|
| CPU/memory | Instruction emulation, EPT/NPT | Out-of-bounds in shadow paging, unvalidated MSRs |
| Emulated devices | QEMU disk, network, USB, VGA | Heap overflow in device model, use-after-free |
| Paravirtual drivers | virtio, VMQ, VMXNET3 | Integer overflow in descriptor parsing |
| Management | libvirt, vCenter API, Hyper-V WMI | Auth bypass, privilege escalation in API handler |

## 5. Categories of Escape Techniques

- **Device model exploitation:** a buffer overflow or use-after-free in an emulated device (QEMU, VMware SVGA) leads to guest-to-host code execution.
- **Hypervisor kernel bugs:** a bug in the hypervisor itself (KVM module, VMware VMkernel, Hyper-V) is triggered by a guest action (specific instruction, MSR, or timing).
- **Paravirtualized driver abuse:** guest crafts malicious descriptors or shared-memory contents that the host-side backend processes incorrectly.
- **Container escape:** a process inside a container breaks out to the host kernel (e.g., via a privileged container, kernel bug, or mounted host path).
- **Sandbox escape:** a process inside an application sandbox (browser, PDF reader) escapes to the OS.

This subcategory covers the first four; sandbox escapes are covered in file 05.

## 6. Common Attack Vector Details

### 6.1 QEMU Device Emulation

QEMU emulates many devices. Each device has a model in `hw/` that parses guest requests. A common pattern is an unchecked length or index from the guest leading to an out-of-bounds write in the host process. Since QEMU usually runs as a user-space process, the immediate impact is code execution in the QEMU process context, which then needs a second stage to reach the host kernel.

### 6.2 KVM Kernel Module

KVM is a Linux kernel module. A bug in KVM (e.g., in the handling of nested virtualization, MMIO, or MSR) is triggered by a guest instruction and executes in kernel context on the host. This is a direct kernel-level escape.

### 6.3 VMware VMkernel

VMware ESXi runs a proprietary kernel (VMkernel). Escapes target the VMkernel's device emulation (SVGA, PVSCSI, E1000) or the hypervisor's handling of specific VM instructions.

### 6.4 Hyper-V

Hyper-V runs as a root partition (the host OS). Escapes target the VMBus (paravirtual bus) or the emulated devices exposed to a guest. A bug in the host-side VMBus handler is a direct host kernel issue.

## 7. Defensive Controls

- **Minimize the attack surface:** remove unused devices from VM configuration, disable legacy emulation.
- **Hardware-assisted isolation:** enable IOMMU (VT-d, AMD-Vi) and interrupt remapping to confine device DMA.
- **Microsegmentation:** ensure VMs that share a hypervisor are not in the same trust zone.
- **Patching:** hypervisor and device emulator patches are critical; escapes are often fixed in QEMU, KVM, VMware, and Hyper-V separately.
- **Introspection:** use hypervisor-level introspection (e.g., libvmi) to monitor guest behavior for anomalous device access.

## 8. Detection Controls

- **Device access anomalies:** unexpected reads/writes to device registers or MMIO regions that are normally unused.
- **Hypervisor logs:** KVM, VMware VMkernel, and Hyper-V log guest faults; a guest triggering the same fault repeatedly is suspicious.
- **Host intrusion detection:** monitor the QEMU process for unexpected `execve`, memory mapping changes, or network connections from the host process.
- **Integrity monitoring:** verify the hypervisor binary and QEMU device model binaries against known-good hashes.

## 9. Verification

To confirm that isolation is working as expected:

- From inside a guest, attempt to read a host physical address via a guest driver; it should fault.
- Inspect the hypervisor logs after a guest crash; a crash in a device model or hypervisor is a signal to investigate.
- Use a lab hypervisor with a known vulnerable device model (e.g., an older QEMU version) and confirm that a PoC triggers the expected error.

## 10. Production Notes

- In production, VM escape is rare but high-impact; assume breach of the hypervisor if a guest is compromised and shared with sensitive workloads.
- Escape attempts are often part of a multi-stage attack: initial access in a guest, credential theft, then escape to the host.
- Do not run untrusted guests on the same hypervisor as high-value workloads unless strong isolation (dedicated host, hardware partitioning) is in place.

## 11. References

- QEMU security advisories - https://www.qemu.org/security/
- Linux KVM documentation - https://www.kernel.org/doc/html/latest/virt/kvm/
- VMware Security Advisories - https://www.vmware.com/security/advisories
- Microsoft Hyper-V security documentation - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/security/
- NIST SP 800-125A Security Recommendations for Hypervisor Deployment - https://csrc.nist.gov/publications/detail/sp/800-125a/final
- Intel Virtualization Technology documentation - https://www.intel.com/content/www/us/en/virtualization/virtualization-technology/intel-virtualization-technology.html