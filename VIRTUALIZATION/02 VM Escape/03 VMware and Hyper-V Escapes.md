# VMware and Hyper-V Escapes

This file covers escape techniques against the two dominant commercial hypervisors: VMware ESXi and Microsoft Hyper-V. Unlike the open-source QEMU/KVM stack, these hypervisors run proprietary kernels and have a smaller but still significant attack surface. Escapes here often target proprietary device emulation, paravirtual buses, or the hypervisor's management plane.

## 1. Overview

VMware ESXi and Microsoft Hyper-V are widely deployed in enterprise data centers and private clouds. Their escape surfaces differ from QEMU/KVM:

- **VMware ESXi** - uses the proprietary VMkernel. Attack surface includes emulated devices (SVGA, PVSCSI, E1000), the VMX process (user-space), and the vSphere management API.
- **Microsoft Hyper-V** - runs as a root partition (the host OS). Attack surface includes the VMBus (paravirtual bus), emulated devices, and the Hyper-V management interfaces (WMI, PowerShell Direct).

A successful escape on either platform can compromise all VMs on the host and the hypervisor management plane.

## 2. VMware ESXi Attack Surface

### 2.1 Emulated Devices

ESXi emulates devices for VMs. Common vulnerable models include:

- **SVGA** - virtual video adapter. A crafted SVGA command from the guest can trigger out-of-bounds writes in the VMX process or VMkernel.
- **PVSCSI** - paravirtual SCSI controller. Malformed requests can trigger heap overflows.
- **E1000/E1000E** - network adapters. Descriptor ring manipulation can lead to memory corruption.

### 2.2 VMX Process

The VMX process is a user-space process that manages each VM. A bug in the VMX process (e.g., in device emulation or RPC handling) can lead to code execution as the VMX process user, which may then escalate to the VMkernel.

### 2.3 vSphere Management API

The vSphere API (SOAP/REST) is used by vCenter to manage ESXi hosts. A vulnerability in the API handler (e.g., unauthenticated RCE in vCenter) can give an attacker control over the entire virtualization cluster. This is not a classic guest-to-host escape but is often the first step in a broader attack.

## 3. Hyper-V Attack Surface

### 3.1 VMBus

Hyper-V uses VMBus as a paravirtual bus for communication between the guest and the host (root partition). VMBus channels are implemented via shared memory. A bug in the host-side VMBus handler (e.g., in `vmbus.sys` or `vmbkmcl.sys`) can be triggered by a malicious guest and lead to host kernel code execution.

### 3.2 Emulated Devices

Hyper-V emulates legacy devices for compatibility. Vulnerable models include:

- **Synthetic video** - Hyper-V's video adapter.
- **Synthetic network adapter** - VMQ/vRSS handling.
- **IDE/SCSI controllers** - legacy emulation.

### 3.3 Management Interfaces

Hyper-V exposes WMI and PowerShell Direct for management. A vulnerability in these interfaces can allow a guest with admin access to its own VM to execute code on the host.

## 4. Common Attack Vectors

### 4.1 VMware SVGA Heap Overflow

The guest sends a crafted SVGA command (e.g., a `SVGA_CMD_DEFINE_GB_SURFACE` with an oversized size). The VMX process fails to validate the size, leading to a heap overflow. Exploitation can lead to code execution in the VMX process.

### 4.2 VMware PVSCSI Use-After-Free

The guest issues a SCSI command that triggers a race condition in the PVSCSI driver. The driver frees a request object while it is still referenced, leading to a use-after-free. This can be exploited for arbitrary write or code execution.

### 4.3 Hyper-V VMBus Message Handling

The guest sends a crafted VMBus message (e.g., a malformed channel offer or a GPADL request). The host-side VMBus handler processes the message without proper validation, leading to memory corruption in the root partition kernel.

### 4.4 Hyper-V Nested Virtualization

If nested virtualization is enabled, a guest hypervisor can trigger complex VM exit paths that may contain bugs in the host Hyper-V implementation.

## 5. Exploitation Recipes

### 5.1 Triggering a VMware SVGA Bug

```bash
# Inside the VMware guest, send a crafted SVGA command.
# (PoC code is specific to the CVE and requires a VMware Tools driver interface.)
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
# (no output - the bug is triggered, the VMX process may crash)
```

### 5.2 Triggering a Hyper-V VMBus Bug

```powershell
# Inside the Hyper-V guest, use PowerShell to send a crafted VMBus message.
# (Requires a custom driver or a known exploit tool.)
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
# (no output - the host may bugcheck or log an error in the Hyper-V-Worker event log)
```

## 6. Defensive Controls

- **Keep ESXi and Hyper-V patched.** Both vendors release security updates for escape vulnerabilities.
- **Minimize the attack surface.** Disable unused devices (e.g., remove floppy/CD-ROM, disable 3D acceleration if not needed).
- **Use vSphere Trust Authority / Hyper-V guarded fabric** to protect the hypervisor from compromised management plane.
- **Enable IOMMU (VT-d/AMD-Vi)** to confine device DMA.
- **Segment management networks.** vCenter and Hyper-V management interfaces should not be reachable from guest networks.

## 7. Detection Controls

- **Monitor VMX/VMworker processes** for unexpected behavior (crash, high CPU, network connections).
- **Hyper-V event logs** - check for `Hyper-V-Worker` errors related to VMBus or device emulation.
- **vSphere logs** - check `vmkernel.log` and `vmx.log` for guest-triggered faults.
- **Integrity monitoring** - verify hypervisor and VMX binary hashes.

## 8. Verification

To verify isolation:

- Run a VM with an old, known-vulnerable device model and confirm the PoC triggers a crash in the hypervisor process (not the guest).
- Check that ESXi runs with the latest patches: `esxcli software vib list | grep -i update`.
- Check Hyper-V patch level: `Get-HotFix` in the root partition.

## 9. Production Notes

- In enterprise environments, a hypervisor escape can lead to full data center compromise.
- Use dedicated hosts for high-value tenants, or strong isolation (confidential computing on supported hardware).
- Monitor for guest-triggered hypervisor crashes; they are a strong indicator of an escape attempt.

## 10. References

- VMware Security Advisories - https://www.vmware.com/security/advisories
- Microsoft Hyper-V security documentation - https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/security/
- CVE-2020-3952 (VMware vCenter Server auth bypass) - https://nvd.nist.gov/vuln/detail/CVE-2020-3952
- CVE-2021-21985 (VMware vCenter RCE) - https://nvd.nist.gov/vuln/detail/CVE-2021-21985
- CVE-2024-37085 (VMware ESXi auth bypass) - https://nvd.nist.gov/vuln/detail/CVE-2024-37085
- CVE-2021-28476 (Hyper-V VMBus RCE) - https://nvd.nist.gov/vuln/detail/CVE-2021-28476
- NIST SP 800-125A - https://csrc.nist.gov/publications/detail/sp/800-125a/final