# Qubes / Whonix

> [!CAUTION]
> This material is provided for educational purposes, authorized security testing, and personal privacy research only. Do not use any technique or tool described here against systems, networks, or individuals without explicit written authorization. You are solely responsible for complying with all applicable laws in your jurisdiction.

Qubes OS and Whonix are two approaches to the same problem: how to keep multiple identities, activities, and threat models from contaminating each other on the same physical machine. Qubes achieves this through Xen-based compartmentalization; Whonix through a Tor gateway VM that forces all traffic through Tor.

This file is a hands-on operator guide: what Qubes and Whonix protect against, how to install them, how to configure compartmentalization, and where they fail.

## 1. Overview

**Qubes OS** is a security-oriented operating system that uses Xen virtualization to run each activity in a separate VM (called a "qube"). The GUI, the network stack, and the storage are all isolated. Qubes is designed so that a compromise in one qube does not compromise others.

**Whonix** is a two-VM design: a Gateway VM runs Tor and enforces that all traffic from the Workstation VM goes through Tor. Whonix can run on top of Qubes (as a pair of qubes) or as a standalone KVM/VirtualBox setup.

Key properties:

- **Compartmentalization.** Each identity or activity runs in its own VM.
- **Tor by default (Whonix).** Gateway VM forces all traffic through Tor; the Workstation has no direct network access.
- **Disposable VMs (DispVM).** Qubes supports VMs that are wiped on shutdown, ideal for opening untrusted files.
- **Template-based VMs.** Qubes uses shared templates for OS files, reducing attack surface and update burden.
- **Inter-VM clipboard and file transfer controls.** Copy/paste and file copy between qubes are user-controlled and can be disabled.
- **Qubes-Whonix.** The recommended way to use Whonix: Gateway and Workstation as separate qubes, with `sys-whonix` as the gateway.
- **Hardware requirements.** Qubes needs serious hardware: 16 GB RAM minimum, 32 GB recommended, a CPU with VT-x/AMD-V and VT-d/IOMMU.

Qubes/Whonix is the strongest available model for keeping multiple identities separate on one machine. It is also the most demanding: hardware requirements, learning curve, and operational discipline are all high.

## 2. Threat Model

What Qubes/Whonix protects against:

- **Cross-identity contamination.** A compromise in one qube cannot read another qube's data.
- **Cross-activity contamination.** Personal, work, and anonymous activities are in separate qubes.
- **IP leaks (Whonix).** All traffic is forced through Tor; direct connections are blocked.
- **Malicious attachments.** Open them in a DispVM, which is wiped after use.
- **Compromised applications.** Each app runs in its own qube.
- **Physical theft (with full-disk encryption).** Qubes supports LUKS full-disk encryption by default.
- **Targeted malware.** The compartmentalization limits the blast radius.
- **Network-level IP correlation (Whonix).** Tor is enforced.

What Qubes/Whonix does NOT protect against:

- **Firmware implants.** A compromised BIOS/UEFI or Intel ME/AMD PSP can compromise Qubes before it starts.
- **Hardware implants.** Hardware keyloggers and physical DMA attacks (Thunderbolt, PCIe) are out of scope.
- **Xen hypervisor escapes.** Xen has had CVEs. Qubes tracks them closely, but the hypervisor is a single point of failure.
- **Physical access.** An attacker with physical access can tamper with the machine.
- **Global passive adversary.** Tor does not protect against a global adversary.
- **User error.** A user who copies a sensitive file to the wrong qube defeats the model.
- **Endpoint compromise within a qube.** Malware inside a qube can still act within that qube.
- **Side channels.** Timing, cache, and power side channels can leak across VMs.
- **USB attacks.** Qubes uses `sys-usb` to isolate USB, but a malicious USB device can still cause damage.

Threat model summary:

| Adversary | Qubes / Whonix |
|-----------|----------------|
| Cross-identity contamination | Strong |
| Malicious attachment | Strong (DispVM) |
| IP leaks | Strong (Whonix) |
| Firmware implant | None |
| Hardware keylogger | None |
| Xen hypervisor escape | Weak (depends on Xen CVE) |
| Global passive adversary | Weak (Tor limits) |
| Physical coercion | None |

## 3. How It Works (technical)

**Qubes OS:**

- The base system is a Xen hypervisor with a minimal dom0 (the admin VM).
- `dom0` has no network access and runs only the GUI and the admin tools.
- The network stack is in a separate qube (`sys-net`), and USB is in `sys-usb`.
- Each qube is a Xen VM. Templates (e.g. `fedora-38`, `debian-12`) provide the read-only OS files; app qubes share the template and store only user data.
- DispVMs are created from a template on demand and destroyed on shutdown.
- Inter-qube communication goes through `qrexec`, which is policy-controlled (`/etc/qubes-rpc/policy/`).

**Whonix:**

- Gateway VM runs Tor and has two network interfaces: one to the outside, one to the Workstation.
- Workstation VM has no direct network access; all its traffic goes through the Gateway.
- The Gateway enforces that no traffic leaves except through Tor. Leaks are blocked at the firewall.
- Whonix also provides `whonix-ws` (Workstation) and `whonix-gw` (Gateway) templates for Qubes.

**Qubes-Whonix integration:**

- `sys-whonix` is the Gateway qube.
- `anon-whonix` is the Workstation qube.
- Tor Browser runs in `anon-whonix`.
- Other qubes can be configured to route through `sys-whonix` if desired.

**Storage:**

- Qubes uses LVM with LUKS by default.
- Each qube has its own private volume (encrypted).
- Templates are shared read-only.

**Updates:**

- dom0 and templates are updated separately.
- Qubes provides a "Qubes Update" tool that handles both.

## 4. Installation and Setup

**Hardware requirements:**

- CPU: 64-bit Intel or AMD with VT-x/AMD-V and VT-d/IOMMU (check the HCL: https://www.qubes-os.org/hcl/).
- RAM: 16 GB minimum, 32 GB recommended.
- Storage: 128 GB SSD minimum, 256 GB+ recommended.
- Graphics: Intel integrated is best-supported; NVIDIA is problematic.
- Networking: Intel Wi-Fi and Ethernet are best-supported.

**Installation:**

1. Download the Qubes ISO and verify the signature (Qubes uses a signing key; verify per their docs).
2. Write the ISO to a USB stick (`dd` on Linux, balenaEtcher on Windows/macOS).
3. Boot from the USB. Enable VT-x/AMD-V and VT-d/IOMMU in BIOS/UEFI.
4. Follow the installer. Choose LUKS full-disk encryption with a strong passphrase.
5. After install, run `sudo qubes-dom0-update` to update dom0.
6. Update templates via Qubes Update.

**Whonix on Qubes (recommended path):**

```bash
# In dom0
sudo qubes-dom0-update qubes-template-whonix-gw-16 qubes-template-whonix-ws-16
```

Then create the Gateway and Workstation qubes via Qube Manager, using the Whonix templates.

**Standalone Whonix (KVM):**

- Download the Whonix Gateway and Workstation images from https://www.whonix.org/.
- Import both into KVM (or VirtualBox).
- Start the Gateway, then the Workstation.
- The Workstation routes through the Gateway automatically.

**First-run checklist:**

1. Set up `sys-net`, `sys-firewall`, `sys-usb` (Qubes creates these during install).
2. Create templates and app qubes for each identity/activity.
3. Configure `sys-whonix` as the gateway for the `anon-whonix` qube.
4. Set clipboard and file transfer policies (`/etc/qubes-rpc/policy/`).
5. Test: open Tor Browser in `anon-whonix`, verify Tor exit node.

## 5. Hardening and Configuration

**Qubes hardening:**

- **Disable unnecessary services in dom0.** dom0 should be minimal.
- **Use the Qubes Update tool regularly.** dom0 and templates.
- **Restrict inter-qube communication.** Review `/etc/qubes-rpc/policy/` and remove rules you do not need.
- **Disable clipboard sharing between untrusted qubes.** Qubes has a `qubes.ClipboardPaste` policy.
- **Disable file copy between untrusted qubes.** Similar policy for `qubes.Filecopy`.
- **Use DispVMs for untrusted files.** Open PDFs, images, and documents in a DispVM.
- **Use split-GPG.** Split-GPG moves the GPG private key to a dedicated qube, so a compromised app qube cannot steal it.
- **Use split-USB.** Qubes already isolates USB via `sys-usb`; only attach specific devices to specific qubes.
- **Enable anti-evil-maid (AEM).** AEM measures the boot process and stores a hash; if the boot is tampered with, AEM warns you.
- **Enable UEFI Secure Boot if supported.** Qubes supports UEFI with Secure Boot in recent versions.

**Whonix hardening:**

- **Verify the Tor connection.** Check the Tor Browser's circuit and exit node.
- **Do not install additional software in the Gateway.** The Gateway should be minimal.
- **Keep the Workstation minimal.** Every app is attack surface.
- **Use Tor Browser's "Safest" security level** when possible.
- **Disable JavaScript by default** unless required.
- **Do not use a VPN with Whonix.** Whonix is Tor-only by design; adding a VPN breaks the model.

**Operational hardening:**

- **Compartmentalize by identity.** One qube per identity (personal, work, anonymous).
- **Never copy data from a higher-trust qube to a lower-trust qube.**
- **Use DispVMs for opening files from untrusted sources.**
- **Never mix activities across qubes.**
- **Do not use the same email or username across qubes.**
- **Do not write in your usual style in anonymous qubes.**
- **Verify Tor is working before sensitive operations.**
- **Test the workflow regularly.**

## 6. Operational Usage

**Daily workflow (Qubes-Whonix):**

1. Boot Qubes. Enter the LUKS passphrase.
2. Log in to dom0 (no network).
3. Start `sys-net`, `sys-firewall`, `sys-usb` (or leave them auto-starting).
4. Start `sys-whonix` (Gateway).
5. Start `anon-whonix` (Workstation). Open Tor Browser.
6. Verify Tor is working (check.torproject.org).
7. Do anonymous work.
8. Shutdown `anon-whonix`.

**Creating a new identity:**

1. Clone a template (e.g. `debian-12`).
2. Create a new app qube based on that template.
3. Set its network VM to `sys-whonix` (if anonymized) or `sys-firewall` (if not).
4. Configure its firewall rules (Qubes has a per-qube firewall).
5. Never reuse the qube for a different identity.

**Opening untrusted files:**

1. Right-click -> "Open in Disposable VM".
2. The DispVM is created, the file opens, and the VM is destroyed on close.
3. If the file tries to exfiltrate data, it can only exfiltrate from the DispVM (which has no persistent identity).

**Split-GPG:**

```bash
# In dom0
sudo qubes-dom0-update qubes-gpg-split

# In the GPG qube (e.g. "work-gpg")
# Copy the public key and secret key to ~/.gnupg

# In the app qube (e.g. "work-email")
# Set the GPG split environment
echo "export QUBES_GPG_DOMAIN=work-gpg" >> ~/.bashrc
```

Now GPG operations in `work-email` are executed by `work-gpg`, which holds the private key.

**File transfer between qubes:**

- Use `qvm-copy-to-vm <target-qube> <file>`.
- The target qube sees the file in `~/QubesIncoming/<source-qube>/`.
- Only copy from higher-trust to lower-trust, never the other way.

**Clipboard:**

- Copy from one qube and paste into another is controlled by the `qubes.ClipboardPaste` policy.
- By default, Qubes asks for confirmation. Do not disable this.

## 7. Common Mistakes

Real mistakes that break Qubes/Whonix protections:

1. **Copying sensitive data from an anonymous qube to a personal qube.** This links the two identities.
2. **Using the same email or username in multiple qubes.** Correlation.
3. **Not using DispVMs for untrusted files.** A malicious PDF can compromise the qube.
4. **Disabling clipboard confirmation.** This allows silent data exfiltration.
5. **Installing software in dom0.** dom0 should be minimal; extra software is attack surface.
6. **Using a VPN with Whonix.** Breaks the Tor-only design.
7. **Not using split-GPG.** A compromised app qube can steal the GPG key.
8. **Reusing the same Tor Browser profile across qubes.** Correlation via browser fingerprint.
9. **Not verifying Tor is working before sensitive operations.**
10. **Assuming Xen is unhackable.** Xen has had CVEs; keep Qubes updated.
11. **Not enabling anti-evil-maid.** A tampered boot is undetectable without AEM.
12. **Using a machine with unsupported hardware.** Qubes HCL lists supported hardware; unsupported hardware may leak or malfunction.
13. **Ignoring the HCL.** Qubes is sensitive to hardware; check the HCL before buying.
14. **Running `anon-whonix` and a personal qube at the same time.** Timing correlation is possible if both are active on the same machine.

## 8. Attacks Against It

Known attacks and limitations:

- **Xen hypervisor escapes.** Xen has had CVEs (e.g. CVE-2015-3456 "VENOM", CVE-2022-26306, and others). A successful escape compromises all qubes.
- **Firmware implants.** A compromised BIOS/UEFI or Intel ME/AMD PSP can compromise Qubes before it starts.
- **Hardware implants.** Physical keyloggers, DMA attacks (Thunderbolt, PCIe).
- **Side channels.** Cache timing, power analysis, and electromagnetic leaks can cross VM boundaries.
- **Evil maid attacks.** An attacker with physical access can modify the bootloader (mitigated by AEM).
- **Tor weaknesses.** Whonix relies on Tor; Tor's limitations apply.
- **User error.** The most common failure mode.
- **USB attacks.** A malicious USB device can attack `sys-usb` or the qube it is attached to.
- **Supply chain attacks.** A compromised Qubes update or template can compromise the system.
- **Cross-VM information leaks.** Even without an escape, side channels can leak data.
- **Denial of service.** A compromised qube can cause resource exhaustion on the host.

## 9. Detection (Blue Team)

What a corporate or network defender can see:

- **Hardware-level:** a machine running Qubes looks like a normal machine to the network.
- **Network traffic:** if the user uses Whonix, the traffic is Tor traffic.
- **On a managed device:** Qubes cannot run on a managed device with endpoint agents because it does not use the host OS. Booting from USB (for a Qubes installer) may be logged by the firmware.
- **Physical presence:** in most corporate environments, a user running Qubes on a personal laptop is physically visible.
- **Tor exit nodes:** if the user routes through Tor, the network sees Tor traffic.
- **USB events:** if the user plugs in a Qubes USB, the machine's firmware may log it.

Blocking Qubes/Whonix at the network level is equivalent to blocking Tor, which is a broader policy question.

## 10. Case Studies

- **Qubes and Edward Snowden (2014).** Snowden publicly recommended Qubes OS. His use of Qubes has been widely documented and is the canonical case study for compartmentalization.
- **Qubes and journalists.** Many investigative journalists use Qubes for compartmentalizing sources, personal life, and work.
- **Qubes and the Xen project.** Qubes depends on Xen; Xen CVEs are a real risk. Qubes has a strong record of patching quickly.
- **Whonix and Tor.** Whonix is a Tor-only design; it is used by users who need enforced Tor routing with a strong separation between the Tor process and user applications.
- **Criticism.** Qubes is criticized for its hardware requirements and learning curve. It is not suitable for casual users, and misconfiguration can create new risks.

(These are documented public events; no new attacks are disclosed here.)

## 11. Legal and Ethical Notes

Qubes OS and Whonix are legal to use in most jurisdictions. However:

- **Some countries restrict or ban Tor and anonymization tools.** Check your local law.
- **Using Qubes/Whonix to plan or commit a crime is illegal everywhere.**
- **Corporate policy may forbid booting from USB or running non-standard OSes.** On a managed machine, installing Qubes may violate acceptable-use policy.
- **You are responsible for your contacts' safety.**
- **No tool replaces operational discipline.**
- **Authorized use only.** In a professional context, use Qubes/Whonix only within the scope of an authorized engagement or for your own personal privacy.

## 12. Production Notes

If you are deploying Qubes/Whonix for a small group:

- **Standardize on Qubes + Qubes-Whonix.** The integration is well-tested.
- **Standardize hardware.** Use hardware on the Qubes HCL. Do not improvise.
- **Standardize the qube layout.** Define the templates, app qubes, and their network VMs.
- **Standardize the file transfer policy.** Explicitly define what can be copied where.
- **Standardize the split-GPG setup.**
- **Train users.** Qubes has a steep learning curve. A 2-3 hour training session is a minimum.
- **Define a compromise procedure.** If a qube is compromised, how is it destroyed, and how are other qubes informed?
- **Test the workflow** before relying on it.
- **Monitor the threat model.** Qubes and Whonix evolve; re-evaluate periodically.

## 13. References

- Qubes OS - https://www.qubes-os.org/
- Qubes documentation - https://www.qubes-os.org/doc/
- Qubes HCL (supported hardware) - https://www.qubes-os.org/hcl/
- Whonix - https://www.whonix.org/
- Whonix documentation - https://www.whonix.org/wiki/Documentation
- Qubes-Whonix - https://www.whonix.org/wiki/Qubes
- Xen Project - https://xenproject.org/
- Tor Project - https://www.torproject.org/
- Electronic Frontier Foundation - Surveillance Self-Defense - https://ssd.eff.org/
- Privacy Guides - Operating Systems - https://www.privacyguides.org/en/os/
