# Data Destruction

> [!CAUTION]
> This material is provided for educational purposes, authorized security testing, and personal privacy research only. Do not use any technique or tool described here against systems, networks, or individuals without explicit written authorization. You are solely responsible for complying with all applicable laws in your jurisdiction.

"Deleting" a file does not remove it. On a hard disk, the data remains until it is overwritten; on an SSD, wear leveling makes guaranteed deletion almost impossible from the OS. This file covers the practical reality of secure deletion, the tools that work, and the cases where no tool can help.

This file is a hands-on operator guide: what data destruction protects against, how to wipe HDDs and SSDs, and where the limits are.

## 1. Overview

Data destruction is the practice of making data unrecoverable. It applies to:

- **Files you delete.** Emptying the recycle bin does not delete the data.
- **Disks before disposal or resale.** A used SSD or HDD often contains recoverable data.
- **Files in the cloud.** Deleting from a synced folder may leave copies on the provider's servers and in backups.
- **Swap and hibernation files.** These can contain plaintext from memory.
- **RAM.** Cold boot attacks can recover RAM after a short power-off.

Key principles:

- **Overwrite, do not delete.** On HDDs, overwriting with random data makes recovery infeasible.
- **SSDs are different.** Wear leveling means the OS cannot guarantee which physical cells are overwritten.
- **Full-disk encryption changes the game.** If the disk is encrypted, destroying the key destroys the data.
- **Crypto-shredding.** Deleting (and securely wiping) the encryption key makes the ciphertext useless.
- **The cloud is out of your control.** You cannot wipe a provider's backups.

## 2. Threat Model

What data destruction protects against:

- **Casual forensic recovery.** Tools like Recuva, PhotoRec, and TestDisk can recover "deleted" files on HDDs. Overwriting prevents this.
- **Resale and disposal.** A wiped disk does not leak your data to the buyer.
- **Physical theft (with FDE).** With full-disk encryption, a stolen disk is useless without the key.
- **Crypto-shredding.** Destroying the encryption key is fast and effective, even on SSDs.

What data destruction does NOT protect against:

- **Cloud copies.** If data is in Google Drive, iCloud, or any sync service, you cannot wipe the provider's copies.
- **Backups you forgot about.** External drives, NAS, and old USB sticks.
- **SSD wear leveling.** The OS cannot guarantee that every physical cell is overwritten.
- **Already-leaked data.** If the data has been copied, wiping the original does not help.
- **Cold boot attacks.** RAM contents can survive a short power-off.
- **Firmware-level persistence.** Malware in firmware survives disk wipes.
- **Snapshots and copy-on-write filesystems.** ZFS, Btrfs, APFS keep snapshots that may contain old data.
- **Journaling filesystems.** Journals may contain fragments of old data.
- **Legal hold.** If you are under a legal obligation to preserve data, wiping it is a crime (spoliation).

Threat model summary:

| Adversary | HDD wipe | SSD wipe | FDE + key destruction |
|-----------|----------|----------|-----------------------|
| Casual recovery | Strong | Weak | Strong |
| Forensic recovery | Strong | Partial | Strong |
| Resale/disposal | Strong | Partial | Strong |
| Cloud provider | None | None | None |
| Legal hold | N/A (illegal) | N/A (illegal) | N/A (illegal) |

## 3. How It Works (technical)

**HDD (magnetic):**

- Data is stored in magnetic domains on a spinning platter.
- Overwriting with random data replaces the magnetic pattern.
- A single pass of random data is sufficient on modern HDDs (multi-pass methods like DoD 5220.22-M and Gutmann are legacy; they were designed for older drives).
- Bad sectors may retain data and are not overwritten.

**SSD (NAND flash):**

- Data is stored in NAND cells, managed by a Flash Translation Layer (FTL).
- Wear leveling spreads writes across cells, so overwriting a logical block does not touch the same physical cells.
- The OS cannot address physical cells directly.
- ATA Secure Erase and NVMe Format are the only reliable ways to wipe an SSD at the firmware level.
- Even then, over-provisioned cells and bad blocks may retain data.

**Full-disk encryption (FDE):**

- The disk is encrypted with a master key; the master key is encrypted with your passphrase.
- Destroying the master key makes all data unrecoverable, even if the ciphertext remains.
- This is called "crypto-shredding" and is the fastest reliable method.
- On SSDs, crypto-shredding is the only practical way to guarantee destruction.

**Filesystem caveats:**

- **Journaling (ext4, NTFS).** The journal may contain fragments of deleted files.
- **Copy-on-write (ZFS, Btrfs, APFS).** Snapshots and copy-on-write may preserve old versions.
- **TRIM (SSD).** TRIM tells the SSD which blocks are free, but the SSD decides when to erase them.
- **Swap and hibernation.** Contain memory contents, including plaintext.

## 4. Installation and Setup

**Tools:**

- **`shred`** (coreutils, Linux) - overwrites a file with random data.
- **`wipe`** - secure file deletion, with more options than `shred`.
- **`dd`** - disk-level overwrite.
- **`hdparm`** - ATA Secure Erase for HDDs and SSDs.
- **`nvme`** - NVMe Format and Sanitize for NVMe SSDs.
- **`blkdiscard`** - discard all blocks on a device (SSD-only).
- **`cryptsetup`** - LUKS encryption; `cryptsetup erase` destroys the LUKS header.
- **`srm`** (macOS) - secure remove, deprecated since macOS 10.13 due to APFS/SSD limitations.
- **`Eraser`** (Windows) - GUI for secure deletion; works on HDDs, limited on SSDs.
- **`DBAN`** - bootable disk wiper; HDD-only, does not work reliably on SSDs.
- **`nwipe`** - open-source fork of DBAN.

**Install (Debian/Ubuntu):**

```bash
sudo apt install secure-delete hdparm nvme-cli cryptsetup
```

**Install (Fedora):**

```bash
sudo dnf install secure-delete hdparm nvme-cli cryptsetup
```

**Install (Arch):**

```bash
sudo pacman -S secure-delete hdparm nvme-cli cryptsetup
```

## 5. Hardening and Configuration

**Full-disk encryption from the start:**

- Enable LUKS (Linux), FileVault (macOS), BitLocker (Windows), or the default FDE on mobile OSes.
- Use a strong passphrase (Diceware, 6+ words).
- Store a recovery key offline.
- Without FDE, wiping an SSD is unreliable. With FDE, crypto-shredding is trivial.

**Swap and hibernation:**

- **Linux:** use an encrypted swap (LUKS) or a swap file inside the encrypted root.
- **Windows:** BitLocker covers hibernation if enabled.
- **macOS:** FileVault covers swap.
- Without encryption, swap and hibernation files may contain plaintext.

**Filesystem configuration:**

- **Disable journaling on sensitive partitions** if the threat model requires it (rare; usually the performance and reliability cost is not worth it).
- **Disable copy-on-write snapshots** for sensitive data, or wipe snapshots explicitly.
- **Use TRIM on SSDs** to allow the SSD to erase free cells early. But TRIM itself is a metadata leak (it reveals which blocks are free).

**Browser and app caches:**

- Clear browser caches, history, and cookies regularly.
- Use private/incognito mode where appropriate.
- Disable disk cache in browsers if the threat model requires it.

**RAM:**

- On shutdown, RAM is cleared by the OS.
- Tails wipes RAM explicitly (`sdmem`).
- For cold boot resistance, power off and wait (RAM decays over seconds to minutes at room temperature).

**Cloud and sync:**

- Do not store sensitive data in cloud-synced folders.
- If you must, use client-side encryption (Cryptomator, rclone with encryption, gocryptfs).
- Remember: you cannot wipe the provider's backups.

## 6. Operational Usage

**Wipe a single file (HDD or encrypted SSD):**

```bash
shred -u -n 3 -z file.txt
# -u: remove the file after overwriting
# -n 3: 3 passes of random data
# -z: final pass of zeros (hides the shred)
```

**Wipe a directory:**

```bash
find /path/to/dir -type f -exec shred -u -n 3 -z {} \;
rm -rf /path/to/dir
```

**Wipe free space on an HDD:**

```bash
# Fill the disk with random data, then delete the file
dd if=/dev/urandom of=/path/to/wipefile bs=1M status=progress
rm /path/to/wipefile
```

On an SSD, this does nothing useful (wear leveling).

**Secure Erase an SSD (ATA):**

```bash
# DANGER: wipes the entire disk
sudo hdparm --user-master u --security-set-pass p /dev/sdX
sudo hdparm --user-master u --security-erase p /dev/sdX
```

**NVMe Format:**

```bash
# DANGER: wipes the entire disk
sudo nvme format /dev/nvme0n1 --ses=1
# --ses=1: User Data Erase (crypto erase if supported)
```

**NVMe Sanitize (block erase or crypto erase):**

```bash
sudo nvme sanitize /dev/nvme0n1 --sanact=2
# --sanact=2: Block Erase
# --sanact=4: Crypto Erase (if supported)
```

**Crypto-shred a LUKS volume:**

```bash
# DANGER: destroys the LUKS header, making all data unrecoverable
sudo cryptsetup erase /dev/sdX
# Or wipe the LUKS header:
sudo dd if=/dev/urandom of=/dev/sdX bs=512 count=4096
```

**Wipe a whole HDD (before disposal):**

```bash
# DANGER: destroys all data
sudo dd if=/dev/urandom of=/dev/sdX bs=4M status=progress
# Or use nwipe for a bootable, GUI-driven wipe
```

**Eraser (Windows):**

- Install Eraser.
- Right-click a file -> Erase.
- For SSDs, Eraser recommends "Erase with zeroes" once (TRIM + wear leveling make multi-pass pointless).

## 7. Common Mistakes

Real mistakes that break data destruction:

1. **Assuming "delete" means "gone."** It does not.
2. **Emptying the recycle bin and thinking the file is gone.** Still recoverable.
3. **Using `shred` on an SSD.** Wear leveling means the physical cells may not be overwritten.
4. **Using DBAN on an SSD.** DBAN is HDD-only; it can damage SSDs and does not wipe them reliably.
5. **Using multi-pass wipes on modern HDDs.** One pass of random data is enough; multi-pass is a myth for modern drives.
6. **Forgetting swap and hibernation files.** These may contain plaintext.
7. **Forgetting cloud copies.** You cannot wipe the provider's backups.
8. **Forgetting external backups.** Old USB sticks, external drives, and NAS.
9. **Not enabling FDE from the start.** Retrofitting FDE is painful and may not cover old data.
10. **Not securely wiping the LUKS header.** Wiping the data but not the header leaves the possibility of recovery.
11. **Using journaling and copy-on-write filesystems without understanding their retention.** Journals and snapshots may preserve old data.
12. **Wiping data under legal hold.** This is a crime (spoliation of evidence).
13. **Trusting "secure delete" in apps.** Many apps just call `unlink()`.
14. **Assuming TRIM deletes data immediately.** TRIM marks blocks as free; the SSD erases them later.

## 8. Attacks Against It

Known attacks and limitations:

- **Wear leveling recovery.** On SSDs, some cells may retain old data even after TRIM and OS-level wipes. Only ATA Secure Erase, NVMe Format, or crypto-shredding is reliable.
- **Bad sectors.** On HDDs, bad sectors may retain data and are not overwritten.
- **Journaling recovery.** On ext4, NTFS, and other journaling filesystems, old file fragments may be recoverable from the journal.
- **Copy-on-write snapshots.** ZFS, Btrfs, and APFS snapshots may retain old versions of files.
- **Cold boot attacks.** RAM contents may survive a short power-off, allowing recovery of encryption keys and plaintext.
- **Firmware persistence.** Malware in BIOS/UEFI or SSD firmware survives disk wipes.
- **Cloud backups.** You cannot wipe them.
- **Legal hold.** Wiping data under legal hold is a crime.
- **Forensic imaging before wipe.** If the attacker imaged the disk before you wiped it, you cannot undo the leak.
- **Recovery from bad blocks.** Forensic tools can attempt to read data from bad blocks at the hardware level.
- **Magnetic force microscopy (MFM).** For very old drives, MFM could recover overwritten data. Modern drives have such high density that MFM is impractical, but the technique exists in the literature.

## 9. Detection (Blue Team)

What a forensic analyst or defender can see:

- **Deleted file recovery.** Tools like Autopsy, FTK, and Sleuth Kit can recover deleted files from HDDs.
- **Journal analysis.** File system journals can reveal deleted file metadata and fragments.
- **Snapshot analysis.** Copy-on-write filesystems keep old data; analysts can read it.
- **TRIM state.** On SSDs, TRIM state can indicate which blocks were recently freed (metadata leak).
- **RAM analysis.** Cold boot or live memory forensics can recover keys and plaintext.
- **Firmware analysis.** Firmware-level persistence survives disk wipes; analysts with firmware tools can find it.
- **Cloud provider logs.** Sync providers log file operations; the provider may still hold copies.
- **Legal discovery.** If the data is under legal hold, forensics can recover it even after wiping (and wiping is a separate crime).

## 10. Case Studies

- **Operation Shady RAT (2011).** A multi-year cyber-espionage campaign; the report highlighted the difficulty of removing attacker persistence even after disk wipes. Firmware-level persistence was a key issue.
- **Lavabit and the US government (2013).** Lavabit shut down rather than hand over its TLS keys. The case illustrated the difference between destroying data and being legally compelled to preserve it.
- **SSD forensic recovery (2010s).** Multiple studies showed that SSD data can be recovered after OS-level wipes due to wear leveling and over-provisioning. The result: secure erase at the firmware level, or FDE, is the only reliable method.
- **Crypto-shredding in practice.** Apple's "Erase All Content and Settings" on iOS destroys the encryption key, effectively crypto-shredding the device. This is fast, reliable, and works on SSDs.
- **Legal hold violations.** Companies have been sanctioned for wiping data under legal hold (e.g. in patent litigation). Spoliation is a separate offense from the underlying case.
- **Cold boot attacks (2008).** Researchers demonstrated recovering encryption keys from RAM after a short power-off by cooling the RAM chips. Modern OSes clear RAM on shutdown more aggressively, but the technique remains relevant in some scenarios.

(These are documented public events; no new attacks are disclosed here.)

## 11. Legal and Ethical Notes

Data destruction tools are legal to use on your own devices. However:

- **Legal hold.** If you are under a legal obligation to preserve data (litigation, investigation, regulatory requirement), wiping it is a crime (spoliation). Do NOT wipe data under legal hold.
- **Corporate data.** Wiping corporate-owned devices may violate company policy or your employment contract.
- **Evidence.** If you suspect a device is evidence in a crime, do not wipe it; contact law enforcement.
- **Data belonging to others.** Do not wipe data you do not own or have authority over.
- **Authorized use only.** In a professional context, use data destruction tools only within the scope of an authorized engagement or on your own devices.

## 12. Production Notes

If you are deploying data destruction for a small group:

- **Standardize on FDE.** LUKS, FileVault, or BitLocker on every device.
- **Standardize the wipe procedure.** For HDDs: single random pass. For SSDs: ATA Secure Erase or NVMe Format. For encrypted disks: crypto-shred.
- **Document the crypto-shred procedure.** Who can trigger it, and how is it verified?
- **Do not rely on `shred` for SSDs.** Document this clearly; it is a common mistake.
- **Cover swap and hibernation.** Encrypted swap or no swap.
- **Cover cloud and backups.** Policy: sensitive data does not go to cloud-synced folders.
- **Train users.** "Delete" does not mean "gone."
- **Legal hold policy.** Define what triggers a legal hold and how it is enforced.
- **Test the procedure** on a spare device before relying on it.
- **Monitor the threat model.** Storage technology evolves; re-evaluate periodically.

## 13. References

- NIST SP 800-88 Rev. 1: Guidelines for Media Sanitization - https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final
- ATA Secure Erase (hdparm) - https://ata.wiki.kernel.org/index.php/ATA_Secure_Erase
- NVMe Specification (Sanitize) - https://nvmexpress.org/
- LUKS / cryptsetup - https://gitlab.com/cryptsetup/cryptsetup
- GnuPG - shred documentation - https://www.gnu.org/software/coreutils/manual/html_node/shred-invocation.html
- DBAN (HDD-only) - https://dban.org/
- nwipe - https://github.com/martijnvanbrummelen/nwipe
- Eraser (Windows) - https://eraser.heidi.ie/
- Cold boot attacks (Princeton, 2008) - https://citp.princeton.edu/our-work/memory/
- Electronic Frontier Foundation - Surveillance Self-Defense - https://ssd.eff.org/
