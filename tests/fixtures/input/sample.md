# FakeMachine (HTB)

> Platform: Hack The Box
> OS: Linux
> Difficulty: Easy
> Result: root

---

## Attack Chain

```text
Recon -> Foothold -> Privesc
```

---

## Machine Briefing

Fake machine for testing `mask.ps1`. Contains all supported
secret types with fake (but format-valid) values.

## Reconnaissance

    nmap -sC -sV -p- 10.10.10.10

Config file leaked combo credentials:

    combo_user:combo_pass_xyz

Application config contained standalone password:

    standalone_pw_abc

Serial number from device banner:

    SN-FAKE12345-ABCDE

## Foothold

Login bypass with captured bcrypt hash:

    $2y$10$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLM

JWT session token intercepted:

    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456

Session cookie value:

    sess_abc123def456ghi789jkl012mno345pqr

SSH key found in backup directory:

    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDtesttesttest

## Privilege Escalation

MySQL user hash dumped from database:

    *ABCDEF1234567890ABCDEF1234567890ABCDEF12

SHA-256 crypt hash from /etc/shadow:

    $5$rounds=5000$saltsaltsalt$hashhashhashhashhashhashhashhashhashhashhash

MD5 hash from legacy backup:

    5f4dcc3b5aa765d61d8327deb882cf99

Booking reference from internal API:

    BR-2026-1234-XYZ

Security key from app config:

    sec_key_0123456789abcdef0123456789abcdef

## Flags

User flag:

    ff7cb55f76acbd3560efe4c1a19ecfb5

Root flag:

    c5a8f8dc9f8bca0c1c2e3d4e5f6a7b8c

System flag (Windows side):

    d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6

## Key Takeaways

- Test sample for `mask.ps1` coverage.
- Contains 15 fake secrets across all supported types.
- Never commit real values.

