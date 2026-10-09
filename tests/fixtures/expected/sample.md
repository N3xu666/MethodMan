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

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Machine Briefing

Fake machine for testing `mask.ps1`. Contains all supported
secret types with fake (but format-valid) values.

## Reconnaissance

    nmap -sC -sV -p- 10.10.10.10

Config file leaked combo credentials:

    combo_user:<PASSWORD>

Application config contained standalone password:

    <PASSWORD>

Serial number from device banner:

    <SERIAL>

## Foothold

Login bypass with captured bcrypt hash:

    <BCRYPT_HASH>

JWT session token intercepted:

    <TOKEN>

Session cookie value:

    <SESSION_ID>

SSH key found in backup directory:

    <SSH_KEY>

## Privilege Escalation

MySQL user hash dumped from database:

    <MYSQL_HASH>

SHA-256 crypt hash from /etc/shadow:

    <SHA256_HASH>

MD5 hash from legacy backup:

    <MD5_HASH>

Booking reference from internal API:

    <BOOKING_REF>

Security key from app config:

    <SECURITY_KEY>

## Flags

User flag:

    <USER_FLAG>

Root flag:

    <ROOT_FLAG>

System flag (Windows side):

    <SYSTEM_FLAG>

## Key Takeaways

- Test sample for `mask.ps1` coverage.
- Contains 15 fake secrets across all supported types.
- Never commit real values.

