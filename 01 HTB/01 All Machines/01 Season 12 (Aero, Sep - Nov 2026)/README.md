# Season 12 Aero

Writeups for HTB Season 12: Aero, running from September to November 2026.

Final writeups are located in [`md/ru/`](./md/ru/). Raw drafts are kept in [`txt/ru/`](./txt/ru/). English translations (`md/en/`) are planned.

## Machines

| # | Machine | OS | Difficulty | Result | Key Techniques | Writeup |
|---|---------|-----|------------|--------|----------------|---------|
| 01 | Layover | Linux | Medium | root | Open WiFi traffic interception, Craft CMS CVE-2026-31857 (Twig RCE), `.env` secret decryption, CUPS CVE-2026-34990 LPE | [md](./md/ru/01%20Layover%20%28open%20WiFi%20traffic%20interception%20%2B%20Craft%20CMS%20CVE-2026-31857%20Twig%20RCE%20%2B%20.env%20secret%20decryption%20%2B%20CUPS%20CVE-2026-34990%20LPE%29.md) |
| 02 | Touch | Windows | Easy | SYSTEM | Nexion DeviceHub serial leak, kiosk escape, MySQL credentials leak, UDF hijacking | [md](./md/ru/02%20Touch%20%28Nexion%20DeviceHub%20serial%20leak%20%2B%20kiosk%20escape%20%2B%20MySQL%20creds%20leak%20%2B%20UDF%20hijacking%20SYSTEM%29.md) |

## Notes

- **Layover** is linked to **Touch** by the season's storyline. The booking reference `KS7X2M` and the name `Jenny Crawford` found on Layover are used on Touch.

## Archive

Raw drafts (before formatting) are stored in [`txt/ru/`](./txt/ru/).