# OWASP Mobile Top 10

> [!NOTE]
> This document is for authorized security testing, educational purposes, and defensive engineering only.

## 1. Overview

The OWASP Mobile Top 10 lists the most critical security risks for mobile applications. The 2024 revision replaces the 2016 list and aligns with MASVS (Mobile Application Security Verification Standard).

Two revisions matter in practice:

- **2016** - still referenced in older audit reports, pentest templates, and vendor questionnaires.
- **2024** - current; use it for new assessments.

This document maps both revisions to the files in this category and to MASVS categories.

## 2. 2024 List

| ID | Risk | MASVS | Covered in |
|----|------|-------|------------|
| M1 | Improper Credential Usage | AUTH, STORAGE | [01 Mobile Security Fundamentals](./01%20Mobile%20Security%20Fundamentals.md), 03 Android Security (planned), 04 iOS Security (planned) |
| M2 | Inadequate Supply Chain Security | CODE, RESILIENCE | 05 Mobile Defense and Testing (planned) |
| M3 | Insecure Authentication/Authorization | AUTH | [01 Mobile Security Fundamentals](./01%20Mobile%20Security%20Fundamentals.md) |
| M4 | Insufficient Input/Output Validation | PLATFORM, CODE | 03 Android Security (planned), 04 iOS Security (planned) |
| M5 | Insecure Communication | NETWORK | [01 Mobile Security Fundamentals](./01%20Mobile%20Security%20Fundamentals.md) |
| M6 | Inadequate Privacy Controls | PRIVACY | 05 Mobile Defense and Testing (planned) |
| M7 | Insufficient Binary Protections | RESILIENCE | 03 Android Security (planned), 05 Mobile Defense and Testing (planned) |
| M8 | Security Misconfiguration | PLATFORM | 03 Android Security (planned), 04 iOS Security (planned) |
| M9 | Insecure Data Storage | STORAGE, CRYPTO | 03 Android Security (planned), 04 iOS Security (planned) |
| M10 | Insufficient Cryptography | CRYPTO | [01 Mobile Security Fundamentals](./01%20Mobile%20Security%20Fundamentals.md) |

## 3. 2016 vs 2024

| 2016 | 2024 | Notes |
|------|------|-------|
| M1 Improper Platform Usage | M8 Security Misconfiguration | Renamed, narrowed to configuration issues |
| M2 Insecure Data Storage | M9 Insecure Data Storage | Same risk, renumbered |
| M3 Insecure Communication | M5 Insecure Communication | Same risk, renumbered |
| M4 Insecure Authentication | M1 + M3 | Split into credential usage and auth/authz |
| M5 Insufficient Cryptography | M10 Insufficient Cryptography | Same risk, renumbered |
| M6 Insecure Authorization | M3 | Merged with authentication |
| M7 Client Code Quality | M4 | Reframed as input/output validation |
| M8 Code Tampering | M7 | Merged into binary protections |
| M9 Reverse Engineering | M7 | Merged into binary protections |
| M10 Extraneous Functionality | (removed) | Covered by code review, not a top-10 risk |
| (new) | M2 Supply Chain | New in 2024 |
| (new) | M6 Privacy Controls | New in 2024 |

**Practical note:** If a client asks for "OWASP Mobile Top 10 compliance", confirm which revision they mean. A 2024 report that ignores M2 and M6 is incomplete against the current standard.

## 4. Mapping to This Category

- **M1, M3, M5, M10** - foundations, covered in `01 Mobile Security Fundamentals.md` (storage, communication, auth, crypto).
- **M4, M7, M8, M9** - platform-specific, covered in `03 Android Security.md` and `04 iOS Security.md`.
- **M2, M6** - process and privacy, covered in `05 Mobile Defense and Testing.md`.
- **M7** (binary protections) - also covered by the pentest angle in `01 Mobile Security Fundamentals.md` (reverse engineering and tampering).

## 5. MASVS Categories

MASVS 2.0 organizes controls into 8 categories (was 7 in 1.x). Mobile Top 10 items map to one or more of these:

| MASVS | Full name | Mapped M-items |
|-------|-----------|----------------|
| MASVS-STORAGE | Data storage | M9 |
| MASVS-CRYPTO | Cryptography | M10 |
| MASVS-AUTH | Authentication and authorization | M1, M3 |
| MASVS-NETWORK | Network communication | M5 |
| MASVS-PLATFORM | Platform interaction | M4, M8 |
| MASVS-CODE | Code quality and build settings | M2, M4, M7 |
| MASVS-RESILIENCE | Resilience against reverse engineering and tampering | M2, M7 |
| MASVS-PRIVACY | Privacy (new in 2.0) | M6 |

## 6. References

- OWASP Mobile Top 10 (2024) - https://owasp.org/www-project-mobile-top-10/
- OWASP Mobile Top 10 (2016) archive - https://owasp.org/www-project-mobile-top-10/2016-risks/
- OWASP MASVS - https://mas.owasp.org/MASVS/
- OWASP MASTG - https://mas.owasp.org/MASTG/