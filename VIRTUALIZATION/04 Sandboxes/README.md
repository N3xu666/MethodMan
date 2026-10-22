# Sandboxes

Isolation mechanisms that constrain untrusted code or content to a limited
execution environment. This subcategory covers how sandboxes are built, where
they break, and how to defend them.

Sandboxes appear at every layer of the stack: the browser isolates web content,
the OS isolates processes and applications, mobile platforms isolate apps, and
analysts isolate malware. Each layer has its own trust model, its own escape
history, and its own defensive controls.

## Scope

This subcategory covers:

- The isolation primitives behind modern sandboxes (namespaces, seccomp,
  job objects, app containers, browser renderer processes).
- Attack surface and historical escapes at each layer.
- Offensive techniques for probing and escaping sandboxes in authorized
  testing.
- Defensive controls, detection signals, and hardening guidance.
- Malware analysis sandboxes as a defensive tool and their evasion surface.

## Format

Each file uses the two-track format:

- **Offensive** - attack surface, escape techniques, proof-of-concept recipes.
- **Defensive** - preventive controls, detection signals, hardening, verification.

## Files

| # | File | Format |
|---|------|--------|
| 01 | [Sandbox Fundamentals](./01%20Sandbox%20Fundamentals.md) | Two-track |
| 02 | [Browser Sandbox Security](./02%20Browser%20Sandbox%20Security.md) | Two-track |
| 03 | [OS-Level Sandboxes](./03%20OS-Level%20Sandboxes.md) | Two-track |
| 04 | [Mobile Sandbox Security](./04%20Mobile%20Sandbox%20Security.md) | Two-track |
| 05 | [Malware Analysis Sandboxes](./05%20Malware%20Analysis%20Sandboxes.md) | Two-track |

## Related

- Virtualization 01 Hypervisors - hypervisor-level isolation.
- Virtualization 02 VM Escape - escapes from the VM boundary.
- Virtualization 03 Containers - namespace and cgroup isolation.

## References

- Sandbox (computer security) - https://en.wikipedia.org/wiki/Sandbox_(computer_security)
- NIST SP 800-83 Rev. 1, Guide to Malware Incident Prevention and Handling for Desktops and Laptops - https://csrc.nist.gov/pubs/sp/800/83/r1/final