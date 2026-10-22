# Browser Sandbox Security

> [!CAUTION]
> Educational reference only. Escape techniques must be used exclusively in
> authorized testing, CTF environments, or your own isolated lab. Running them
> against systems you do not own is illegal.

## 1. Overview

The browser is the most exposed application on a typical workstation. It
renders arbitrary code and content from the internet every day, on behalf of
a user who has no way to inspect it. A browser sandbox exists to make that
content harmless: even if a web page runs malicious JavaScript, exploits a
parser bug, or triggers a memory-safety bug in a rendering engine, it must
not be able to read the user's files, steal cookies from other sites, or
execute code outside the browser.

This file covers how browsers build that boundary, where it has broken, and
how to test and harden it.

## 2. Threat Model

The browser sandbox defends against:

- Malicious web content (JavaScript, HTML, CSS, media, WebAssembly).
- Exploited rendering-engine bugs (V8, JavaScriptCore, SpiderMonkey, Blink,
  WebKit, Gecko).
- Compromised third-party content (ads, trackers, embedded widgets).
- Malicious extensions (partially - extensions have more privilege by design).

What it explicitly does NOT defend against:

- A user who approves a dangerous action (download and run, grant permission).
- A malicious extension with the permissions it requested (that is a user
  decision, not a sandbox escape).
- A compromised OS-level component beneath the browser.

The threat model is unusual because the attacker is not just a remote server;
any website the user visits is a potential attacker.

## 3. How the Browser Sandbox Works

### 3.1 Multi-Process Architecture

Modern browsers split work across processes. The renderer process handles
untrusted content and runs at the lowest privilege. The browser process
(the "broker") handles privileged operations: file access, network, IPC with
the OS. The GPU process handles graphics.

The renderer cannot call OS APIs directly. It sends IPC messages to the
browser process, which validates and performs the action. This is a
classic confused-deputy design: the security of the whole system depends on
the broker's validation of every IPC request.

### 3.2 Process per Site (Site Isolation)

Chromium's Site Isolation places pages from different sites in different
renderer processes. The boundary is the site (eTLD+1), not the origin, so
`a.example.com` and `b.example.com` share a process, but
`example.com` and `attacker.com` do not.

Why it matters: a Spectre-class side-channel or a renderer bug in one site
cannot read the memory of a page from a different site.

### 3.3 OS-Level Sandboxing

The renderer process is confined by the OS sandbox:

- Linux: seccomp-bpf allow-list, namespaces, a dedicated sandbox helper.
- Windows: restricted token, job object, AppContainer, win32k lockdown.
- macOS: Seatbelt (`sandbox_init`) profiles per process type.

A renderer escape yields code execution inside the renderer process, but it
is still confined by the OS sandbox. Reaching the user's files requires a
second escape from the OS sandbox.

### 3.4 Site Isolation and Origin Sandboxing

Even within a site, different origins are separated by the same-origin
policy. JavaScript cannot read a cross-origin iframe's DOM, cookies, or
storage. This is enforced by the browser, not by the OS.

## 4. Common Attack Vectors

### 4.1 Renderer Exploitation

The classic path: a memory-safety bug in the JavaScript engine or a rendering
component yields arbitrary read/write in the renderer process.

Steps an exploit must complete:

1. Achieve a memory-safety primitive in the renderer (type confusion,
   use-after-free, out-of-bounds).
2. Build arbitrary read/write from the primitive.
3. Bypass ASLR and the heap mitigations inside the renderer.
4. Pivot from "arbitrary read/write in the renderer" to "arbitrary code
   execution in the renderer".
5. Escape the OS sandbox (a second, independent exploit).

Each step is a separate engineering problem. A full chain is expensive; this
is why browser zero-days are among the most valuable exploits on the market.

### 4.2 IPC and Broker Bugs

Instead of exploiting the renderer, attack the broker's IPC handlers. A
missing sender check, a type confusion in a Mojo/XPC message handler, or a
path traversal in a file-open request can give the renderer access to
resources the broker should have protected.

This class is often cheaper than a full renderer exploit because IPC handlers
are numerous and less fuzzed than the core engine.

### 4.3 Site Isolation Bypass

A bug in the site-isolation logic can place two different sites in the same
process. From there, a renderer bug in one site (or a Spectre gadget) can
read the other site's data.

### 4.4 Spectre and Side Channels

Spectre-class attacks let an attacker read memory outside the architectural
boundary of their own code. Site Isolation is the browser's primary defense:
if the target data is in a different process, the attacker cannot reach it
even with a speculative-execution gadget.

### 4.5 Extension Privilege

Extensions are not sandboxed the same way as web content. A malicious or
compromised extension can read the content of pages the user visits, exfiltrate
data, and in some configurations execute native code. Extensions are a
user-mediated trust decision, not a sandbox escape.

## 5. Exploitation Recipes

### 5.1 Fingerprinting the Sandbox Configuration

Before assuming a boundary exists, confirm it.

```javascript
// site isolation and cross-origin isolation state
console.log(crossOriginIsolated);
console.log(self.originAgentCluster);

// measure whether two origins are in the same process (weak signal)
// a real check requires a renderer crash correlation, not JS
```

Expected (a modern Chrome on a normal page):

```text
false
true
```

`crossOriginIsolated` is `false` unless COOP+COEP are set. `originAgentCluster`
being `true` means the page is in its own agent cluster.

### 5.2 Inspecting the Renderer Process

On Linux, identify which process is the renderer and which sandbox confines
it.

```bash
# list browser processes and their sandbox state
ps -ef | grep -i chrom
cat /proc/<renderer_pid>/status | grep -E 'Seccomp|NoNewPrivs|CapEff'

# what namespaces does the renderer live in
ls -l /proc/<renderer_pid>/ns/
```

Expected:

```text
Seccomp: 2
NoNewPrivs: 1
CapEff: 0000000000000000
```

A renderer with `Seccomp: 2`, `NoNewPrivs: 1`, and zero capabilities is
confined as designed.

### 5.3 Checking for a Missing Site Isolation Boundary

If two sites land in the same renderer, the site-isolation boundary is
absent. This is not directly observable from JavaScript; it requires
inspecting the browser's process model (chrome://process-internals in
Chromium-based browsers) or correlating renderer crashes.

### 5.4 Reading the Broker's IPC Surface

The renderer's IPC interface is defined in the browser's mojom/IPC IDL files.
For an authorized assessment, enumerate the messages the renderer can send
and check each one for validation.

```bash
# Chromium source: renderer -> browser interface definitions
find . -name '*.mojom' | xargs grep -l 'interface' | head
```

This is source-level reconnaissance, not runtime. It narrows which IPC
handlers are worth fuzzing.

## 6. Post-Exploitation

Two distinct post-exploitation states exist.

Renderer code execution (still sandboxed):

- Can read the DOM, cookies, storage, and memory of its own process.
- Can send arbitrary IPC to the broker, subject to broker validation.
- Cannot read the user's files or execute OS processes directly.
- Cannot read other sites' data (site isolation).

OS sandbox escape (full user compromise):

- Runs as the user, can read the user's files and profile.
- Can persist (startup items, extensions, scheduled tasks).
- Can reach the network and other local services.

Most browser exploits stop at the first state. The second state requires a
separate OS-sandbox exploit.

## 7. Preventive Controls

- Keep the browser and OS patched. Renderer and kernel bugs are the main
  escape vectors.
- Enable Site Isolation. It is on by default in modern Chromium; verify it
  has not been disabled by policy or a flag.
- Enable the OS-level sandbox. Do not run browsers with `--no-sandbox` except
  in disposable, isolated analysis VMs.
- Restrict extensions. Allow-list only what the user genuinely needs; audit
  extension permissions.
- Use per-site process isolation for high-value sites if the browser supports
  it (e.g. isolated web apps).
- Run high-risk browsing in a separate VM or browser profile.
- For enterprises, enforce browser policy (ExtensionInstallAllowlist,
  SitePerProcess, SandboxEnabled) via MDM/GPO.

## 8. Detection Controls

- Monitor renderer crashes and restarts. Repeated crashes for the same site
  are a fuzzing/exploitation signal.
- Alert on browser processes running without the sandbox (missing seccomp,
  `--no-sandbox` flag).
- Monitor extension installation and permission changes.
- Detect unusual IPC volume or malformed IPC from a renderer.
- For endpoint detection, correlate a renderer crash with a subsequent
  privilege change or file access outside the browser profile.
- Network-side: detect exploit delivery (known exploit kit patterns,
  obfuscated JavaScript, heap-spray-like allocation patterns in WebAssembly).

## 9. Verification

To verify a browser sandbox configuration:

1. Confirm Site Isolation is active (`chrome://process-internals`).
2. Confirm the renderer is confined by the OS sandbox (section 5.2).
3. Confirm `--no-sandbox` is not set in the launch flags.
4. Confirm extensions are allow-listed and their permissions reviewed.
5. Run a benign renderer-crash test and confirm the crash is contained
   (no OS-level side effects).
6. Re-verify after every browser update: sandbox configuration can regress.

## 10. References

- Chromium sandbox design - https://chromium.googlesource.com/chromium/src/+/main/docs/design/sandbox.md
- Site Isolation - https://www.chromium.org/Home/chromium-security/site-isolation/
- Chromium process model - https://chromium.googlesource.com/chromium/src/+/main/docs/process_model_and_site_isolation.md
- Spectre - https://spectreattack.com/
- WebKit security - https://webkit.org/security/
- Firefox process model - https://firefox-source-docs.mozilla.org/dom/ipc/process_model.html
- NIST SP 800-83 Rev. 1, Guide to Malware Incident Prevention and Handling for Desktops and Laptops - https://csrc.nist.gov/pubs/sp/800/83/r1/final