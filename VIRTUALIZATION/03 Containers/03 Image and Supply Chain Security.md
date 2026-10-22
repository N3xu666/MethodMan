# Image and Supply Chain Security

This file covers the security of container images and the software supply chain that produces them. A single vulnerable or malicious base image can compromise every container built from it. This file covers both the offensive techniques for attacking the supply chain and the defensive controls to secure it.

## 1. Overview

Container images are the building blocks of containerized applications. They are composed of layers, each representing a filesystem change. The supply chain includes:

- **Base images** (e.g., `ubuntu`, `alpine`, `python`) from public registries.
- **Dependencies** installed during the build.
- **Build tools** (Docker, Buildah, Kaniko).
- **Registries** (Docker Hub, GitHub Container Registry, private registries).

An attacker who compromises any part of this chain can inject malicious code into every container built from the image.

## 2. Image Anatomy

A container image consists of:

- **Manifest** - metadata (layers, config).
- **Config** - environment variables, entrypoint, user.
- **Layers** - filesystem diffs (each layer is a tarball).

Layers are cached and shared. If a base layer is compromised, every image that uses it is affected.

## 3. Supply Chain Attack Vectors

### 3.1 Compromised Base Image

An attacker uploads a malicious base image to a public registry (e.g., `ubuntu:latest` with a backdoor). If developers use it without verification, the backdoor is included in every build.

### 3.2 Dependency Confusion

An attacker uploads a malicious package to a public registry with the same name as a private internal package. If the build process resolves dependencies from the public registry first, the malicious package is installed.

### 3.3 Typosquatting

An attacker uploads a package with a name similar to a popular package (e.g., `python-dateutil` vs. `python-dateutil`). Developers who make a typo install the malicious package.

### 3.4 Compromised Build Pipeline

An attacker compromises the CI/CD pipeline (e.g., GitHub Actions) and injects malicious code into the build process. The resulting image is backdoored.

### 3.5 Registry Compromise

An attacker gains access to a private registry and replaces a trusted image with a malicious one.

## 4. Exploitation Recipes

### 4.1 Checking Image Layers

```bash
# Inspect image layers for suspicious files.
$ docker history --no-trunc <image>
$ docker save <image> -o image.tar
$ tar -xf image.tar
$ ls -la
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
IMAGE          CREATED        CREATED BY                                      SIZE
<missing>      2 weeks ago    /bin/sh -c #(nop)  CMD ["/bin/bash"]            0B
<missing>      2 weeks ago    /bin/sh -c apt-get update && apt-get install...  50MB
```

### 4.2 Scanning for Vulnerabilities

```bash
# Scan an image for known vulnerabilities (requires Trivy or Grype).
$ trivy image <image>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
2026-10-22T10:00:00.000Z INFO Detected OS: ubuntu 22.04
2026-10-22T10:00:00.000Z INFO Detecting vulnerabilities...
2026-10-22T10:00:00.000Z INFO Number of language-specific files: 1
+-------------------+------------------+----------+-------------------+
|      LIBRARY      | VULNERABILITY ID | SEVERITY | INSTALLED VERSION |
+-------------------+------------------+----------+-------------------+
| libssl1.1         | CVE-2023-1234    | HIGH     | 1.1.1f-1ubuntu2   |
+-------------------+------------------+----------+-------------------+
```

### 4.3 Verifying Image Signatures

```bash
# Verify an image signature with cosign.
$ cosign verify <image>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Expected output:

```text
Verification for <image> --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

## 5. Defensive Controls

- **Use minimal base images** (Alpine, distroless) to reduce attack surface.
- **Pin image digests** (`image@sha256:...`) instead of tags.
- **Scan images for vulnerabilities** in the CI pipeline (Trivy, Grype, Clair).
- **Sign images** with cosign or Notary.
- **Use private registries** with access control.
- **Verify dependencies** with checksums and lockfiles.
- **Implement SLSA** (Supply-chain Levels for Software Artifacts) for build integrity.

## 6. Detection Controls

- **Monitor registry access** for unusual pull/push activity.
- **Audit image signatures** and reject unsigned images.
- **Scan running containers** for known malicious files.
- **Use admission controllers** (e.g., OPA Gatekeeper) to enforce image policies.

## 7. Verification

To verify supply chain security:

- Check that all images are signed: `cosign verify <image>`.
- Check that images are pinned by digest: `docker inspect <image> | grep RepoDigests`.
- Run a vulnerability scan on the base image.
- Confirm that the CI pipeline uses lockfiles and checksums.

## 8. Production Notes

- In production, treat the container registry as a critical asset. Protect it with MFA and audit logs.
- Implement a "trusted base image" policy and automate rebuilds when a new base image is released.
- Use SBOM (Software Bill of Materials) to track dependencies.

## 9. References

- NIST SP 800-190 Application Container Security Guide - https://csrc.nist.gov/publications/detail/sp/800-190/final
- SLSA (Supply-chain Levels for Software Artifacts) - https://slsa.dev/
- Trivy vulnerability scanner - https://github.com/aquasecurity/trivy
- cosign image signing - https://docs.sigstore.dev/cosign/overview/
- OWASP Dependency-Check - https://owasp.org/www-project-dependency-check/
- CIS Docker Benchmark - https://www.cisecurity.org/benchmark/docker