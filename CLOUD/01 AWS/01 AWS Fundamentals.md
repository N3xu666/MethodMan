# AWS Fundamentals

> [!CAUTION]
> This file is for authorized security testing of AWS accounts you own or have explicit written permission to assess. Do not use these techniques against accounts, resources, or services you do not own or have permission to test.

## 1. Overview

Amazon Web Services (AWS) is a cloud platform of over 200 managed services. From a security standpoint, the account is the trust boundary: the AWS account ID, its root user, its IAM identities, and the resources inside it. The shared responsibility model splits security between AWS (security *of* the cloud: physical, hypervisor, managed-service internals) and the customer (security *in* the cloud: IAM, network configuration, data, logging, application code).

This file covers the fundamentals that every other AWS file in this subcategory builds on: the account model, regions and availability zones, the IAM identity types, the main service families (compute, storage, networking, serverless, logging), and the reconnaissance surface an attacker sees from outside and from inside the account.

The goal is to answer three questions before touching anything:

1. What identities exist, and what can each of them do?
2. What resources are reachable from the current position?
3. What evidence does each action leave, and where is it stored?

## 2. Reconnaissance / Enumeration

### 2.1 External reconnaissance (no credentials)

The account ID, region, and service surface are discoverable from outside without any AWS credentials:

- **Account ID discovery** via public S3 bucket responses, public ECR image URIs, public Lambda function URLs, and IAM error messages on unauthenticated calls. A canonical method is the `x-amz-account-id` header or the AWS account alias in a public response.
- **S3 bucket enumeration** by name guessing: bucket names are globally unique, so a hit confirms the name exists. Unauthenticated `GET https://<bucket>.s3.amazonaws.com/` returns 200 (listable), 403 (exists, not listable), or 404 (does not exist).
- **DNS-based discovery** via `CNAME` records pointing to `*.cloudfront.net`, `*.elb.amazonaws.com`, `*.execute-api.<region>.amazonaws.com`, `*.s3.amazonaws.com`.
- **TLS certificate transparency** logs reveal internal hostnames tied to AWS services.

### 2.2 Authenticated reconnaissance (with credentials)

Once any credential is obtained (leaked access key, SSRF to the instance metadata service, compromised CI runner), the first three calls are:

```bash
# Who am I?
aws sts get-caller-identity

# What account and region am I in?
aws configure list

# What can I do?
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>
```

`sts:GetCallerIdentity` is the single most useful call in AWS security: it returns the account ID, the principal ARN, and the user ID, and it requires no permissions beyond itself. Most hardening guides do not disable it, and it works for every identity type (user, role, federated session).

### 2.3 Enumerating the account surface

After the identity is known, enumerate what the identity can see. AWS IAM permissions are granular, so "I can see it" and "I can use it" are different questions. Start with read-only calls that most identities are allowed to make by default in developer accounts:

```bash
# S3 buckets visible to this identity
aws s3 ls

# EC2 instances in the current region
aws ec2 describe-instances --query 'Reservations[].Instances[].{ID:InstanceId,Type:InstanceType,State:State.Name,Tags:Tags}'

# IAM users, roles, and policies
aws iam list-users
aws iam list-roles
aws iam list-policies --scope Local

# Lambda functions
aws lambda list-functions

# Secrets and parameters (often the highest-value targets)
aws secretsmanager list-secrets
aws ssm describe-parameters
```

Region matters: AWS resources are regional (except IAM, Route 53, CloudFront, and S3 bucket names which are global). A complete enumeration loops over all enabled regions, not just the default one.

## 3. Common Attack Vectors

### 3.1 Credential leakage

The most common way into an AWS account is not an AWS vulnerability, it is a leaked credential: an access key in a public GitHub repository, an IAM user with a console password reused from a breached site, a CI/CD runner with over-permissive role assumption, or an SSRF in a public web application that reaches the instance metadata service (IMDS).

### 3.2 Identity and permission misconfiguration

IAM policies are powerful and easy to over-grant. Common patterns:

- `Action: "*"` with `Resource: "*"` on a user or role (full admin).
- `iam:PassRole` combined with `lambda:CreateFunction` or `ec2:RunInstances` (privilege escalation via a new resource that assumes a more privileged role).
- Trust policies that allow `Principal: "*"` or a broad `AWS: "*"` condition.
- Cross-account trust without `ExternalId` (confused-deputy risk).

### 3.3 Network exposure

- Security groups with `0.0.0.0/0` on management ports (22, 3389, 5432, 6379, 9200, 27017).
- Public S3 buckets, public ECR repositories, public RDS snapshots.
- IMDSv1 still enabled on EC2 instances (SSRF -> credential theft).
- VPC peering or Transit Gateway routes that expose internal services to less-trusted accounts.

### 3.4 Service-specific weaknesses

Each AWS service has its own attack surface: S3 bucket policies and ACLs, EC2 user-data and instance profiles, Lambda environment variables and layers, ECS task definitions, EKS cluster IAM roles for service accounts (IRSA), RDS snapshot sharing, CloudFormation stack parameters. Later files in this subcategory cover each family in detail.

## 4. Exploitation Recipes

### 4.1 From leaked access key to account reconnaissance

Assume an access key (`AKIA...`) and secret key (`...`) leaked in a public repository. Configure the AWS CLI with the leaked pair, then run the identity call and the read-only enumeration from section 2.

```bash
export AWS_ACCESS_KEY_ID=AKIAEXAMPLE
export AWS_SECRET_ACCESS_KEY=<SECRET>
aws sts get-caller-identity
aws s3 ls
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query 'Arn' --output text | cut -d/ -f2)
```

Expected output of `get-caller-identity`:

```text
{
    "UserId": "AIDAEXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/leaked-user"
}
```

If the key belongs to a role session rather than a user, `get-caller-identity` returns `arn:aws:sts::123456789012:assumed-role/<role>/<session>`, and the policy enumeration path is different (`aws iam list-role-policies --role-name <role>` plus `list-attached-role-policies`).

### 4.2 From SSRF to IMDS credentials

If a public web application has an SSRF, the target is `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>`. On IMDSv1 the response contains `AccessKeyId`, `SecretAccessKey`, and `Token`. On IMDSv2 the attacker must first `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds`, then send `GET` with `X-aws-ec2-metadata-token`. IMDSv2 raises the bar but does not eliminate SSRF; it only forces a two-step request, which many SSRF gadgets can still perform.

## 5. Post-Exploitation

After initial access, the attacker's priorities are persistence, privilege escalation, and data access. In AWS these are distinct from a Linux foothold:

- **Persistence** via a new IAM user with an access key, a new role with a trust policy pointing to an external account, a Lambda function with a scheduled EventBridge rule, or an EC2 instance with a modified user-data script.
- **Privilege escalation** via `iam:PassRole` plus a compute service, `iam:CreatePolicyVersion` on a policy attached to the current identity, `iam:AttachUserPolicy` on self, or `sts:AssumeRole` to a more privileged role that trusts the current identity.
- **Data access** via S3 `GetObject` on buckets the identity can read, RDS snapshot export to S3, DynamoDB `Scan`, Secrets Manager `GetSecretValue`, SSM Parameter Store `GetParameter` with `--with-decryption`.

Each of these leaves a CloudTrail event. Section 7 describes what to look for.

## 6. Preventive Controls

- **Eliminate long-lived access keys.** Use IAM roles and OIDC federation for CI/CD. AWS Organizations SCP can deny `iam:CreateAccessKey` for non-break-glass identities.
- **Enforce IMDSv2** (`HttpTokens: required`) on every EC2 instance. Deny `RunInstances` without `MetadataOptions.HttpTokens=required` via SCP.
- **Least privilege on IAM.** Replace `Action: "*"` with explicit actions and conditions. Use IAM Access Analyzer to find unused permissions.
- **Block public S3 by default** at the account level (`BlockPublicAcls`, `BlockPublicPolicy`, `IgnorePublicAcls`, `RestrictPublicBuckets`). Allow exceptions only through a reviewed bucket policy.
- **Require MFA for sensitive actions** via a `aws:MultiFactorAuthPresent` condition on destructive or privilege-granting API calls.
- **Guardrails at the organization level** with SCPs that deny disabling CloudTrail, GuardDuty, or Config, and deny leaving the organization.

## 7. Detection Controls

CloudTrail is the primary AWS audit log. Every management event (and optionally every data event) is recorded with the caller identity, source IP, user agent, and request parameters. Detection priorities:

- **`sts:GetCallerIdentity` from a new IP or user agent** - weak signal alone, but a strong one when the identity has never used that IP.
- **`iam:CreateAccessKey`, `iam:CreateUser`, `iam:AttachUserPolicy`, `iam:CreatePolicyVersion`** - persistence and privilege escalation.
- **`iam:PassRole` followed by `lambda:CreateFunction` or `ec2:RunInstances`** - classic privilege escalation chain.
- **`s3:GetObject` on sensitive buckets outside business hours** - data access.
- **`secretsmanager:GetSecretValue` and `ssm:GetParameter` with `--with-decryption`** - secret theft.
- **`cloudtrail:StopLogging`, `guardduty:DeleteDetector`, `config:DeleteConfigurationRecorder`** - defense evasion. These should be near-impossible: SCP-deny them.
- **IMDSv1 requests** (`curl 169.254.169.254` from inside an instance) - CloudWatch Logs from the instance's OS-level audit, or VPC Flow Logs to the metadata IP (though the metadata IP is link-local and not captured by VPC Flow Logs; use GuardDuty's `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` finding).

GuardDuty covers many of these patterns out of the box, especially credential exfiltration, cryptocurrency mining, and anomalous API calls. Security Hub aggregates GuardDuty, Config, and IAM Access Analyzer findings into one place.

## 8. Verification

To verify the preventive controls in section 6, run the following read-only checks from an account with the appropriate permissions:

```bash
# Public S3 block at the account level
aws s3control get-public-access-block --account-id $(aws sts get-caller-identity --query 'Account' --output text)

# IMDSv2 enforcement (look for HttpTokens: required)
aws ec2 describe-instances --query 'Reservations[].Instances[].{ID:InstanceId,IMDS:MetadataOptions.HttpTokens}'

# Access keys older than 90 days
aws iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n' | while read u; do aws iam list-access-keys --user-name "$u"; done

# Root account access keys and MFA
aws iam get-account-summary
```

Expected result: `BlockPublicAcls`, `BlockPublicPolicy`, `IgnorePublicAcls`, `RestrictPublicBuckets` all `true`; every instance `HttpTokens: required`; no root access keys; root MFA enabled.

## 9. Certification Alignment

- **AWS Certified Solutions Architect - Associate** - account model, IAM, regions, shared responsibility model, core service families.
- **AWS Certified Advanced Networking - Specialty** - VPC, subnets, route tables, security groups, network ACLs, VPC Flow Logs (section 2.3 and section 7).
- **CompTIA Security+** - cloud security concepts, identity and access management, logging and monitoring.

## 10. Production Notes

- The AWS account ID is sensitive but not secret. Treat it as a scoping hint, not as a secret.
- `sts:GetCallerIdentity` is almost always allowed. Do not rely on blocking it.
- CloudTrail is per-region for management events; a complete trail must be configured in every region, or use an organization trail.
- GuardDuty is per-region and per-account by default; use an organization-level detector.
- CloudTrail data events (`s3:GetObject`, `s3:PutObject`, `lambda:Invoke`) are charged per event and disabled by default. Enable them only on sensitive buckets and functions.
- Log integrity matters: CloudTrail log file validation, S3 object lock on the trail bucket, and a separate log-archive account.

## 11. References

- AWS Shared Responsibility Model - https://aws.amazon.com/compliance/shared-responsibility-model/
- AWS IAM User Guide - https://docs.aws.amazon.com/IAM/latest/UserGuide/
- AWS CloudTrail User Guide - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/
- Amazon GuardDuty User Guide - https://docs.aws.amazon.com/guardduty/latest/ug/
- AWS Security Best Practices - https://docs.aws.amazon.com/security/
- AWS Well-Architected Framework - Security Pillar - https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/
