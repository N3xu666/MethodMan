# AWS Defense and Detection

> [!CAUTION]
> This file is for authorized security testing of AWS accounts you own or have explicit written permission to assess. Do not use these techniques against accounts, resources, or services you do not own or have permission to test.

## 1. Overview

AWS defense is not a single service. It is a stack of overlapping controls: identity (IAM, SCPs), network (security groups, NACLs, VPC Flow Logs), data (encryption, bucket policies, KMS), logging (CloudTrail, VPC Flow Logs, S3 access logs), detection (GuardDuty, Security Hub, Config, Macie, Inspector, Detective, Access Analyzer, Security Lake), and response (EventBridge rules, Lambda auto-remediation, Systems Manager Incident Manager). No single control is sufficient; the value comes from the overlap.

This file is the defense-side counterpart to the rest of the AWS subcategory. It answers three questions:

1. What detection services exist, and what does each one actually see?
2. How does an attacker try to evade each one, and where does the evasion leave traces?
3. How does an incident-response workflow look when the incident is in AWS, not on a Linux host?

The offensive track is not absent. Section 2 and section 3 describe how an attacker enumerates the detection stack and which controls are most often missing. The verification section (section 8) is a read-only check that a defender can run against their own account.

## 2. Reconnaissance / Enumeration

### 2.1 Mapping the logging and detection stack

The first step for an attacker (and for a defender performing a self-assessment) is to enumerate which logging and detection services are enabled, in which regions, and with what coverage. Every call below is read-only and returns a small JSON document.

```bash
# CloudTrail: list trails, check multi-region and logging status
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name <trail-name>

# GuardDuty: list detectors, check status per region
aws guardduty list-detectors
aws guardduty get-detector --detector-id <id>

# Security Hub: list hubs and enabled standards
aws securityhub describe-hub
aws securityhub get-enabled-standards

# AWS Config: list recorders and rules
aws configservice describe-configuration-recorders
aws configservice describe-config-rules

# Access Analyzer: list analyzers (account-level and organization-level)
aws accessanalyzer list-analyzers

# Macie: list sessions and findings
aws macie2 get-macie-session

# Inspector: list coverage and findings
aws inspector2 batch-get-account-status

# Security Lake: list data lakes and subscribers
aws securitylake list-data-lakes
```

### 2.2 Identifying gaps

The reconnaissance output is most useful when read as a coverage map. The gaps that matter most, in order:

- **CloudTrail is single-region or not organization-wide.** An attacker who creates resources in a region with no trail leaves no management-event record. An organization trail with `IsOrganizationTrail: true` closes this gap.
- **CloudTrail log file validation disabled.** `LogFileValidationEnabled: false` means an attacker who gains write access to the S3 trail bucket can rewrite history without a cryptographic mismatch.
- **S3 data events disabled on sensitive buckets.** `s3:GetObject` and `s3:PutObject` are not recorded by default. Data access on buckets holding secrets is invisible without data events.
- **GuardDuty is per-account, not organization-wide.** New accounts in the organization are not covered by default, which is exactly where an attacker creates resources.
- **Security Hub standards partially enabled.** CIS AWS Foundations and AWS Foundational Security Best Practices are the two baseline standards. A missing standard means the controls it covers are not being evaluated.
- **Config recorders disabled in some regions.** Configuration drift is not recorded, and conformance packs do not run.
- **No EventBridge rules for high-severity findings.** GuardDuty and Security Hub findings exist, but nobody is paged when they fire.

### 2.3 Enumerating the responders

Detection is only half of the stack. The response side is equally enumerable:

```bash
# EventBridge rules (which findings trigger an action)
aws events list-rules

# Lambda functions that might be auto-remediation responders
aws lambda list-functions --query 'Functions[?starts_with(FunctionName, `auto-remediate`)].FunctionName'

# Systems Manager Incident Manager: response plans and contacts
aws ssm-incidents list-response-plans
aws ssm-contacts list-contacts
```

An attacker who finds that detection fires but no responder runs has found a monitoring theatre: the findings are recorded, but nothing happens. In practice, this is the most common detection gap in real AWS accounts.

## 3. Common Attack Vectors

### 3.1 Defense evasion, mapped to detection services

Every defense-evasion action in AWS maps to one or more detection services. The attacker's goal is to find the action that is not covered, or to cover the trace it leaves.

- **`cloudtrail:StopLogging` / `cloudtrail:DeleteTrail`** - recorded by CloudTrail itself (if the trail is still logging when the call is made) and by GuardDuty (`Stealth:IAMUser/CloudTrailLoggingDisabled`). Defense: SCP-deny both calls, and configure CloudTrail to log to a separate log-archive account.
- **`guardduty:DeleteDetector` / `guardduty:UpdateDetector`** - recorded by CloudTrail and by Security Hub (control `GuardDuty.1`). Defense: SCP-deny, and organization-level detector that cannot be disabled by a member account.
- **`config:StopConfigurationRecorder` / `config:DeleteConfigurationRecorder`** - recorded by CloudTrail; Security Hub control `Config.1`. Defense: SCP-deny.
- **`s3:PutBucketLogging` with an empty configuration** - recorded by CloudTrail. Defense: SCP-deny on sensitive buckets, and monitor the event.
- **`iam:CreateAccessKey` for a role that should not have long-lived credentials** - recorded by CloudTrail; GuardDuty `Persistence:IAMUser/UserPermissions`. Defense: SCP-deny for non-break-glass identities.
- **`sts:AssumeRole` from an unusual IP or user agent** - GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` and `Discovery:IAMUser/AnomalousBehavior`. Defense: baseline known-good IPs and user agents, and alert on deviation.

### 3.2 Log tampering

If the trail bucket is in the same account and the attacker has write access to it, the attacker can delete or rewrite log files. Three controls make this visible or impossible:

- **Log file validation** produces a digest file every hour. A rewritten log file fails validation.
- **S3 Object Lock** in compliance mode prevents deletion and overwrite for a defined retention period.
- **A separate log-archive account** with a bucket policy that denies `s3:DeleteObject` and `s3:PutBucketPolicy` to anyone outside the log-archive account's break-glass role. The production account can write logs but cannot modify them.

### 3.3 Detection service blind spots

Each detection service has a documented scope and a documented blind spot. The important ones:

- **GuardDuty does not inspect encrypted S3 objects** (it cannot decrypt SSE-KMS without permission), so malware in an encrypted object is invisible.
- **GuardDuty Malware Protection for S3** is a separate feature and must be enabled per bucket.
- **CloudTrail data events are opt-in per bucket and per function.** A bucket without data events is invisible to CloudTrail.
- **VPC Flow Logs do not capture the instance metadata IP (`169.254.169.254`)**, because the metadata service is link-local and bypasses the VPC network interface. IMDS credential theft is invisible to VPC Flow Logs; GuardDuty `InstanceCredentialExfiltration` is the compensating control.
- **AWS Config evaluates configuration, not activity.** A resource that is misconfigured but not used does not trigger a Config rule; a resource that is used in a misconfigured way may be invisible if no Config rule covers that use.

### 3.4 Detection evasion through legitimate services

An attacker who has compromised an identity can sometimes use legitimate AWS services to hide:

- **SSM Session Manager** (see `04 EC2 and Compute Attacks.md`) produces CloudTrail `StartSession` events but no network-level traffic to port 22.
- **Lambda invocation via EventBridge** produces `InvokeFunction` events but no network-level traffic from an attacker IP.
- **S3 presigned URLs** produce `GetObject` events under the signer's identity, not the requester's, which can obscure attribution.
- **Cross-account role assumption** produces an `AssumeRole` event in both accounts but a single `GetCallerIdentity` from the target identity in the destination account.

## 4. Exploitation Recipes

### 4.1 Verifying that CloudTrail actually logs what you think

Precondition: read access to CloudTrail and to the trail's S3 bucket. The goal is not to attack CloudTrail; it is to confirm that a management event the defender expects to see is actually recorded. Test with a harmless call (`sts:GetCallerIdentity`) in a region the trail should cover.

```bash
# Generate a known event
aws sts get-caller-identity --region eu-central-1

# Search CloudTrail for that event in that region
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity \
    --region eu-central-1 \
    --start-time 2026-10-22T00:00:00Z \
    --query 'Events[].{Time:EventTime,User:Username,Source:EventSource}'
```

If the event is not in `lookup-events`, either the trail does not cover the region (single-region trail) or the event is outside the 90-day `lookup-events` window and must be read from the S3 bucket directly. Both outcomes are findings.

### 4.2 Verifying GuardDuty finding delivery

Precondition: read access to GuardDuty and to EventBridge. Generate a sample finding with `CreateSampleFindings`, then confirm that it appears in GuardDuty and, if an EventBridge rule is configured, that the rule matches.

```bash
# Create a sample finding (safe: it is a synthetic finding, not a real attack)
aws guardduty create-sample-findings \
    --detector-id <detector-id> \
    --finding-types UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration

# List recent findings
aws guardduty list-findings --detector-id <detector-id> --finding-criteria '{"Criterion":{"service.archived":{"Eq":["false"]}}}'

# Check that the EventBridge rule matches (look for a recent invocation in the rule's metrics)
aws events list-rules --query 'Rules[?EventPattern!=null].{Name:Name,State:State,Pattern:EventPattern}'
```

Expected result: the sample finding appears in `list-findings`, and the EventBridge rule for GuardDuty findings (`source: aws.guardduty`, `detail-type: GuardDuty Finding`) is in state `ENABLED`.

### 4.3 Testing log integrity

Precondition: read access to the trail's S3 bucket. Log file validation produces a `manifest.json` alongside each log file. The `validate-logs` command compares the digest file to the log file.

```bash
# Start a validation job
aws cloudtrail validate-logs \
    --trail-arn arn:aws:cloudtrail:us-east-1:123456789012:trail/example-trail \
    --start-time 2026-10-21T00:00:00Z \
    --end-time 2026-10-22T00:00:00Z \
    --verbose
```

Expected result: `Logs validated successfully.` Any other outcome (a missing digest, a digest mismatch) means the log has been modified after delivery, which is the exact signature of log tampering.

### 4.4 Verifying Config rule coverage

Precondition: read access to AWS Config. The goal is to confirm that a misconfiguration the defender cares about is actually detected.

```bash
# List all Config rules and their compliance state
aws configservice describe-config-rules --query 'ConfigRules[].{Name:ConfigRuleName,State:ConfigRuleState}'
aws configservice describe-compliance-by-config-rule --query 'ComplianceByConfigRules[?Compliance.ComplianceType!=`COMPLIANT`]'
```

Expected result: no rule in state `NOT_APPLICABLE` on a resource that should be evaluated, and no non-compliant resource that the defender thought was covered. A rule that is `ACTIVE` but `NOT_APPLICABLE` is a coverage gap, not a pass.

### 4.5 EventBridge rule for auto-remediation

Precondition: the defender wants to respond automatically to a specific finding. The recipe below is the pattern: an EventBridge rule matches a GuardDuty finding, and a Lambda function performs a remediation (for example, disabling an access key, isolating an instance).

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "type": ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"],
    "severity": [{"numeric": [">=", 7]}]
  }
}
```

The rule body is JSON; the target is a Lambda function with an IAM role that allows the remediation API calls. The Lambda function must be idempotent and must log its own actions to CloudTrail (every Lambda invocation does).

## 5. Post-Exploitation

After a detection event fires, the attacker's behavior determines the outcome. Two patterns:

- **The attacker does not know the alert fired.** The responder has a window (minutes to hours) to isolate the resource, revoke the credential, and preserve evidence. Speed is the entire game.
- **The attacker notices and accelerates.** The attacker creates persistence (a new IAM user), escalates (a new policy version), or exfiltrates (a shared snapshot) before the responder can react. This is why auto-remediation matters: the responder must be faster than the attacker.

From the defender's perspective, the post-exploitation phase is the incident-response phase:

1. **Contain.** Disable the compromised access key (`iam:UpdateAccessKey Status=Inactive`), detach the compromised role session (`aws sts revoke-session` with the session ID from CloudTrail), isolate the instance (`ec2:ModifyInstanceAttribute` to a quarantine security group with no egress).
2. **Preserve.** Snapshot the EBS volume (`ec2:CreateSnapshot`), export the CloudTrail events for the account and time range, export GuardDuty findings, and copy the trail log files from the S3 bucket. Preserve evidence before changing anything else.
3. **Eradicate.** Delete the attacker-created IAM user, role, policy version, or access key. Rotate every credential that was reachable from the compromised identity.
4. **Recover.** Restore from a known-good snapshot, re-deploy the affected workloads, and re-validate the controls.
5. **Learn.** Update the detection rules to cover the gap that was exploited. A post-mortem that does not change a rule is a post-mortem that will repeat.

## 6. Preventive Controls

The preventive controls in this file are organization-level guardrails. They are not detection; they are the reason a detection service has fewer events to analyze.

- **SCP: deny the detection-disable APIs.** `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `guardduty:DeleteDetector`, `guardduty:UpdateDetector`, `config:StopConfigurationRecorder`, `config:DeleteConfigurationRecorder`, `securityhub:DisableSecurityHub`, `securityhub:DeleteInvitations`. Attach to the organization root or to every OU except the security OU.
- **Organization trail.** `IsOrganizationTrail: true`, all regions, log file validation enabled, delivery to a dedicated log-archive account with S3 Object Lock.
- **Organization GuardDuty.** The delegated administrator account manages the detector for every member account. Member accounts cannot disable it.
- **Organization Security Hub.** The delegated administrator account manages the standards for every member account.
- **Organization Config.** The delegated administrator account manages the recorder and conformance packs for every member account.
- **Access Analyzer at the organization level.** The organization-level analyzer surfaces external access from every member account in one place.
- **Macie with an organization administrator.** Macie scans S3 for sensitive data; without the organization administrator, member accounts must enable it themselves, which they often do not.
- **Security Lake for centralized logs.** Security Lake normalizes CloudTrail, VPC Flow Logs, Route 53 Resolver logs, and GuardDuty findings into a single Open Cybersecurity Schema Framework (OCSF) format, which can be queried with Athena and consumed by third-party SIEMs.

## 7. Detection Controls

The detection controls are the services themselves. This section is the map; the sections above are the detail.

- **CloudTrail** - management events (always) and data events (opt-in). The authoritative record of every AWS API call.
- **GuardDuty** - machine learning and threat-intelligence findings across CloudTrail, VPC Flow Logs, DNS logs, EKS audit logs, S3 data events, and malware protection. The primary threat-detection service.
- **Security Hub** - aggregates findings from GuardDuty, Config, Inspector, Macie, IAM Access Analyzer, and Firewall Manager. Provides standards-based scoring (CIS, AWS Foundational Security Best Practices, PCI DSS).
- **AWS Config** - configuration history and compliance rules. Detects drift, not activity. Conformance packs bundle rules for a standard.
- **IAM Access Analyzer** - finds resources shared with external principals (S3 buckets, IAM roles, KMS keys, SQS queues, Secrets Manager secrets). Account-level and organization-level analyzers.
- **Macie** - sensitive-data discovery in S3 (PII, credentials, financial data). Uses machine learning and pattern matching.
- **Inspector** - vulnerability scanning for EC2 instances, ECR container images, and Lambda functions.
- **Detective** - investigation and root-cause analysis. Builds a graph of resource behavior and finding context.
- **Security Lake** - centralized, normalized log storage in OCSF format, queryable with Athena.

The relationship between them: CloudTrail and VPC Flow Logs are the raw data; GuardDuty, Config, Macie, and Inspector are the analyzers; Security Hub is the aggregator; Detective is the investigator; Security Lake is the archive.

## 8. Verification

Read-only checks to confirm the detection stack is enabled, organization-wide, and covers the regions that matter.

```bash
# CloudTrail: organization trail, multi-region, validation, logging
aws cloudtrail describe-trails --query 'trailList[].{Name:Name,IsOrg:IsOrganizationTrail,MultiRegion:IsMultiRegionTrail,Validation:LogFileValidationEnabled,HomeRegion:HomeRegion}'
aws cloudtrail get-trail-status --name <trail-name> --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}'

# GuardDuty: detectors in every region, organization-administered
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
    echo "=== $r ==="
    aws guardduty list-detectors --region "$r"
done

# Security Hub: standards enabled
aws securityhub get-enabled-standards

# Config: recorder status in every region
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
    aws configservice describe-configuration-recorder-status --region "$r" --query 'ConfigurationRecordersStatus[].{Name:name,Recording:recording}'
done

# Access Analyzer: organization-level analyzer present
aws accessanalyzer list-analyzers --type ORGANIZATION
```

Expected result: one organization trail with `IsOrg: true`, `MultiRegion: true`, `Validation: true`, and `IsLogging: true`; a GuardDuty detector in every region; at least the CIS and Foundational Security Best Practices standards in Security Hub; every Config recorder in state `recording: true`; and an organization-level Access Analyzer.

## 9. Certification Alignment

- **AWS Certified Security - Specialty** - the primary certification for this file. CloudTrail, GuardDuty, Security Hub, Config, Macie, Inspector, Access Analyzer, incident response.
- **AWS Certified Solutions Architect - Associate** - the shared responsibility model and the logging baseline.
- **CompTIA Security+** - monitoring, detection, incident response, logging.
- **CompTIA CySA+** - threat detection, SIEM concepts, incident response (the AWS services map to the general categories).

## 10. Production Notes

- CloudTrail `lookup-events` covers 90 days. Older events must be read from the S3 bucket with Athena or a SIEM.
- GuardDuty findings are regional. An organization-level detector does not merge findings into one region; Security Hub aggregates them across regions.
- Security Hub findings are also regional. Use the cross-region aggregation feature to bring them into one home region.
- Config rule evaluation is not real-time. Most rules evaluate on a schedule (every 1, 3, or 24 hours), and some evaluate on resource change. A rule that appears to be green may simply not have run yet.
- Macie charges per GB scanned. Enable it on buckets with sensitive data, not on every bucket.
- Inspector is regional and per-resource. Coverage is a first-class metric: an instance without the Inspector agent is not scanned.

## 11. References

- AWS CloudTrail User Guide - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/
- Amazon GuardDuty User Guide - https://docs.aws.amazon.com/guardduty/latest/ug/
- AWS Security Hub User Guide - https://docs.aws.amazon.com/securityhub/latest/userguide/
- AWS Config Developer Guide - https://docs.aws.amazon.com/config/latest/developerguide/
- IAM Access Analyzer - https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html
- Amazon Macie User Guide - https://docs.aws.amazon.com/macie/latest/user/
- Amazon Inspector User Guide - https://docs.aws.amazon.com/inspector/latest/user/
- Amazon Detective User Guide - https://docs.aws.amazon.com/detective/latest/userguide/
- Amazon Security Lake User Guide - https://docs.aws.amazon.com/security-lake/latest/userguide/
- AWS Security Incident Response Guide - https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/
