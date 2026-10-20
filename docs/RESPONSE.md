# Findings, response and live acceptance

## What the offline exercise proves

The demo renders the deployed policy templates, evaluates 27 explicit request contexts and runs four supported finding cases. Each response follows:

```text
new -> triaged -> approved by a different fictional reviewer
    -> simulated -> verified
                 -> verification_failed
verified / simulated / verification_failed -> rolled_back
```

Plans contain the resource and proposed changes. Before and after state, approval rationale and transition history are recorded locally. Self-approval and account/resource mismatches are rejected. Failed postconditions cannot be marked verified. Rollback restores the original in-memory state.

None of these transitions executes AWS writes. Fixture approvals are training data, not user or organisational approval. The report is neither signed nor tamper-proof.

## Four playbooks

| Event | Triage | Simulated response | Verification |
| --- | --- | --- | --- |
| GuardDuty SSH brute force | Identify the instance, actor/activity and business owner | Replace the fixture's groups with its approved quarantine group | Only that group remains in simulated state |
| Security Hub S3.8 failed control | Confirm intended public access and bucket owner | Enable BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy and RestrictPublicBuckets | All four simulated settings are true |
| Config required-tags failure | Obtain approved ownership/environment values | Add Owner and Environment without deleting unrelated tags | Values match the approved tag map |
| CloudTrail denied StopLogging | Review the principal, attempted change and denial context | Preserve existing logging configuration | Logging remains enabled; no change is claimed |

Real containment requires network and forensic judgment. A security-group change is not proof that every existing connection ended. Real S3 restrictions can interrupt intentional public workloads. Do not apply these training changes automatically to production.

The normalized fixtures are deliberately simplified and limited to the named playbooks. Unsupported controls/events fail the exercise rather than silently selecting a generic remediation.

## Authorised live validation checklist

This procedure is pending until a test organization and authorised access are available.

1. **Baseline readiness:** verify the four services in each selected account/region and confirm the archive receives fresh CloudTrail and Config records for each source account.
2. **SCP positive case:** use a workload identity with an existing IAM allow to perform a harmless read in an approved region, such as EC2 DescribeVpcs.
3. **SCP negative case:** use the same identity for the same read in a denied region. Verify the denial using account/role/region context and CloudTrail evidence. Do not infer policy causation from the word AccessDenied alone.
4. **Protected change:** test an approved low-impact control-change case in the sandbox, with an operator and the governance role. Avoid disabling actual logging just to prove a guardrail; use reviewed test resources or a separately approved maintenance window.
5. **Recovery:** verify the management-account process can remove only the lab's SCP attachments and restore the intended access.
6. **GuardDuty sample:** generate service-owned sample findings in an approved detector. Samples test the finding review path, not detection of real malicious activity.
7. **Security Hub:** inspect the active FSBP subscription and actual control results after Config has recorded resources. Controls can require time and supporting resources; initial enablement is not compliance.
8. **Config:** evaluate a designated lab resource missing required tags. Approve and apply tags through the normal change process, then capture the later compliant evaluation.
9. **Remediation:** record owner approval, actual commands/API actions, before/after evidence and an independently checked postcondition.

## Optional GuardDuty sample generation

This command is provided for a future authorised sandbox. It creates sample findings in AWS and is not run by the local demo or CI:

```text
aws guardduty create-sample-findings \
  --profile approved-sandbox-operator \
  --region eu-west-1 \
  --detector-id <actual-detector-id> \
  --finding-types UnauthorizedAccess:EC2/SSHBruteForce
```

Use your shell's line-continuation syntax or run it on one line. Keep sample evidence labelled as samples and separate from real incident records. The AWS API supports [CreateSampleFindings](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_CreateSampleFindings.html).

## Review record

For each live case retain: account/region, resource, finding/event ID, collection time, owner, reviewer, disposition, change approval reference, executed action, verification evidence and rollback decision.

Possible dispositions: confirmed issue, intentional configuration, accepted risk, insufficient evidence or sample/training event. Do not resolve a real finding solely because a local simulation passed.
