# AWS Security & Governance Hardening Lab

**SYNTHETIC OFFLINE EXERCISE. No AWS resources were deployed or changed.**

Status: passed | Completed: 2026-10-20T17:11:21.641932+00:00

Policy cases: 27/27 passed.
Response exercises: 4/4 verified in memory.

## Policy outcomes

| Case | Expected | Observed | Pass |
| --- | --- | --- | --- |
| approved-region | not&#95;denied&#95;by&#95;lab&#95;scps | not&#95;denied&#95;by&#95;lab&#95;scps | True |
| outside-region | explicit&#95;deny | explicit&#95;deny | True |
| secondary-approved-region | not&#95;denied&#95;by&#95;lab&#95;scps | not&#95;denied&#95;by&#95;lab&#95;scps | True |
| global-iam | not&#95;denied&#95;by&#95;lab&#95;scps | not&#95;denied&#95;by&#95;lab&#95;scps | True |
| global-route53 | not&#95;denied&#95;by&#95;lab&#95;scps | not&#95;denied&#95;by&#95;lab&#95;scps | True |
| deny-cloudtrail-stoplogging | explicit&#95;deny | explicit&#95;deny | True |
| deny-cloudtrail-deletetrail | explicit&#95;deny | explicit&#95;deny | True |
| deny-config-stopconfigurationrecorder | explicit&#95;deny | explicit&#95;deny | True |
| deny-config-putconfigurationrecorder | explicit&#95;deny | explicit&#95;deny | True |
| deny-guardduty-deletedetector | explicit&#95;deny | explicit&#95;deny | True |
| deny-guardduty-updatedetector | explicit&#95;deny | explicit&#95;deny | True |
| deny-securityhub-disablesecurityhub | explicit&#95;deny | explicit&#95;deny | True |
| deny-securityhub-batchdisablestandards | explicit&#95;deny | explicit&#95;deny | True |
| deny-kms-schedulekeydeletion | explicit&#95;deny | explicit&#95;deny | True |
| deny-kms-putkeypolicy | explicit&#95;deny | explicit&#95;deny | True |
| approved-administrator-change | not&#95;denied&#95;by&#95;lab&#95;scps | not&#95;denied&#95;by&#95;lab&#95;scps | True |
| administrator-still-region-restricted | explicit&#95;deny | explicit&#95;deny | True |
| governance-trust-protected | explicit&#95;deny | explicit&#95;deny | True |
| governance-role-creation-protected | explicit&#95;deny | explicit&#95;deny | True |
| workload-role-not-governance-role | not&#95;denied&#95;by&#95;lab&#95;scps | not&#95;denied&#95;by&#95;lab&#95;scps | True |
| cannot-leave-organization | explicit&#95;deny | explicit&#95;deny | True |
| root-access-key-blocked | explicit&#95;deny | explicit&#95;deny | True |
| management-outside-scp-scope | outside&#95;scp&#95;scope | outside&#95;scp&#95;scope | True |
| service-linked-role-outside-scp-scope | outside&#95;scp&#95;scope | outside&#95;scp&#95;scope | True |
| lookalike-admin-not-exempt | explicit&#95;deny | explicit&#95;deny | True |
| other-account-admin-not-exempt | explicit&#95;deny | explicit&#95;deny | True |
| case-insensitive-actions | explicit&#95;deny | explicit&#95;deny | True |

## Findings and simulated response

### HIGH - An attempt to stop audit logging was denied

- Resource: arn:aws:cloudtrail:eu-west-1:444444444444:trail/govlab-trail
- Risk: A blocked attempt can still indicate misuse of credentials or an incorrect change process.
- Remediation: Verify continued logging, review the actor and denial reason, and preserve the event. A denial alone does not establish which policy caused it.
- Workflow: verified (simulation only)

Evidence and before/after state:

    {
      "id": "cloudtrail-blocked-tamper",
      "finding": {
        "id": "8f04efcbfdcd748aedf5",
        "source": "aws.cloudtrail",
        "account_id": "444444444444",
        "region": "eu-west-1",
        "resource": "arn:aws:cloudtrail:eu-west-1:444444444444:trail/govlab-trail",
        "issue": "An attempt to stop audit logging was denied",
        "severity": "high",
        "risk": "A blocked attempt can still indicate misuse of credentials or an incorrect change process.",
        "remediation": "Verify continued logging, review the actor and denial reason, and preserve the event. A denial alone does not establish which policy caused it.",
        "playbook": "verify-blocked-tamper",
        "evidence": {
          "eventSource": "cloudtrail.amazonaws.com",
          "eventName": "StopLogging",
          "errorCode": "AccessDenied",
          "userIdentity": {
            "arn": "arn:aws:iam::444444444444:role/WorkloadOperator"
          },
          "requestParameters": {
            "name": "arn:aws:cloudtrail:eu-west-1:444444444444:trail/govlab-trail"
          }
        },
        "synthetic": true
      },
      "exercise": {
        "finding_id": "8f04efcbfdcd748aedf5",
        "status": "verified",
        "mode": "simulation_only",
        "before": {
          "resource": "arn:aws:cloudtrail:eu-west-1:444444444444:trail/govlab-trail",
          "account_id": "444444444444",
          "logging_enabled": true,
          "region": "eu-west-1"
        },
        "after": {
          "resource": "arn:aws:cloudtrail:eu-west-1:444444444444:trail/govlab-trail",
          "account_id": "444444444444",
          "logging_enabled": true,
          "region": "eu-west-1"
        },
        "plan": {
          "playbook": "verify-blocked-tamper",
          "resource": "arn:aws:cloudtrail:eu-west-1:444444444444:trail/govlab-trail",
          "changes": {},
          "execution": "simulation_only"
        },
        "history": [
          {
            "step": "new",
            "actor": "demo-analyst"
          },
          {
            "step": "triaged",
            "actor": "demo-analyst"
          },
          {
            "step": "approved",
            "actor": "demo-independent-reviewer",
            "reason": "Approved fictional training scenario",
            "approval_mode": "fictional_training"
          },
          {
            "step": "simulated",
            "actor": "offline-engine"
          },
          {
            "step": "verified",
            "actor": "offline-verifier"
          }
        ]
      }
    }

### HIGH - UnauthorizedAccess:EC2/SSHBruteForce

- Resource: i-00000000000000001
- Risk: Suspected instance activity requires investigation and approved containment.
- Remediation: Review the sample finding, preserve evidence, and simulate assigning the approved quarantine security group.
- Workflow: verified (simulation only)

Evidence and before/after state:

    {
      "id": "guardduty-containment",
      "finding": {
        "id": "16f2d47ab82ab1a32896",
        "source": "aws.guardduty",
        "account_id": "444444444444",
        "region": "eu-west-1",
        "resource": "i-00000000000000001",
        "issue": "UnauthorizedAccess:EC2/SSHBruteForce",
        "severity": "high",
        "risk": "Suspected instance activity requires investigation and approved containment.",
        "remediation": "Review the sample finding, preserve evidence, and simulate assigning the approved quarantine security group.",
        "playbook": "quarantine-ec2",
        "evidence": {
          "id": "fictional-gd-001",
          "type": "UnauthorizedAccess:EC2/SSHBruteForce",
          "severity": 8,
          "resource": {
            "instanceDetails": {
              "instanceId": "i-00000000000000001"
            }
          },
          "service": {
            "additionalInfo": {
              "sample": true
            }
          }
        },
        "synthetic": true
      },
      "exercise": {
        "finding_id": "16f2d47ab82ab1a32896",
        "status": "verified",
        "mode": "simulation_only",
        "before": {
          "resource": "i-00000000000000001",
          "account_id": "444444444444",
          "security_group_ids": [
            "sg-00000000000000001"
          ],
          "region": "eu-west-1"
        },
        "after": {
          "resource": "i-00000000000000001",
          "account_id": "444444444444",
          "security_group_ids": [
            "sg-00000000000000002"
          ],
          "region": "eu-west-1"
        },
        "plan": {
          "playbook": "quarantine-ec2",
          "resource": "i-00000000000000001",
          "changes": {
            "security_group_ids": [
              "sg-00000000000000002"
            ]
          },
          "execution": "simulation_only"
        },
        "history": [
          {
            "step": "new",
            "actor": "demo-analyst"
          },
          {
            "step": "triaged",
            "actor": "demo-analyst"
          },
          {
            "step": "approved",
            "actor": "demo-independent-reviewer",
            "reason": "Approved fictional training scenario",
            "approval_mode": "fictional_training"
          },
          {
            "step": "simulated",
            "actor": "offline-engine"
          },
          {
            "step": "verified",
            "actor": "offline-verifier"
          }
        ]
      }
    }

### HIGH - S3 bucket public access settings require review

- Resource: arn:aws:s3:::fictional-governance-bucket
- Risk: Unintended public bucket configuration can expose sensitive data.
- Remediation: Confirm the bucket&#x27;s purpose and simulate all four bucket Block Public Access settings.
- Workflow: verified (simulation only)

Evidence and before/after state:

    {
      "id": "securityhub-public-access",
      "finding": {
        "id": "b3a0bc0a846968db04a7",
        "source": "aws.securityhub",
        "account_id": "444444444444",
        "region": "eu-west-1",
        "resource": "arn:aws:s3:::fictional-governance-bucket",
        "issue": "S3 bucket public access settings require review",
        "severity": "high",
        "risk": "Unintended public bucket configuration can expose sensitive data.",
        "remediation": "Confirm the bucket's purpose and simulate all four bucket Block Public Access settings.",
        "playbook": "block-public-s3",
        "evidence": {
          "findings": [
            {
              "SchemaVersion": "2018-10-08",
              "Id": "fictional-sh-001",
              "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/securityhub",
              "GeneratorId": "security-control/S3.8",
              "AwsAccountId": "444444444444",
              "Title": "S3 bucket public access settings require review",
              "Severity": {
                "Label": "HIGH"
              },
              "Compliance": {
                "Status": "FAILED"
              },
              "RecordState": "ACTIVE",
              "Resources": [
                {
                  "Type": "AwsS3Bucket",
                  "Id": "arn:aws:s3:::fictional-governance-bucket"
                }
              ]
            }
          ]
        },
        "synthetic": true
      },
      "exercise": {
        "finding_id": "b3a0bc0a846968db04a7",
        "status": "verified",
        "mode": "simulation_only",
        "before": {
          "resource": "arn:aws:s3:::fictional-governance-bucket",
          "account_id": "444444444444",
          "public_access_block": {
            "BlockPublicAcls": false,
            "IgnorePublicAcls": false,
            "BlockPublicPolicy": false,
            "RestrictPublicBuckets": false
          },
          "region": "eu-west-1"
        },
        "after": {
          "resource": "arn:aws:s3:::fictional-governance-bucket",
          "account_id": "444444444444",
          "public_access_block": {
            "BlockPublicAcls": true,
            "IgnorePublicAcls": true,
            "BlockPublicPolicy": true,
            "RestrictPublicBuckets": true
          },
          "region": "eu-west-1"
        },
        "plan": {
          "playbook": "block-public-s3",
          "resource": "arn:aws:s3:::fictional-governance-bucket",
          "changes": {
            "public_access_block": {
              "BlockPublicAcls": true,
              "IgnorePublicAcls": true,
              "BlockPublicPolicy": true,
              "RestrictPublicBuckets": true
            }
          },
          "execution": "simulation_only"
        },
        "history": [
          {
            "step": "new",
            "actor": "demo-analyst"
          },
          {
            "step": "triaged",
            "actor": "demo-analyst"
          },
          {
            "step": "approved",
            "actor": "demo-independent-reviewer",
            "reason": "Approved fictional training scenario",
            "approval_mode": "fictional_training"
          },
          {
            "step": "simulated",
            "actor": "offline-engine"
          },
          {
            "step": "verified",
            "actor": "offline-verifier"
          }
        ]
      }
    }

### MEDIUM - Required ownership and environment tags are missing

- Resource: i-00000000000000001
- Risk: Missing ownership metadata delays accountability and incident response.
- Remediation: Obtain approved Owner and Environment values and simulate adding the missing tags.
- Workflow: verified (simulation only)

Evidence and before/after state:

    {
      "id": "config-required-tags",
      "finding": {
        "id": "89e3f402f4fb1f608083",
        "source": "aws.config",
        "account_id": "444444444444",
        "region": "eu-west-1",
        "resource": "i-00000000000000001",
        "issue": "Required ownership and environment tags are missing",
        "severity": "medium",
        "risk": "Missing ownership metadata delays accountability and incident response.",
        "remediation": "Obtain approved Owner and Environment values and simulate adding the missing tags.",
        "playbook": "apply-required-tags",
        "evidence": {
          "configRuleName": "govlab-required-tags",
          "resourceId": "i-00000000000000001",
          "resourceType": "AWS::EC2::Instance",
          "newEvaluationResult": {
            "complianceType": "NON_COMPLIANT"
          }
        },
        "synthetic": true
      },
      "exercise": {
        "finding_id": "89e3f402f4fb1f608083",
        "status": "verified",
        "mode": "simulation_only",
        "before": {
          "resource": "i-00000000000000001",
          "account_id": "444444444444",
          "tags": {
            "Environment": "lab"
          },
          "region": "eu-west-1"
        },
        "after": {
          "resource": "i-00000000000000001",
          "account_id": "444444444444",
          "tags": {
            "Environment": "lab",
            "Owner": "security-engineering"
          },
          "region": "eu-west-1"
        },
        "plan": {
          "playbook": "apply-required-tags",
          "resource": "i-00000000000000001",
          "changes": {
            "tags": {
              "Environment": "lab",
              "Owner": "security-engineering"
            }
          },
          "execution": "simulation_only"
        },
        "history": [
          {
            "step": "new",
            "actor": "demo-analyst"
          },
          {
            "step": "triaged",
            "actor": "demo-analyst"
          },
          {
            "step": "approved",
            "actor": "demo-independent-reviewer",
            "reason": "Approved fictional training scenario",
            "approval_mode": "fictional_training"
          },
          {
            "step": "simulated",
            "actor": "offline-engine"
          },
          {
            "step": "verified",
            "actor": "offline-verifier"
          }
        ]
      }
    }

## Errors

None.

## Interpretation

SCP results cover only the supplied deny policies and context. Not denied does not mean IAM permission is granted. Fictional workflow approvals are not operational authorisations.
