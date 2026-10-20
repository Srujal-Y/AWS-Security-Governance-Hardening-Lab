# Architecture and design decisions

## Accounts and trust

| Fictional account | Purpose | Control boundary |
| --- | --- | --- |
| `111111111111` Management | Own the existing organization and lab OUs/SCPs | SCPs do not constrain the management account |
| `222222222222` Security | Host the pre-existing GovernanceOperator identity | Identity, MFA and access lifecycle must be managed separately |
| `333333333333` LogArchive | Own the shared regional bucket and KMS key | Explicit account/role/service permissions control delivery |
| `444444444444` Sandbox | First workload target for controlled testing | Workloads OU SCPs apply after enforcement |
| `555555555555` ProductionModel | Second fictional workload account | Models a production boundary; it is not a production deployment |

The organization stack creates OUs and policies in an existing organization. It intentionally leaves account creation, account moves and organization feature changes outside Terraform ownership. These are administrative prerequisites with wider consequences than this lab.

In each account's primary region, the baseline creates `GovernanceAdministrator`. Its trust policy delegates only to one exact operator role in the Security account. The role receives the AWS-managed AdministratorAccess policy and a one-hour maximum session duration. It is an elevated lab change role, not a routine workload identity.

The SCP exception uses exact IAM role ARNs, not a wildcard account/name pattern. Role trust, attached/inline policies, boundaries, tags and passing the role are protected against other member-account principals by selected guardrail statements. The role uses an AWS-managed permission policy so a workload principal cannot edit a customer-managed policy version to change its permissions. The Security account's operator role and its own administrators remain a separate trust boundary.

## Regional design

One primary-region baseline creates the account's multi-region CloudTrail trail. Regional GuardDuty, Security Hub CSPM and Config deployments must be repeated in every monitored region with separate state. A secondary baseline does not create a duplicate global governance role or another multi-region trail.

Config records supported resource types continuously. Legacy global IAM resource recording is enabled only in the primary region. Choose a primary region that supports recording those types; the examples use `eu-west-1`.

The regional archive must precede its member baselines. It authorises source accounts explicitly and uses stable trail/recorder names. Keep `name_prefix` consistent across all stacks.

## Data flow and encryption

CloudTrail delivers management events and digest files under `cloudtrail/AWSLogs/<account>/`. Config delivers under `config/AWSLogs/<account>/Config/`. Per-account bucket statements bind delivery to each account's prefix.

The central bucket blocks public access, requires TLS, enforces bucket ownership, versions objects and uses a rotating customer-managed KMS key. CloudTrail key use is constrained by named trail source ARNs and matching encryption contexts. Config delivery supports both the named recorder role and the documented service-principal fallback. Cross-account permissions are needed in the role, bucket policy and key policy.

Default lifecycle retention is 90 days for current and noncurrent object versions. This is a configurable lab retention choice, not a regulatory retention policy. There is no Object Lock, independent immutable replica, signed evidence repository or organizational retention approval. `prevent_destroy` and `force_destroy=false` reduce accidental Terraform deletion; they do not prevent every privileged AWS change.

## Detection and posture

- CloudTrail records account management activity across regions; S3/object data events are not enabled by this trail.
- GuardDuty has a detector and S3 protection; other protection plans are not explicitly configured by this lab.
- Security Hub CSPM subscribes to AWS Foundational Security Best Practices. Enabling a standard does not make every control compliant.
- Config records inventory and evaluates public S3 reads/writes, encrypted EBS volumes, unrestricted SSH, CloudTrail presence and required tags.

The Security account is not a delegated administrator, organization auto-enrollment manager or findings aggregator. Each baseline is managed per account/region, making ownership and scope explicit.

## Offline trust boundary

The evaluator renders the same two templates Terraform consumes. It supports a strict subset of deny-policy syntax and rejects unknown fields/operators. Explicit context includes member/management account and service-linked-role status; these are scenario inputs, not identities independently verified by the evaluator.

The four event fixtures are simplified fictional envelopes for the implemented playbooks. They are not complete AWS ingestion payloads and must not be submitted to BatchImportFindings unchanged.

Response exercises operate on deep copies of in-memory state. A distinct fictional reviewer, approval rationale and observed postcondition are required. Rollback restores the original simulated state. These mechanisms teach a review workflow; they do not provide production authorisation, tamper-proof audit trails or remote execution.

## Sources

- [SCP behaviour and scope](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [CloudTrail bucket policy requirements](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html)
- [CloudTrail KMS key policies](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-kms-key-policy-for-cloudtrail.html)
- [Config cross-account S3 delivery](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-policy.html)
- [Config KMS permissions](https://docs.aws.amazon.com/config/latest/developerguide/s3-kms-key-policy.html)
