# Deployment and operation

## Offline validation first

Install Python dependencies as described in the README. Initialise provider schemas in each root; these commands download providers and do not create AWS resources:

```powershell
terraform -chdir=infra/organization init -backend=false -input=false
terraform -chdir=infra/log-archive init -backend=false -input=false
terraform -chdir=infra/account-baseline init -backend=false -input=false
.\.venv\Scripts\python.exe scripts/verify.py
```

All `.tftest.hcl` runs use a mocked AWS provider and `command = plan`. The lock files pin the provider. No credentials are needed for these tests.

## Live prerequisites

- Existing commercial-partition AWS organization with all features and SCPs enabled.
- Existing Management, Security, LogArchive and approved workload accounts. The fictional IDs in example files must be replaced.
- An established Security-account `GovernanceOperator` role controlled by your identity process, with enforced human authentication and permission to assume the named member governance roles.
- Approved deployment roles and short-lived AWS profiles for each stack/account. Deployment requires write permissions; no misleading single “least-privilege deployment policy” is supplied for all possible account configurations.
- An inventory of existing CloudTrail trails, Config recorders/channels, GuardDuty detectors and Security Hub enablement. Import existing resources into approved Terraform ownership or use a clean sandbox. Do not create conflicting singleton resources blindly.
- Agreed allowed regions, retention, expected service costs and a live test plan.

AWS Config recording/evaluations, GuardDuty, Security Hub CSPM, KMS and S3 storage/requests can incur charges. CloudTrail cost depends on configuration and existing trails. The lab makes no free-tier guarantee. No chargeable resources were created during local validation.

## Isolate state

Use a separate checkout or approved backend key for every account/region/root combination, for example:

```text
organization/management/terraform.tfstate
log-archive/333333333333/eu-west-1/terraform.tfstate
account-baseline/444444444444/eu-west-1/terraform.tfstate
account-baseline/444444444444/eu-central-1/terraform.tfstate
```

State is local by default. Before shared use, configure an approved encrypted remote backend with locking and appropriate access controls. Do not reuse the same local state while switching account or region variables. Backend provisioning is outside this lab.

## Review and deploy

In each isolated stack checkout, copy `terraform.tfvars.example` to `terraform.tfvars` and replace all fictional values.

Use an existing AWS profile through the SDK credential chain:

```powershell
$env:AWS_PROFILE = "approved-management-profile"
terraform -chdir=infra/organization plan -out=reviewed.tfplan
# Review the plan and account before applying.
terraform -chdir=infra/organization apply reviewed.tfplan
terraform -chdir=infra/organization output -json policy_documents
```

Keep `enforce_guardrails = false` during bootstrap. The organization root must retain the required allow policy for a deny-list strategy. The Terraform checks verify all features, the expected management account and enabled SCP policy type.

Switch to the approved LogArchive profile in its own checkout/state:

```powershell
$env:AWS_PROFILE = "approved-logarchive-profile"
terraform -chdir=infra/log-archive plan -out=reviewed.tfplan
terraform -chdir=infra/log-archive apply reviewed.tfplan
terraform -chdir=infra/log-archive output
```

Take the real bucket name and KMS key ARN from the outputs. The source-account list must contain every account whose baseline will deliver records to this archive. The archive must be in the baseline's region.

For each member account, use its isolated baseline state and approved profile:

```powershell
$env:AWS_PROFILE = "approved-sandbox-bootstrap-profile"
terraform -chdir=infra/account-baseline plan -out=reviewed.tfplan
terraform -chdir=infra/account-baseline apply reviewed.tfplan
```

Keep `primary_region = true` in exactly one region per account. That deployment creates the global GovernanceAdministrator role and multi-region trail. Secondary regions use `false`, a regional archive and their own state.

The baseline role receives AWS-managed AdministratorAccess and trusts only the specified Security operator role. It is intentionally privileged for controlled lab administration. Review its use and session policy before production adoption.

## Verify enablement and delivery

Export the baseline's service inventory as UTF-8, then run the read-only verifier:

```powershell
New-Item -ItemType Directory -Force reports | Out-Null
$InventoryJson = terraform -chdir=infra/account-baseline output -json service_inventory
if ($LASTEXITCODE -ne 0) { throw "Terraform output failed." }
[IO.File]::WriteAllText((Join-Path $PWD "reports/baseline-inventory.json"), ($InventoryJson -join "`n"))
.\.venv\Scripts\python.exe -m governance_lab verify-live `
  --profile approved-sandbox-reader `
  --input reports/baseline-inventory.json `
  --output reports/live-verification
```

The verifier uses only STS identity, CloudTrail status, GuardDuty detector, Security Hub hub/standards and Config status/rule read APIs. Its profile needs those reads. It checks account identity before service calls, reports denied reads as partial and does not generate samples or remediate resources.

It does not prove end-to-end log delivery or that a service will detect an actual attack. Confirm fresh account-prefix objects in S3, readable encrypted logs, CloudTrail digest validation, Config delivery status and actual evaluation results separately. A secondary-region inventory has no local trail; the verifier marks that check unverified and returns partial until primary-region evidence is reviewed separately.

## Attach policies

1. Verify bootstrap, role assumption, service configuration and fresh log delivery.
2. Move only the approved sandbox account into the lab Workloads OU through the authorised Organizations administration process. Terraform does not move accounts.
3. Review a new organization plan with `enforce_guardrails = true`.
4. Apply that reviewed plan using the management profile.
5. Execute the controlled acceptance cases in RESPONSE.md. Validate actual AccessDenied events and allowed operations with the intended member identities.
6. Expand to additional approved accounts only after reviewing the results.

The work models multi-account governance; it does not enable organization-wide GuardDuty/Security Hub delegated administration, auto-enrollment or finding aggregation.

## Cleanup and retention

1. Preserve required evidence and record the state/account/region mapping.
2. Remove the lab SCP attachments through the management stack before planned security-service teardown. Otherwise guardrails may correctly deny Terraform deletes.
3. Destroy member baselines through authorised change roles. Confirm that removing detection and logging is acceptable.
4. Move accounts out of the lab OUs before deleting empty OUs and the lab policies.
5. Retain the log archive according to the approved schedule. The bucket and key have `prevent_destroy`; the bucket also has `force_destroy = false`. An intentional archive retirement requires explicit review of lifecycle settings, Terraform protection and all object versions.
6. Schedule key deletion only after retained logs no longer need decryption. Removing an alias does not retire encrypted data safely.

Never use a broad recursive bucket deletion as an automatic cleanup shortcut. The default 90-day lifecycle is a lab choice; obtain a real retention decision before collecting organizational audit data.
