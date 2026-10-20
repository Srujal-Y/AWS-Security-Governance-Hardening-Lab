# Security and data handling

The offline demo and Terraform mock tests do not contact AWS. The `verify-live` command makes read-only AWS API calls using the selected boto3 profile. No Python code changes AWS resources or generates findings in a live detector.

Terraform is the live write surface. Reviewed applies can create IAM roles, enable chargeable security services, change organization controls and establish storage/key policies. Providers restrict their expected account IDs, and SCP attachment is opt-in. Account and region checks are not a substitute for reviewing a plan and its state.

The GovernanceAdministrator role is an elevated exception identity. Its Security-account operator trust, authentication, access review and recovery process require independent administration. The lab does not configure an identity provider or enforce MFA in the Security account.

Live state and reports can contain sensitive account, policy and resource metadata. Use approved storage, encryption and access controls. `reports/`, Terraform state/plan/tfvars files and credentials are ignored by Git. Review staged files before publishing; an ignore rule is not data-loss prevention.

Reports use escaped HTML, no scripts or external assets, and a restrictive Content Security Policy. Files inherit the writer's filesystem environment; reports are not encrypted or signed by the application.

The central bucket's versioning, retention and Terraform deletion protections do not provide immutable WORM storage. Review retention and key availability before using real organizational logs.

For a defect report, provide a minimal fictional reproduction and version information. Do not publish AWS keys, real organization IDs, live state or unredacted findings in public issues.
