# SCP guardrails

## Policy catalogue

| Policy / statement | Intent | Exception |
| --- | --- | --- |
| Region / DenyRequestsOutsideApprovedRegions | Restrict regional requests to the approved region set | Listed global service action namespaces |
| Permissions / DenySecurityControlTampering | Prevent selected CloudTrail, Config, GuardDuty and Security Hub disable/update operations | Exact GovernanceAdministrator role ARNs |
| Permissions / ProtectGovernanceAdministratorRoles | Protect the exception roles' creation, trust, permissions, boundaries, tags and passing | Exact GovernanceAdministrator role ARNs |
| Permissions / DenyKeyDestructionWithoutGovernanceRole | Restrict KMS disabling, scheduled deletion and key-policy updates | Exact GovernanceAdministrator role ARNs |
| Permissions / DenyMemberDeparture | Prevent affected members from leaving the organization | None |
| Permissions / DenyRootAccessKeyCreation | Prevent root access-key creation | None |

Review the complete action lists in `src/governance_lab/policies/`. These are selected guardrails, not an exhaustive catalogue of every bypass or future AWS API.

## Deployment and exceptions

The organization must already have all features and SCPs enabled. Retain the default FullAWSAccess SCP at the necessary hierarchy levels for this deny-list strategy. A deny SCP adds restrictions; it does not grant IAM permissions.

Policies are created unattached by default. Bootstrap the Security operator identity and account baselines first. Record the exact governance role ARNs in the organization stack, verify role assumption, and review the rendered JSON before attaching the policies to the Workloads OU.

Normal operators cannot modify the named governance roles under these guardrails. The trusted role can administer protected services within the permitted regions. It has no exception to the region policy or member-departure denial. A role in another account with the same name is not automatically trusted by the SCP exception list.

The management account is outside SCP scope, as are service-linked roles. Securing those identities requires other controls. Do not test region-deny enforcement using the management account and interpret success as a guardrail failure.

## Region restrictions are not data residency controls

The lab exempts IAM, Organizations, account management, billing namespaces, Route 53, CloudFront, support, health and pricing APIs from the endpoint region restriction. This is a reviewed starting list, not a universal list for every workload. Regional dependencies of global products can require additional design, such as certificates used by CloudFront.

`aws:RequestedRegion` constrains the API endpoint; some operations can affect resources elsewhere. Replication, global services and cross-region effects require separate review. An approved-region SCP does not prove that all data remains in that region.

## Recovery

1. Keep the management-account recovery path available under the organisation's normal identity controls.
2. If sandbox enforcement blocks a required action, capture the principal, API, resource, endpoint region and CloudTrail event.
3. Inspect all applicable SCP levels and IAM policies. An AccessDenied message alone is not proof that this lab's SCP caused the denial.
4. In the management account, plan `enforce_guardrails = false` for the lab stack to remove these two attachments, or use the authorised Organizations recovery process.
5. Correct and retest in a sandbox before reattaching. Do not expand role exceptions to wildcard account or role patterns.

The stack manages only its own policies and attachments. It does not detach unrelated organization policies or replace an existing landing zone.

## Offline evaluator limits

Supported syntax: named Deny statements, Action or NotAction, Resource, StringNotEquals, ArnNotEquals and ArnLike with the explicit context keys used by the lab.

Unknown syntax and missing request context are rejected. Evaluation does not include policy inheritance, allow lists, IAM identity/resource policies, boundaries or session policies. `not_denied_by_lab_scps` is deliberately distinct from an allow decision.

The model also trusts the scenario's account-type and service-linked-role flags. Use real AWS evidence to validate those attributes in a deployed organization.

References: [AWS SCP examples and deny-list prerequisite](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html), [SCP syntax and region conditions](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html), [SCP evaluation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html).
