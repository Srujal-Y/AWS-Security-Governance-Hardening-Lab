data "aws_organizations_organization" "current" {}

resource "aws_organizations_organizational_unit" "lab" {
  for_each  = toset(["Security", "LogArchive", "Workloads"])
  name      = "${var.name_prefix}-${each.key}"
  parent_id = data.aws_organizations_organization.current.roots[0].id

  lifecycle {
    precondition {
      condition     = data.aws_organizations_organization.current.feature_set == "ALL"
      error_message = "The existing organization must have all features enabled."
    }
    precondition {
      condition     = data.aws_organizations_organization.current.master_account_id == var.management_account_id
      error_message = "This must be the intended management account."
    }
  }
}

locals {
  policy_inputs = {
    allowed_regions         = jsonencode(sort(tolist(var.allowed_regions)))
    administrator_role_arns = jsonencode(sort(tolist(var.administrator_role_arns)))
  }
  policies = {
    for name in ["region-restriction", "permissions-guardrails"] :
    name => jsonencode(jsondecode(templatefile("${path.module}/../../src/governance_lab/policies/${name}.json.tftpl", local.policy_inputs)))
  }
}

resource "aws_organizations_policy" "guardrail" {
  for_each    = local.policies
  name        = "${var.name_prefix}-${each.key}"
  description = "Lab deny guardrail; retain inherited FullAWSAccess and validate in a sandbox OU."
  type        = "SERVICE_CONTROL_POLICY"
  content     = each.value

  lifecycle {
    precondition {
      condition     = anytrue([for policy_type in data.aws_organizations_organization.current.roots[0].policy_types : policy_type.type == "SERVICE_CONTROL_POLICY" && policy_type.status == "ENABLED"])
      error_message = "Enable SCPs on the existing organization root before creating lab guardrails."
    }
    precondition {
      condition     = length(each.value) <= 5120
      error_message = "SCP content exceeds the 5120-character service limit."
    }
  }
}

resource "aws_organizations_policy_attachment" "workloads" {
  for_each  = var.enforce_guardrails ? local.policies : {}
  policy_id = aws_organizations_policy.guardrail[each.key].id
  target_id = aws_organizations_organizational_unit.lab["Workloads"].id
}

output "organizational_units" {
  value = { for name, ou in aws_organizations_organizational_unit.lab : name => ou.id }
}

output "policy_documents" {
  value       = local.policies
  description = "Rendered documents for review before setting enforce_guardrails=true."
}

output "enforcement_enabled" {
  value = var.enforce_guardrails
}
