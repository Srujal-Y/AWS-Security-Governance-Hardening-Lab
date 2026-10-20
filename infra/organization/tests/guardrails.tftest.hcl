mock_provider "aws" {
  mock_data "aws_organizations_organization" {
    defaults = {
      feature_set       = "ALL"
      master_account_id = "111111111111"
      roots             = [{ id = "r-lab1", arn = "arn:aws:organizations::111111111111:root/o-fictional/r-lab1", name = "Root", policy_types = [{ type = "SERVICE_CONTROL_POLICY", status = "ENABLED" }] }]
    }
  }
}

variables {
  management_account_id   = "111111111111"
  administrator_role_arns = ["arn:aws:iam::444444444444:role/GovernanceAdministrator"]
}

run "review_before_enforcement" {
  command = plan
  assert {
    condition     = length(aws_organizations_organizational_unit.lab) == 3 && length(aws_organizations_policy.guardrail) == 2
    error_message = "Model three organizational units and two SCPs."
  }
  assert {
    condition     = length(aws_organizations_policy_attachment.workloads) == 0
    error_message = "Guardrails must remain unattached until enforcement is explicitly selected."
  }
  assert {
    condition     = contains(jsondecode(output.policy_documents["region-restriction"]).Statement[0].NotAction, "iam:*")
    error_message = "IAM global endpoint access needs a documented region exception."
  }
  assert {
    condition     = alltrue([for policy in values(output.policy_documents) : length(policy) <= 5120])
    error_message = "SCPs must fit the service size limit."
  }
}

run "attach_only_to_workloads" {
  command = plan
  variables {
    enforce_guardrails = true
  }
  assert {
    condition     = length(aws_organizations_policy_attachment.workloads) == 2
    error_message = "Enforcement must attach both lab policies."
  }
  assert {
    condition     = jsondecode(output.policy_documents["permissions-guardrails"]).Statement[1].Resource == ["arn:aws:iam::444444444444:role/GovernanceAdministrator"]
    error_message = "Only exact governance role ARNs may be exceptions."
  }
}

run "reject_wildcard_exception" {
  command = plan
  variables {
    administrator_role_arns = ["arn:aws:iam::*:role/Admin"]
  }
  expect_failures = [var.administrator_role_arns]
}

run "reject_empty_regions" {
  command = plan
  variables {
    allowed_regions = []
  }
  expect_failures = [var.allowed_regions]
}
