variable "management_account_id" {
  type        = string
  description = "Existing organization management account; the provider refuses other accounts."
  validation {
    condition     = can(regex("^[0-9]{12}$", var.management_account_id))
    error_message = "Use a 12-digit management account ID."
  }
}

variable "home_region" {
  type    = string
  default = "eu-west-1"
}

variable "allowed_regions" {
  type    = set(string)
  default = ["eu-west-1", "eu-central-1"]
  validation {
    condition     = length(var.allowed_regions) > 0 && alltrue([for r in var.allowed_regions : can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", r))])
    error_message = "Supply at least one explicit AWS region."
  }
}

variable "administrator_role_arns" {
  type        = set(string)
  description = "Exact existing governance administrator role ARNs. No wildcard bypasses."
  validation {
    condition     = length(var.administrator_role_arns) > 0 && alltrue([for arn in var.administrator_role_arns : can(regex("^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+$", arn))])
    error_message = "Supply exact commercial-partition IAM role ARNs with no wildcards."
  }
}

variable "enforce_guardrails" {
  type        = bool
  default     = false
  description = "Attach reviewed SCPs to the lab Workloads OU after baseline and administrator bootstrap."
}

variable "name_prefix" {
  type    = string
  default = "govlab"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,15}$", var.name_prefix))
    error_message = "Use 3-16 lowercase letters, digits or hyphens, starting with a letter."
  }
}
