variable "account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Use the explicit 12-digit member account ID."
  }
}

variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "name_prefix" {
  type    = string
  default = "govlab"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,15}$", var.name_prefix))
    error_message = "Use a lowercase 3-16 character prefix matching the archive stack."
  }
}

variable "audit_bucket_name" {
  type        = string
  description = "Regional central archive bucket from the log-archive stack."
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.audit_bucket_name))
    error_message = "Use a valid S3 bucket name."
  }
}

variable "audit_kms_key_arn" {
  type        = string
  description = "Customer-managed archive key ARN in this same region."
  validation {
    condition     = can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-f0-9-]+$", var.audit_kms_key_arn))
    error_message = "Use the archive KMS key ARN, not an alias."
  }
}

variable "primary_region" {
  type        = bool
  default     = true
  description = "One region per account creates the multi-region trail and records legacy global IAM resource types."
}

variable "security_operator_role_arn" {
  type        = string
  description = "Exact pre-existing operator role in the Security account allowed to assume the governance role."
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+$", var.security_operator_role_arn))
    error_message = "Supply one exact commercial-partition IAM role ARN without wildcards."
  }
}
