variable "log_archive_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.log_archive_account_id))
    error_message = "Use the 12-digit central log archive account ID."
  }
}

variable "source_account_ids" {
  type        = set(string)
  description = "Existing accounts authorised to deliver their own CloudTrail and Config records."
  validation {
    condition     = length(var.source_account_ids) > 0 && length(var.source_account_ids) <= 10 && alltrue([for id in var.source_account_ids : can(regex("^[0-9]{12}$", id))])
    error_message = "Supply 1-10 explicit 12-digit account IDs for this lab."
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
    error_message = "Use a lowercase 3-16 character prefix."
  }
}

variable "retention_days" {
  type    = number
  default = 90
  validation {
    condition     = var.retention_days >= 30 && var.retention_days <= 3650 && floor(var.retention_days) == var.retention_days
    error_message = "Retention must be a whole number between 30 and 3650 days."
  }
}
