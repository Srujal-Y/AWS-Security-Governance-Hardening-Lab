# This global role is created once per account, before Workloads OU enforcement.
resource "aws_iam_role" "governance" {
  count                = var.primary_region ? 1 : 0
  name                 = "GovernanceAdministrator"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow",
      Principal = { AWS = "arn:aws:iam::${split(":", var.security_operator_role_arn)[4]}:root" },
      Action    = "sts:AssumeRole",
      Condition = { ArnEquals = { "aws:PrincipalArn" = var.security_operator_role_arn } }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "governance" {
  count      = var.primary_region ? 1 : 0
  role       = aws_iam_role.governance[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_cloudtrail" "baseline" {
  count                         = var.primary_region ? 1 : 0
  name                          = "${var.name_prefix}-trail"
  s3_bucket_name                = var.audit_bucket_name
  s3_key_prefix                 = "cloudtrail"
  kms_key_id                    = var.audit_kms_key_arn
  enable_logging                = true
  enable_log_file_validation    = true
  is_multi_region_trail         = true
  include_global_service_events = true
  is_organization_trail         = false
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
  lifecycle {
    precondition {
      condition     = split(":", var.audit_kms_key_arn)[3] == var.region
      error_message = "Use the archive key for this region."
    }
  }
}

resource "aws_guardduty_detector" "baseline" {
  enable                       = true
  finding_publishing_frequency = "SIX_HOURS"
}

resource "aws_guardduty_detector_feature" "s3" {
  detector_id = aws_guardduty_detector.baseline.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

resource "aws_securityhub_account" "baseline" {
  enable_default_standards  = false
  control_finding_generator = "SECURITY_CONTROL"
  auto_enable_controls      = true
}

resource "aws_securityhub_standards_subscription" "foundational" {
  standards_arn = "arn:aws:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.baseline, aws_config_configuration_recorder_status.baseline]
}

resource "aws_iam_role" "config" {
  name = "${var.name_prefix}-config-${var.region}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Service = "config.amazonaws.com" }, Action = "sts:AssumeRole",
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id },
        ArnLike      = { "aws:SourceArn" = "arn:aws:config:${var.region}:${var.account_id}:*" }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_read" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_delivery" {
  name = "${var.name_prefix}-config-delivery"
  role = aws_iam_role.config.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow", Action = ["s3:GetBucketAcl", "s3:GetBucketLocation", "s3:ListBucket"],
        Resource = "arn:aws:s3:::${var.audit_bucket_name}"
      },
      {
        Effect    = "Allow", Action = "s3:PutObject",
        Resource  = "arn:aws:s3:::${var.audit_bucket_name}/config/AWSLogs/${var.account_id}/Config/*",
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
      {
        Effect   = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt"],
        Resource = var.audit_kms_key_arn
      }
    ]
  })
}

resource "aws_config_configuration_recorder" "baseline" {
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config.arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = var.primary_region
  }
  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
  depends_on = [aws_iam_role_policy_attachment.config_read, aws_iam_role_policy.config_delivery]
}

resource "aws_config_delivery_channel" "baseline" {
  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = var.audit_bucket_name
  s3_key_prefix  = "config"
  s3_kms_key_arn = var.audit_kms_key_arn
  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }
  lifecycle {
    precondition {
      condition     = split(":", var.audit_kms_key_arn)[3] == var.region
      error_message = "Use a Config delivery key in the recorder region."
    }
  }
  depends_on = [aws_config_configuration_recorder.baseline]
}

resource "aws_config_configuration_recorder_status" "baseline" {
  name       = aws_config_configuration_recorder.baseline.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.baseline]
}

locals {
  managed_rules = {
    s3-public-read-prohibited  = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    s3-public-write-prohibited = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
    encrypted-volumes          = "ENCRYPTED_VOLUMES"
    restricted-ssh             = "INCOMING_SSH_DISABLED"
    cloudtrail-enabled         = "CLOUD_TRAIL_ENABLED"
  }
}

resource "aws_config_config_rule" "baseline" {
  for_each = local.managed_rules
  name     = "${var.name_prefix}-${each.key}"
  source {
    owner             = "AWS"
    source_identifier = each.value
  }
  depends_on = [aws_config_configuration_recorder_status.baseline]
}

resource "aws_config_config_rule" "required_tags" {
  name             = "${var.name_prefix}-required-tags"
  input_parameters = jsonencode({ tag1Key = "Owner", tag2Key = "Environment" })
  scope {
    compliance_resource_types = ["AWS::EC2::Instance", "AWS::S3::Bucket"]
  }
  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }
  depends_on = [aws_config_configuration_recorder_status.baseline]
}

output "service_inventory" {
  value = {
    account_id        = var.account_id
    region            = var.region
    trail_name        = var.primary_region ? aws_cloudtrail.baseline[0].name : null
    guardduty_id      = aws_guardduty_detector.baseline.id
    securityhub_arn   = aws_securityhub_account.baseline.arn
    config_recorder   = aws_config_configuration_recorder.baseline.name
    config_delivery   = aws_config_delivery_channel.baseline.name
    config_rule_names = concat([for rule in aws_config_config_rule.baseline : rule.name], [aws_config_config_rule.required_tags.name])
    archive_bucket    = var.audit_bucket_name
    managed_rule_ids  = concat(sort(keys(local.managed_rules)), ["required-tags"])
  }
}
