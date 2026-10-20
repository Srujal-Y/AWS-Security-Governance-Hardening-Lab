mock_provider "aws" {}

variables {
  account_id                 = "444444444444"
  audit_bucket_name          = "govlab-audit-333333333333-eu-west-1"
  audit_kms_key_arn          = "arn:aws:kms:eu-west-1:333333333333:key/00000000-0000-0000-0000-000000000000"
  security_operator_role_arn = "arn:aws:iam::222222222222:role/GovernanceOperator"
}

run "all_four_services_enabled" {
  command = plan
  assert {
    condition     = aws_cloudtrail.baseline[0].enable_logging && aws_cloudtrail.baseline[0].is_multi_region_trail && aws_cloudtrail.baseline[0].enable_log_file_validation
    error_message = "CloudTrail must log all-region management events with digest validation."
  }
  assert {
    condition     = aws_guardduty_detector.baseline.enable && aws_guardduty_detector_feature.s3.status == "ENABLED"
    error_message = "GuardDuty and S3 protection must be enabled."
  }
  assert {
    condition     = !aws_securityhub_account.baseline.enable_default_standards && endswith(aws_securityhub_standards_subscription.foundational.standards_arn, "aws-foundational-security-best-practices/v/1.0.0")
    error_message = "Subscribe explicitly to Foundational Security Best Practices."
  }
  assert {
    condition     = aws_config_configuration_recorder_status.baseline.is_enabled && one(aws_config_configuration_recorder.baseline.recording_group).all_supported
    error_message = "Config recording must be enabled for supported resource types."
  }
  assert {
    condition     = length(aws_config_config_rule.baseline) == 5 && aws_config_config_rule.required_tags.name == "govlab-required-tags"
    error_message = "All six managed Config rules must be present."
  }
  assert {
    condition     = jsondecode(aws_iam_role.governance[0].assume_role_policy).Statement[0].Condition.ArnEquals["aws:PrincipalArn"] == var.security_operator_role_arn
    error_message = "The governance role must trust exactly the approved operator role."
  }
}

run "secondary_region_avoids_duplicate_global_resources" {
  command = plan
  variables {
    primary_region = false
  }
  assert {
    condition     = length(aws_cloudtrail.baseline) == 0 && length(aws_iam_role.governance) == 0 && !one(aws_config_configuration_recorder.baseline.recording_group).include_global_resource_types
    error_message = "Create the multi-region trail and global role only in the primary region."
  }
}

run "reject_wrong_region_key" {
  command = plan
  variables {
    audit_kms_key_arn = "arn:aws:kms:us-east-1:333333333333:key/00000000-0000-0000-0000-000000000000"
  }
  expect_failures = [aws_cloudtrail.baseline[0], aws_config_delivery_channel.baseline]
}
