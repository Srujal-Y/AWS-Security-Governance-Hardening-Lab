mock_provider "aws" {}

variables {
  log_archive_account_id = "333333333333"
  source_account_ids     = ["444444444444", "555555555555"]
}

run "encrypted_private_archive" {
  command = plan
  assert {
    condition     = aws_kms_key.audit.enable_key_rotation && aws_kms_key.audit.deletion_window_in_days == 30
    error_message = "Rotate keys and retain a 30-day deletion window."
  }
  assert {
    condition     = !aws_s3_bucket.audit.force_destroy && aws_s3_bucket_public_access_block.audit.block_public_acls && aws_s3_bucket_public_access_block.audit.block_public_policy && aws_s3_bucket_public_access_block.audit.ignore_public_acls && aws_s3_bucket_public_access_block.audit.restrict_public_buckets
    error_message = "The archive must block every public-access mechanism and retain objects on destroy."
  }
  assert {
    condition     = one(aws_s3_bucket_versioning.audit.versioning_configuration).status == "Enabled"
    error_message = "Audit objects must be versioned."
  }
  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.audit.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"
    error_message = "Audit objects must use customer-managed KMS encryption."
  }
  assert {
    condition     = one(aws_s3_bucket_ownership_controls.audit.rule).object_ownership == "BucketOwnerEnforced"
    error_message = "The archive account must own delivered objects."
  }
}

run "account_bound_delivery" {
  command = plan
  assert {
    condition = alltrue([
      for s in jsondecode(aws_s3_bucket_policy.audit.policy).Statement :
      endswith(s.Resource, "/AWSLogs/${substr(s.Sid, 10, 12)}/*") && s.Condition.StringEquals["aws:SourceArn"] == "arn:aws:cloudtrail:eu-west-1:${substr(s.Sid, 10, 12)}:trail/govlab-trail"
      if startswith(s.Sid, "TrailWrite")
    ])
    error_message = "Each trail may deliver only to its own account prefix."
  }
  assert {
    condition     = jsondecode(aws_s3_bucket_policy.audit.policy).Statement[0].Condition.Bool["aws:SecureTransport"] == "false"
    error_message = "Reject non-TLS S3 requests."
  }
  assert {
    condition     = length([for s in jsondecode(aws_kms_key.audit.policy).Statement : s if s.Sid == "ConfigRecorderRoleEncryption" && length(s.Condition.ArnEquals["aws:PrincipalArn"]) == 2]) == 1
    error_message = "Cross-account Config key use must be bound to named recorder roles."
  }
}

run "reject_short_retention" {
  command = plan
  variables {
    retention_days = 1
  }
  expect_failures = [var.retention_days]
}
