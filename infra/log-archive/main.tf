locals {
  bucket_name = "${var.name_prefix}-audit-${var.log_archive_account_id}-${var.region}"
  bucket_arn  = "arn:aws:s3:::${local.bucket_name}"
  trail_arns  = [for id in sort(tolist(var.source_account_ids)) : "arn:aws:cloudtrail:${var.region}:${id}:trail/${var.name_prefix}-trail"]
  config_arns = [for id in sort(tolist(var.source_account_ids)) : "arn:aws:iam::${id}:role/${var.name_prefix}-config-${var.region}"]
}

resource "aws_kms_key" "audit" {
  description             = "Central CloudTrail and Config delivery key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DelegateAdministrationToArchiveAccountIAM", Effect = "Allow",
        Principal = { AWS = "arn:aws:iam::${var.log_archive_account_id}:root" },
        Action    = "kms:*", Resource = "*"
      },
      {
        Sid       = "CloudTrailDataKeysForNamedTrails", Effect = "Allow",
        Principal = { Service = "cloudtrail.amazonaws.com" },
        Action    = "kms:GenerateDataKey*", Resource = "*",
        Condition = {
          StringEquals = { "aws:SourceArn" = local.trail_arns },
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = [for id in sort(tolist(var.source_account_ids)) : "arn:aws:cloudtrail:*:${id}:trail/${var.name_prefix}-trail"] }
        }
      },
      {
        Sid       = "CloudTrailKeyMetadata", Effect = "Allow",
        Principal = { Service = "cloudtrail.amazonaws.com" },
        Action    = "kms:DescribeKey", Resource = "*",
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arns } }
      },
      {
        Sid       = "ConfigRecorderRoleEncryption", Effect = "Allow",
        Principal = { AWS = [for id in sort(tolist(var.source_account_ids)) : "arn:aws:iam::${id}:root"] },
        Action    = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = "*",
        Condition = {
          ArnEquals    = { "aws:PrincipalArn" = local.config_arns },
          StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" }
        }
      },
      {
        Sid       = "ConfigServiceFallbackEncryption", Effect = "Allow",
        Principal = { Service = "config.amazonaws.com" },
        Action    = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = "*",
        Condition = {
          StringEquals = { "aws:SourceAccount" = sort(tolist(var.source_account_ids)) }
          ArnLike      = { "aws:SourceArn" = [for id in sort(tolist(var.source_account_ids)) : "arn:aws:config:${var.region}:${id}:*"] }
        }
      }
    ]
  })
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "audit" {
  name          = "alias/${var.name_prefix}-audit-${var.region}"
  target_key_id = aws_kms_key.audit.key_id
}

resource "aws_s3_bucket" "audit" {
  bucket        = local.bucket_name
  force_destroy = false
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
    }
    bucket_key_enabled = false
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    id     = "reviewed-audit-retention"
    status = "Enabled"
    filter {}
    expiration {
      days = var.retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = var.retention_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
  depends_on = [aws_s3_bucket_versioning.audit]
}

locals {
  delivery_statements = flatten([
    for id in sort(tolist(var.source_account_ids)) : [
      {
        Sid       = "TrailAcl${id}", Effect = "Allow",
        Principal = { Service = "cloudtrail.amazonaws.com" },
        Action    = "s3:GetBucketAcl", Resource = local.bucket_arn,
        Condition = { StringEquals = { "aws:SourceArn" = "arn:aws:cloudtrail:${var.region}:${id}:trail/${var.name_prefix}-trail" } }
      },
      {
        Sid       = "TrailWrite${id}", Effect = "Allow",
        Principal = { Service = "cloudtrail.amazonaws.com" },
        Action    = "s3:PutObject", Resource = "${local.bucket_arn}/cloudtrail/AWSLogs/${id}/*",
        Condition = { StringEquals = {
          "aws:SourceArn" = "arn:aws:cloudtrail:${var.region}:${id}:trail/${var.name_prefix}-trail",
          "s3:x-amz-acl"  = "bucket-owner-full-control"
        } }
      },
      {
        Sid       = "ConfigServiceCheck${id}", Effect = "Allow",
        Principal = { Service = "config.amazonaws.com" },
        Action    = ["s3:GetBucketAcl", "s3:ListBucket"], Resource = local.bucket_arn,
        Condition = { StringEquals = { "aws:SourceAccount" = id } }
      },
      {
        Sid       = "ConfigServiceWrite${id}", Effect = "Allow",
        Principal = { Service = "config.amazonaws.com" },
        Action    = "s3:PutObject", Resource = "${local.bucket_arn}/config/AWSLogs/${id}/Config/*",
        Condition = { StringEquals = { "aws:SourceAccount" = id, "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
      {
        Sid       = "ConfigRoleCheck${id}", Effect = "Allow",
        Principal = { AWS = "arn:aws:iam::${id}:root" },
        Action    = ["s3:GetBucketAcl", "s3:ListBucket", "s3:GetBucketLocation"], Resource = local.bucket_arn,
        Condition = { ArnEquals = { "aws:PrincipalArn" = "arn:aws:iam::${id}:role/${var.name_prefix}-config-${var.region}" } }
      },
      {
        Sid       = "ConfigRoleWrite${id}", Effect = "Allow",
        Principal = { AWS = "arn:aws:iam::${id}:root" },
        Action    = "s3:PutObject", Resource = "${local.bucket_arn}/config/AWSLogs/${id}/Config/*",
        Condition = {
          ArnEquals    = { "aws:PrincipalArn" = "arn:aws:iam::${id}:role/${var.name_prefix}-config-${var.region}" },
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  ])
}

resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "DenyInsecureTransport", Effect = "Deny", Principal = "*",
        Action    = "s3:*", Resource = [local.bucket_arn, "${local.bucket_arn}/*"],
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ], local.delivery_statements)
  })
  lifecycle {
    precondition {
      condition     = length(jsonencode(local.delivery_statements)) < 19500
      error_message = "Too many source statements for the S3 bucket-policy limit; split the lab archive."
    }
  }
  depends_on = [aws_s3_bucket_public_access_block.audit, aws_s3_bucket_ownership_controls.audit]
}

output "audit_bucket_name" {
  value = aws_s3_bucket.audit.id
}

output "audit_kms_key_arn" {
  value = aws_kms_key.audit.arn
}

output "source_account_ids" {
  value = var.source_account_ids
}
