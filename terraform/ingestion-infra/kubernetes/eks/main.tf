data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

data "aws_eks_cluster" "this" {
  name = var.cluster_name

  lifecycle {
    postcondition {
      condition     = contains(self.enabled_cluster_log_types, "audit")
      error_message = "EKS cluster '${var.cluster_name}' does not have 'audit' in enabled_cluster_log_types. Enable it on the cluster resource (e.g. terraform-aws-modules/eks: cluster_enabled_log_types = [\"audit\", ...]) and re-apply before installing this module."
    }
  }
}

locals {
  cluster_log_group_name = "/aws/eks/${var.cluster_name}/cluster"

  common_tags = merge(
    {
      "app.kubernetes.io/part-of"    = "picket"
      "app.kubernetes.io/component"  = "k8s-audit-forwarder"
      "app.kubernetes.io/managed-by" = "terraform"
      "picket:cluster"         = var.cluster_name
    },
    var.tags,
  )
}

data "archive_file" "forwarder" {
  type        = "zip"
  source_file = "${path.module}/lambda/index.mjs"
  output_path = "${path.module}/.build/forwarder.zip"
}

resource "aws_secretsmanager_secret" "ingest_token" {
  name        = "${var.name_prefix}-${var.cluster_name}-ingest-token"
  description = "picket ingestion bearer token for EKS cluster ${var.cluster_name}"
  tags        = local.common_tags
}

resource "aws_secretsmanager_secret_version" "ingest_token" {
  secret_id     = aws_secretsmanager_secret.ingest_token.id
  secret_string = var.ingest_token
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.name_prefix}-${var.cluster_name}"
  retention_in_days = var.lambda_log_retention_days
  tags              = local.common_tags
}

resource "aws_lambda_function" "forwarder" {
  function_name = "${var.name_prefix}-${var.cluster_name}"
  role          = aws_iam_role.forwarder.arn
  runtime       = "nodejs20.x"
  handler       = "index.handler"
  architectures = ["arm64"]

  filename         = data.archive_file.forwarder.output_path
  source_code_hash = data.archive_file.forwarder.output_base64sha256

  memory_size = var.lambda_memory_mb
  timeout     = var.lambda_timeout_seconds

  environment {
    variables = {
      INGEST_URL                = var.ingest_url
      INGEST_TOKEN_SECRET_ARN   = aws_secretsmanager_secret.ingest_token.arn
      CLUSTER_NAME              = var.cluster_name
      CLUSTER_REGION            = data.aws_region.current.name
      CLOUD_ACCOUNT             = data.aws_caller_identity.current.account_id
      FORWARDED_STREAM_PREFIXES = join(",", var.forwarded_log_stream_prefixes)
    }
  }

  tags = local.common_tags

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_secretsmanager_secret_version.ingest_token,
    aws_iam_role_policy.read_ingest_token,
  ]
}

resource "aws_lambda_permission" "allow_cloudwatch_logs" {
  statement_id  = "AllowExecutionFromCloudWatchLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.forwarder.function_name
  principal     = "logs.${data.aws_region.current.name}.amazonaws.com"
  source_arn    = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:${local.cluster_log_group_name}:*"
}

resource "aws_cloudwatch_log_subscription_filter" "audit" {
  name            = "${var.name_prefix}-${var.cluster_name}"
  log_group_name  = local.cluster_log_group_name
  filter_pattern  = var.subscription_filter_pattern
  destination_arn = aws_lambda_function.forwarder.arn

  depends_on = [aws_lambda_permission.allow_cloudwatch_logs]
}
