locals {
  lambda_function_name     = var.name_prefix
  ingest_token_secret_name = "${var.name_prefix}-ingest-token"
  guardduty_event_pattern = coalesce(var.event_pattern, jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  }))

  common_tags = merge(
    {
      "app.kubernetes.io/part-of"    = "picket"
      "app.kubernetes.io/component"  = "aws-guardduty-forwarder"
      "app.kubernetes.io/managed-by" = "terraform"
      "picket:source"                = "aws_guardduty"
    },
    var.tags,
  )
}

resource "aws_guardduty_detector" "this" {
  count  = var.create_detector ? 1 : 0
  enable = true
  tags   = local.common_tags
}

data "archive_file" "forwarder" {
  type        = "zip"
  source_file = "${path.module}/lambda/index.mjs"
  output_path = "${path.module}/.build/forwarder.zip"
}

resource "aws_secretsmanager_secret" "ingest_token" {
  name        = local.ingest_token_secret_name
  description = "picket ingestion API key for AWS GuardDuty"
  tags        = local.common_tags
}

resource "aws_secretsmanager_secret_version" "ingest_token" {
  secret_id     = aws_secretsmanager_secret.ingest_token.id
  secret_string = var.ingest_token
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.lambda_function_name}"
  retention_in_days = var.lambda_log_retention_days
  tags              = local.common_tags
}

resource "aws_lambda_function" "forwarder" {
  function_name = local.lambda_function_name
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
      INGEST_URL              = var.ingest_url
      INGEST_TOKEN_SECRET_ARN = aws_secretsmanager_secret.ingest_token.arn
    }
  }

  tags = local.common_tags

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_secretsmanager_secret_version.ingest_token,
    aws_iam_role_policy.forwarder,
  ]
}

resource "aws_cloudwatch_event_rule" "guardduty" {
  name          = var.name_prefix
  description   = "Forward GuardDuty findings to picket-ingest."
  event_pattern = local.guardduty_event_pattern
  tags          = local.common_tags
}

resource "aws_cloudwatch_event_target" "forwarder" {
  rule = aws_cloudwatch_event_rule.guardduty.name
  arn  = aws_lambda_function.forwarder.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.forwarder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty.arn
}
