data "aws_caller_identity" "current" {}

locals {
  bucket_arn               = "arn:aws:s3:::${var.flow_logs_bucket_name}"
  lambda_function_name     = var.name_prefix
  ingest_token_secret_name = "${var.name_prefix}-ingest-token"
  resource_ids             = compact([var.vpc_id, var.subnet_id, var.network_interface_id])

  common_tags = merge(
    {
      "app.kubernetes.io/part-of"    = "picket"
      "app.kubernetes.io/component"  = "aws-vpc-flow-forwarder"
      "app.kubernetes.io/managed-by" = "terraform"
      "picket:source"                = "aws_vpc_flow"
    },
    var.tags,
  )
}

resource "aws_flow_log" "this" {
  count = length(local.resource_ids) == 1 ? 1 : 0

  log_destination      = "arn:aws:s3:::${var.flow_logs_bucket_name}/${var.flow_logs_object_key_prefix}"
  log_destination_type = "s3"
  traffic_type         = var.traffic_type
  vpc_id               = var.vpc_id
  subnet_id            = var.subnet_id
  eni_id               = var.network_interface_id

  tags = local.common_tags
}

data "archive_file" "forwarder" {
  type        = "zip"
  source_file = "${path.module}/lambda/index.mjs"
  output_path = "${path.module}/.build/forwarder.zip"
}

resource "aws_secretsmanager_secret" "ingest_token" {
  name        = local.ingest_token_secret_name
  description = "picket ingestion API key for AWS VPC Flow Logs"
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

resource "aws_sqs_queue" "vpc_flow" {
  name                       = "${var.name_prefix}-events"
  visibility_timeout_seconds = var.lambda_timeout_seconds * 6
  message_retention_seconds  = 345600
  tags                       = local.common_tags
}

data "aws_iam_policy_document" "allow_s3_to_sqs" {
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.vpc_flow.arn]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [local.bucket_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sqs_queue_policy" "allow_s3" {
  queue_url = aws_sqs_queue.vpc_flow.id
  policy    = data.aws_iam_policy_document.allow_s3_to_sqs.json
}

resource "aws_s3_bucket_notification" "vpc_flow" {
  bucket = var.flow_logs_bucket_name

  queue {
    queue_arn     = aws_sqs_queue.vpc_flow.arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = var.flow_logs_object_key_prefix
    filter_suffix = var.flow_logs_object_key_suffix
  }

  depends_on = [aws_sqs_queue_policy.allow_s3]
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

resource "aws_lambda_event_source_mapping" "vpc_flow" {
  event_source_arn        = aws_sqs_queue.vpc_flow.arn
  function_name           = aws_lambda_function.forwarder.arn
  batch_size              = var.lambda_batch_size
  function_response_types = ["ReportBatchItemFailures"]
}

check "exactly_one_flow_log_resource" {
  assert {
    condition     = length(local.resource_ids) == 1
    error_message = "Set exactly one of vpc_id, subnet_id, or network_interface_id."
  }
}
