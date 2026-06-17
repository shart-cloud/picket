output "lambda_function_arn" {
  description = "ARN of the audit log forwarder Lambda."
  value       = aws_lambda_function.forwarder.arn
}

output "lambda_function_name" {
  description = "Name of the audit log forwarder Lambda."
  value       = aws_lambda_function.forwarder.function_name
}

output "lambda_role_arn" {
  description = "IAM role ARN assumed by the forwarder Lambda."
  value       = aws_iam_role.forwarder.arn
}

output "subscription_filter_name" {
  description = "Name of the CloudWatch Logs subscription filter installed on the EKS cluster log group."
  value       = aws_cloudwatch_log_subscription_filter.audit.name
}

output "cluster_log_group_name" {
  description = "Log group this module subscribes to."
  value       = local.cluster_log_group_name
}

output "ingest_token_secret_arn" {
  description = "Secrets Manager ARN storing the ingestion bearer token."
  value       = aws_secretsmanager_secret.ingest_token.arn
}
