output "flow_log_id" {
  description = "ID of the managed VPC Flow Log."
  value       = try(aws_flow_log.this[0].id, null)
}

output "lambda_function_arn" {
  description = "ARN of the VPC Flow Logs forwarder Lambda."
  value       = aws_lambda_function.forwarder.arn
}

output "lambda_function_name" {
  description = "Name of the VPC Flow Logs forwarder Lambda."
  value       = aws_lambda_function.forwarder.function_name
}

output "lambda_role_arn" {
  description = "IAM role ARN assumed by the forwarder Lambda."
  value       = aws_iam_role.forwarder.arn
}

output "queue_arn" {
  description = "ARN of the SQS queue receiving S3 VPC Flow Logs notifications."
  value       = aws_sqs_queue.vpc_flow.arn
}

output "queue_url" {
  description = "URL of the SQS queue receiving S3 VPC Flow Logs notifications."
  value       = aws_sqs_queue.vpc_flow.url
}

output "ingest_token_secret_arn" {
  description = "Secrets Manager ARN storing the Picket ingest API key."
  value       = aws_secretsmanager_secret.ingest_token.arn
}
