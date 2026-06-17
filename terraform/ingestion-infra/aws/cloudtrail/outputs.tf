output "lambda_function_arn" {
  description = "ARN of the CloudTrail forwarder Lambda."
  value       = aws_lambda_function.forwarder.arn
}

output "lambda_function_name" {
  description = "Name of the CloudTrail forwarder Lambda."
  value       = aws_lambda_function.forwarder.function_name
}

output "lambda_role_arn" {
  description = "IAM role ARN assumed by the forwarder Lambda."
  value       = aws_iam_role.forwarder.arn
}

output "queue_arn" {
  description = "ARN of the SQS queue receiving S3 CloudTrail notifications."
  value       = aws_sqs_queue.cloudtrail.arn
}

output "queue_url" {
  description = "URL of the SQS queue receiving S3 CloudTrail notifications."
  value       = aws_sqs_queue.cloudtrail.url
}

output "ingest_token_secret_arn" {
  description = "Secrets Manager ARN storing the Picket ingest API key."
  value       = aws_secretsmanager_secret.ingest_token.arn
}
