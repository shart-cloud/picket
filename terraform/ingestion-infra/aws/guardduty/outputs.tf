output "lambda_function_arn" {
  description = "ARN of the GuardDuty forwarder Lambda."
  value       = aws_lambda_function.forwarder.arn
}

output "lambda_function_name" {
  description = "Name of the GuardDuty forwarder Lambda."
  value       = aws_lambda_function.forwarder.function_name
}

output "lambda_role_arn" {
  description = "IAM role ARN assumed by the forwarder Lambda."
  value       = aws_iam_role.forwarder.arn
}

output "event_rule_arn" {
  description = "EventBridge rule ARN forwarding GuardDuty findings."
  value       = aws_cloudwatch_event_rule.guardduty.arn
}

output "ingest_token_secret_arn" {
  description = "Secrets Manager ARN storing the Picket ingest API key."
  value       = aws_secretsmanager_secret.ingest_token.arn
}

output "guardduty_detector_id" {
  description = "Managed GuardDuty detector ID, when create_detector is true."
  value       = try(aws_guardduty_detector.this[0].id, null)
}
