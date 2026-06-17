# picket — AWS CloudTrail Forwarder

Add-on Terraform module that ships CloudTrail log files from an existing S3 bucket to the `picket-ingest` Worker. This MVP supports the existing-bucket path: CloudTrail already writes JSON files to S3, and this module adds S3 event notifications, SQS buffering, and a thin Lambda forwarder.

## What It Creates

- Secrets Manager secret holding the Picket ingest API key
- SQS queue receiving S3 object-created notifications for CloudTrail files
- Bucket notification configuration on the existing CloudTrail S3 bucket
- Node.js 20 (arm64) Lambda function that reads SQS messages, fetches CloudTrail JSON from S3, and POSTs raw CloudTrail records to `picket-ingest`
- IAM role and scoped inline policy for S3 object reads, SQS consume/delete, Secrets Manager read, and Lambda log writes
- CloudWatch Log Group for the Lambda's own logs with configurable retention

The Lambda does not normalize or enrich events. It forwards CloudTrail record objects or `{ Records: [...] }` payloads to `picket-ingest`, where `normalizeCloudTrail` runs.

## Example Usage

```hcl
module "picket_cloudtrail_forwarder" {
  source = "github.com/picket-siem/picket//terraform/ingestion-infra/aws/cloudtrail"

  cloudtrail_bucket_name = "my-org-cloudtrail-logs"
  ingest_url             = "https://ingest.picket.example"
  ingest_token           = var.picket_cloudtrail_ingest_token

  cloudtrail_object_key_prefixes = ["AWSLogs/123456789012/CloudTrail/us-east-1/"]

  tags = {
    environment = "prod"
  }
}
```

## Control Tower Centralized Logging

AWS Control Tower commonly stores organization CloudTrail logs in a centralized bucket with this layout:

```text
o-<org-id>/AWSLogs/o-<org-id>/<account-id>/CloudTrail/<region>/<yyyy>/<mm>/<dd>/<file>.json.gz
```

For that layout, scope S3 notifications to the organization prefix, not just `AWSLogs/`:

```hcl
variable "picket_cloudtrail_ingest_token" {
  type      = string
  sensitive = true
}

module "picket_cloudtrail_forwarder" {
  source = "github.com/picket-siem/picket//terraform/ingestion-infra/aws/cloudtrail"

  name_prefix            = "picket-cloudtrail"
  cloudtrail_bucket_name = "aws-controltower-logs-473867148610-us-east-1"
  ingest_url             = "https://ingest.shart.cloud"
  ingest_token           = var.picket_cloudtrail_ingest_token

  cloudtrail_object_key_prefixes = ["o-<org-id>/AWSLogs/o-<org-id>/"]
}
```

Set the token outside Terraform files, for example with `TF_VAR_picket_cloudtrail_ingest_token` in your shell or CI secret store.

If `ingest_url` already ends with `/events`, the Lambda uses it as-is. Otherwise it appends `/events`.

Use `cloudtrail_object_key_prefixes = []` to receive every object-created event in the bucket. The default suffix filter is `.json.gz`, which matches standard CloudTrail delivery. Set `cloudtrail_object_key_suffix = null` to omit the suffix filter.

## Required AWS Permissions

The Terraform identity applying this module needs permissions to create and manage:

- IAM role and inline policy for the Lambda forwarder
- Lambda function and event source mapping
- SQS queue and queue policy
- Secrets Manager secret and secret version
- CloudWatch Log Group
- S3 bucket notifications on `cloudtrail_bucket_name`

The runtime Lambda role created by the module is limited to:

- `s3:GetObject` on objects in the CloudTrail bucket
- `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:ChangeMessageVisibility`, and `sqs:GetQueueAttributes` on the module queue
- `secretsmanager:GetSecretValue` on the module token secret
- `logs:CreateLogStream` and `logs:PutLogEvents` on the Lambda log group

## Picket API Key

Mint an API key scoped to CloudTrail ingestion from Picket admin/CLI, with source metadata set to `aws_cloudtrail`. Store it in Terraform as a sensitive variable and pass it as `ingest_token`.

Example variable declaration:

```hcl
variable "picket_cloudtrail_ingest_token" {
  type      = string
  sensitive = true
}
```

Do not hardcode the token in Terraform files. This module writes the value to AWS Secrets Manager and the Lambda reads it at runtime.

## Verification

After applying the module outside this workflow, generate or wait for a CloudTrail event that writes a new object under the configured prefix. Then verify from Picket:

```sh
picket status
picket query --preset iam-changes
```

Default AWS CloudTrail alert rules should evaluate inside `picket-detection` after ingest. To test a high-signal path, perform a small IAM change in a non-production account, wait for CloudTrail delivery, and confirm the query/alert output includes the event.

## Assumptions and Notes

- This module does not create CloudTrail or the S3 bucket. CloudTrail must already deliver logs to `cloudtrail_bucket_name`.
- Terraform's `aws_s3_bucket_notification` resource manages the bucket notification configuration. If the bucket already has notifications, consolidate them in Terraform before applying this module to avoid overwriting unmanaged notification rules.
- CloudTrail usually writes gzip-compressed `.json.gz` files. The Lambda detects gzip by suffix or magic bytes.
- The AWS SDK v3 is provided by the Node.js 20 Lambda runtime, so the forwarder is archived without a dependency bundle.
- OCSF normalization remains in `picket-ingest`; the AWS Lambda only forwards raw CloudTrail JSON.
