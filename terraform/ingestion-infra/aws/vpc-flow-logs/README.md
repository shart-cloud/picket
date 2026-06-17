# AWS VPC Flow Logs Ingestion

Terraform module that enables VPC Flow Logs to an existing S3 bucket, wires S3 object-created notifications through SQS, and deploys a Lambda forwarder that posts raw Flow Log text to `picket-ingest` using an API key scoped to `source=aws_vpc_flow`.

```hcl
module "picket_vpc_flow_logs" {
  source = "./terraform/ingestion-infra/aws/vpc-flow-logs"

  vpc_id                = "vpc-0123456789abcdef0"
  flow_logs_bucket_name = "my-vpc-flow-logs"
  ingest_url            = "https://ingest.example.com"
  ingest_token          = var.picket_aws_vpc_flow_ingest_token
}
```

Set exactly one of `vpc_id`, `subnet_id`, or `network_interface_id`.

The module owns the bucket notification configuration for `flow_logs_bucket_name`. If other modules also manage notifications on the same bucket, consolidate them into one Terraform resource to avoid AWS notification overwrite behavior.
