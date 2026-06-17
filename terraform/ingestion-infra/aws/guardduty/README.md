# AWS GuardDuty Ingestion

Terraform module that forwards GuardDuty findings from EventBridge to `picket-ingest` using an API key scoped to `source=aws_guardduty`.

```hcl
module "picket_guardduty" {
  source = "./terraform/ingestion-infra/aws/guardduty"

  ingest_url   = "https://ingest.example.com"
  ingest_token = var.picket_aws_guardduty_ingest_token
}
```

Set `create_detector = true` only when this module should enable GuardDuty in the target region. Leave it false when GuardDuty is already managed elsewhere.
