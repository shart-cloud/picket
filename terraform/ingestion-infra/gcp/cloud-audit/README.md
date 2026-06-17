# GCP Cloud Audit Ingestion

Terraform module that creates a project-level Cloud Logging sink for Cloud Audit logs, routes matching entries through Pub/Sub to a Cloud Function, and forwards raw log entries to `picket-ingest` using an API key scoped to `source=gcp_cloud_audit`.

```hcl
module "picket_gcp_cloud_audit" {
  source = "./terraform/ingestion-infra/gcp/cloud-audit"

  project_id   = "my-security-project"
  ingest_url   = "https://ingest.example.com"
  ingest_token = var.picket_gcp_cloud_audit_ingest_token
}
```

By default the sink forwards Admin Activity and System Event logs. Set `include_data_access_logs = true` only after sizing expected volume.
