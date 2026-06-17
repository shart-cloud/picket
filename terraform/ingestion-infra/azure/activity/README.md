# Azure Activity Log Ingestion

Terraform module that exports subscription Activity Logs to Event Hub, deploys an Azure Function forwarder, and posts raw Activity records to `picket-ingest` using an API key scoped to `source=azure_activity`.

```hcl
module "picket_azure_activity" {
  source = "./terraform/ingestion-infra/azure/activity"

  resource_group_name = "picket-forwarders"
  location            = "eastus"
  ingest_url          = "https://ingest.example.com"
  ingest_token        = var.picket_azure_activity_ingest_token
}
```

The module targets the active AzureRM provider subscription by default. Set `subscription_id` to forward a different subscription's Activity Log.

Azure AD / Entra ID sign-in logs are a separate Picket source (`source=azure_ad_signin`) and must use a separate API key. See `../ad-signin/README.md` for the shared Event Hub deployment pattern.
