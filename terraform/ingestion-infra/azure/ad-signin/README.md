# Azure AD Sign-in Ingestion

Terraform module that exports Entra ID / Azure AD sign-in logs to Event Hub, deploys an Azure Function forwarder, and posts raw sign-in records to `picket-ingest` using an API key scoped to `source=azure_ad_signin`.

```hcl
module "picket_azure_ad_signin" {
  source = "./terraform/ingestion-infra/azure/ad-signin"

  resource_group_name = "picket-forwarders"
  location            = "eastus"
  ingest_url          = "https://ingest.example.com"
  ingest_token        = var.picket_azure_ad_signin_ingest_token
}
```

The module creates a tenant-level `azurerm_monitor_aad_diagnostic_setting` for these categories by default:

- `SignInLogs`
- `NonInteractiveUserSignInLogs`
- `ServicePrincipalSignInLogs`
- `ManagedIdentitySignInLogs`

Normalization remains inside `picket-ingest`; the Azure Function forwards raw records unchanged. Keep Azure Activity and Azure AD Sign-in keys separate because Picket routes normalization by API-key metadata.

The applying identity must be able to create Entra diagnostic settings and send them to Event Hub. In many tenants this requires elevated directory permissions in addition to Azure resource permissions.
