output "event_hub_namespace" {
  description = "Event Hub namespace receiving AKS diagnostic logs."
  value       = azurerm_eventhub_namespace.this.name
}

output "event_hub_name" {
  description = "Event Hub name."
  value       = azurerm_eventhub.audit.name
}

output "diagnostic_setting_id" {
  description = "Diagnostic Setting ID on the AKS cluster."
  value       = azurerm_monitor_diagnostic_setting.audit.id
}

output "function_app_name" {
  description = "Name of the forwarder Function App."
  value       = azurerm_linux_function_app.forwarder.name
}

output "function_app_principal_id" {
  description = "System-assigned managed identity principal of the Function App."
  value       = azurerm_linux_function_app.forwarder.identity[0].principal_id
}

output "enabled_log_categories" {
  description = "Effective list of AKS diagnostic categories shipped to the Event Hub."
  value       = local.enabled_categories
}

output "key_vault_id" {
  description = "Key Vault holding the ingestion bearer token (created by this module or BYO)."
  value       = local.key_vault_id
}

output "ingest_token_secret_id" {
  description = "Versionless Key Vault secret ID for the ingestion bearer token."
  value       = azurerm_key_vault_secret.ingest_token.versionless_id
}
