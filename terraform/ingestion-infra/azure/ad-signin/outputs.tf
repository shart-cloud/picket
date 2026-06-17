output "eventhub_namespace_id" {
  description = "Event Hub namespace receiving Azure AD sign-in logs."
  value       = azurerm_eventhub_namespace.this.id
}

output "eventhub_name" {
  description = "Event Hub name receiving Azure AD sign-in logs."
  value       = azurerm_eventhub.signin.name
}

output "function_app_name" {
  description = "Azure Function App name for the forwarder."
  value       = azurerm_linux_function_app.forwarder.name
}

output "function_principal_id" {
  description = "System-assigned managed identity principal ID for the forwarder."
  value       = azurerm_linux_function_app.forwarder.identity[0].principal_id
}

output "diagnostic_setting_id" {
  description = "Entra ID sign-in diagnostic setting ID."
  value       = azurerm_monitor_aad_diagnostic_setting.signin.id
}
