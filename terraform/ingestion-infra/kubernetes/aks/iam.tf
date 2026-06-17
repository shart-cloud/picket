data "azurerm_client_config" "current" {}

locals {
  create_key_vault = var.key_vault_id == ""
  key_vault_id     = local.create_key_vault ? azurerm_key_vault.this[0].id : var.key_vault_id
  key_vault_name   = local.create_key_vault ? azurerm_key_vault.this[0].name : reverse(split("/", var.key_vault_id))[0]
  key_vault_uri    = local.create_key_vault ? azurerm_key_vault.this[0].vault_uri : "https://${local.key_vault_name}.vault.azure.net/"
}

resource "azurerm_key_vault" "this" {
  count = local.create_key_vault ? 1 : 0

  name                       = substr("${local.short_name}kv", 0, 24)
  resource_group_name        = local.forwarder_rg
  location                   = local.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  enable_rbac_authorization  = true
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
  tags                       = local.common_tags
}

resource "azurerm_role_assignment" "deployer_secrets_officer" {
  count = local.create_key_vault ? 1 : 0

  scope                = local.key_vault_id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_key_vault_secret" "ingest_token" {
  name         = "${local.short_name}-ingest-token"
  value        = var.ingest_token
  key_vault_id = local.key_vault_id

  depends_on = [azurerm_role_assignment.deployer_secrets_officer]
}

resource "azurerm_role_assignment" "forwarder_secrets_user" {
  scope                = azurerm_key_vault_secret.ingest_token.resource_versionless_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_function_app.forwarder.identity[0].principal_id
}

resource "azurerm_role_assignment" "forwarder_eventhub_receiver" {
  scope                = azurerm_eventhub.audit.id
  role_definition_name = "Azure Event Hubs Data Receiver"
  principal_id         = azurerm_linux_function_app.forwarder.identity[0].principal_id
}
