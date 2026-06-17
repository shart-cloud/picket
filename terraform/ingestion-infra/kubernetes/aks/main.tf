data "azurerm_kubernetes_cluster" "this" {
  name                = var.cluster_name
  resource_group_name = var.resource_group_name
}

locals {
  forwarder_rg = var.forwarder_resource_group_name != "" ? var.forwarder_resource_group_name : var.resource_group_name
  location     = var.location != "" ? var.location : data.azurerm_kubernetes_cluster.this.location

  instance_suffix = substr(sha1("${var.resource_group_name}-${var.cluster_name}"), 0, 6)
  short_name      = "${var.name_prefix}${local.instance_suffix}"

  audit_categories = compact([
    var.include_kube_audit_admin ? "kube-audit-admin" : "",
    var.include_kube_audit ? "kube-audit" : "",
  ])
  enabled_categories = concat(local.audit_categories, var.additional_log_categories)

  common_tags = merge(
    {
      "app.kubernetes.io/part-of"    = "picket"
      "app.kubernetes.io/component"  = "k8s-audit-forwarder"
      "app.kubernetes.io/managed-by" = "terraform"
      "picket:cluster"         = var.cluster_name
    },
    var.tags,
  )
}

resource "azurerm_eventhub_namespace" "this" {
  name                = "${local.short_name}-ns"
  resource_group_name = local.forwarder_rg
  location            = local.location
  sku                 = var.event_hub_sku
  capacity            = 1
  tags                = local.common_tags
}

resource "azurerm_eventhub" "audit" {
  name              = "audit"
  namespace_id      = azurerm_eventhub_namespace.this.id
  partition_count   = var.event_hub_partition_count
  message_retention = var.event_hub_retention_days
}

resource "azurerm_eventhub_consumer_group" "forwarder" {
  name                = "forwarder"
  namespace_name      = azurerm_eventhub_namespace.this.name
  eventhub_name       = azurerm_eventhub.audit.name
  resource_group_name = local.forwarder_rg
}

resource "azurerm_monitor_diagnostic_setting" "audit" {
  name                           = "${local.short_name}-audit"
  target_resource_id             = data.azurerm_kubernetes_cluster.this.id
  eventhub_authorization_rule_id = azurerm_eventhub_namespace_authorization_rule.sender.id
  eventhub_name                  = azurerm_eventhub.audit.name

  dynamic "enabled_log" {
    for_each = toset(local.enabled_categories)
    content {
      category = enabled_log.value
    }
  }

  lifecycle {
    precondition {
      condition     = length(local.enabled_categories) > 0
      error_message = "At least one of include_kube_audit_admin, include_kube_audit, or additional_log_categories must produce a category."
    }
  }
}

resource "azurerm_eventhub_namespace_authorization_rule" "sender" {
  name                = "diagnostic-sender"
  namespace_name      = azurerm_eventhub_namespace.this.name
  resource_group_name = local.forwarder_rg

  listen = false
  send   = true
  manage = false
}

resource "azurerm_storage_account" "function" {
  name                            = substr("${replace(local.short_name, "-", "")}sa", 0, 24)
  resource_group_name             = local.forwarder_rg
  location                        = local.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  tags                            = local.common_tags
}

resource "azurerm_storage_container" "function_source" {
  name                  = "function-source"
  storage_account_id    = azurerm_storage_account.function.id
  container_access_type = "private"
}

data "archive_file" "function" {
  type        = "zip"
  output_path = "${path.module}/.build/forwarder.zip"

  source {
    filename = "host.json"
    content  = file("${path.module}/function/host.json")
  }
  source {
    filename = "package.json"
    content  = file("${path.module}/function/package.json")
  }
  source {
    filename = "src/index.mjs"
    content  = file("${path.module}/function/src/index.mjs")
  }
}

resource "azurerm_storage_blob" "function" {
  name                   = "forwarder-${data.archive_file.function.output_base64sha256}.zip"
  storage_account_name   = azurerm_storage_account.function.name
  storage_container_name = azurerm_storage_container.function_source.name
  type                   = "Block"
  source                 = data.archive_file.function.output_path
}

data "azurerm_storage_account_blob_container_sas" "function" {
  connection_string = azurerm_storage_account.function.primary_connection_string
  container_name    = azurerm_storage_container.function_source.name
  https_only        = true

  start  = "2024-01-01"
  expiry = "2099-01-01"

  permissions {
    read   = true
    add    = false
    create = false
    write  = false
    delete = false
    list   = false
  }
}

resource "azurerm_service_plan" "function" {
  name                = "${local.short_name}-plan"
  resource_group_name = local.forwarder_rg
  location            = local.location
  os_type             = "Linux"
  sku_name            = var.function_plan_sku
  tags                = local.common_tags
}

resource "azurerm_linux_function_app" "forwarder" {
  name                       = "${local.short_name}-fn"
  resource_group_name        = local.forwarder_rg
  location                   = local.location
  service_plan_id            = azurerm_service_plan.function.id
  storage_account_name       = azurerm_storage_account.function.name
  storage_account_access_key = azurerm_storage_account.function.primary_access_key
  tags                       = local.common_tags

  https_only = true

  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_stack {
      node_version = "20"
    }
  }

  app_settings = {
    FUNCTIONS_WORKER_RUNTIME = "node"
    WEBSITE_RUN_FROM_PACKAGE = "https://${azurerm_storage_account.function.name}.blob.core.windows.net/${azurerm_storage_container.function_source.name}/${azurerm_storage_blob.function.name}${data.azurerm_storage_account_blob_container_sas.function.sas}"

    EVENT_HUB_NAME                              = azurerm_eventhub.audit.name
    EVENT_HUB_CONSUMER_GROUP                    = azurerm_eventhub_consumer_group.forwarder.name
    EventHubConnection__fullyQualifiedNamespace = "${azurerm_eventhub_namespace.this.name}.servicebus.windows.net"
    EventHubConnection__credential              = "managedidentity"

    INGEST_URL     = var.ingest_url
    INGEST_TOKEN   = "@Microsoft.KeyVault(SecretUri=${azurerm_key_vault_secret.ingest_token.versionless_id})"
    CLUSTER_NAME   = var.cluster_name
    CLUSTER_REGION = local.location
    CLOUD_ACCOUNT  = "${var.resource_group_name}/${var.cluster_name}"
  }

  depends_on = [azurerm_role_assignment.forwarder_secrets_user]
}
