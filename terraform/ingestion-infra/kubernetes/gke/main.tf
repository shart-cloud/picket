locals {
  instance_suffix = substr(sha1("${var.project_id}-${var.cluster_name}-${var.cluster_location}"), 0, 8)
  resource_name   = "${var.name_prefix}-${var.cluster_name}-${local.instance_suffix}"

  log_categories = var.include_data_access_logs ? ["activity", "system_event", "data_access"] : ["activity", "system_event"]
  log_name_regex = "projects/${var.project_id}/logs/cloudaudit.googleapis.com%2F(${join("|", local.log_categories)})"

  location_clause = var.cluster_location != "" ? "resource.labels.location=\"${var.cluster_location}\"" : ""
  extra_clause    = var.additional_sink_filter != "" ? "(${var.additional_sink_filter})" : ""

  sink_filter = join(" AND ", compact([
    "resource.type=\"k8s_cluster\"",
    "resource.labels.cluster_name=\"${var.cluster_name}\"",
    local.location_clause,
    "logName=~\"${local.log_name_regex}\"",
    local.extra_clause,
  ]))

  create_source_bucket = var.source_bucket_name == ""
  source_bucket_name   = local.create_source_bucket ? "${var.project_id}-${var.name_prefix}-src" : var.source_bucket_name

  common_labels = merge(
    {
      "app_kubernetes_io_part-of"    = "picket"
      "app_kubernetes_io_component"  = "k8s-audit-forwarder"
      "app_kubernetes_io_managed-by" = "terraform"
      "picket_cluster"         = var.cluster_name
    },
    var.labels,
  )
}

resource "google_pubsub_topic" "audit" {
  project = var.project_id
  name    = local.resource_name
  labels  = local.common_labels
}

resource "google_logging_project_sink" "audit" {
  project                = var.project_id
  name                   = local.resource_name
  destination            = "pubsub.googleapis.com/${google_pubsub_topic.audit.id}"
  filter                 = local.sink_filter
  unique_writer_identity = true
}

resource "google_pubsub_topic_iam_member" "sink_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.audit.name
  role    = "roles/pubsub.publisher"
  member  = google_logging_project_sink.audit.writer_identity
}

resource "google_storage_bucket" "source" {
  count = local.create_source_bucket ? 1 : 0

  project                     = var.project_id
  name                        = local.source_bucket_name
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
  labels                      = local.common_labels

  lifecycle_rule {
    condition { age = 30 }
    action { type = "Delete" }
  }
}

data "archive_file" "function" {
  type        = "zip"
  output_path = "${path.module}/.build/forwarder.zip"

  source {
    filename = "index.mjs"
    content  = file("${path.module}/function/index.mjs")
  }
  source {
    filename = "package.json"
    content  = file("${path.module}/function/package.json")
  }
}

resource "google_storage_bucket_object" "function" {
  name   = "forwarder-${data.archive_file.function.output_base64sha256}.zip"
  bucket = local.source_bucket_name
  source = data.archive_file.function.output_path

  depends_on = [google_storage_bucket.source]
}

resource "google_cloudfunctions2_function" "forwarder" {
  project  = var.project_id
  name     = local.resource_name
  location = var.region
  labels   = local.common_labels

  build_config {
    runtime     = "nodejs20"
    entry_point = "forwardAudit"
    source {
      storage_source {
        bucket = local.source_bucket_name
        object = google_storage_bucket_object.function.name
      }
    }
  }

  service_config {
    available_memory               = "${var.function_memory_mb}M"
    timeout_seconds                = var.function_timeout_seconds
    max_instance_count             = var.function_max_instances
    service_account_email          = google_service_account.forwarder.email
    ingress_settings               = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision = true

    environment_variables = {
      INGEST_URL     = var.ingest_url
      CLUSTER_NAME   = var.cluster_name
      CLUSTER_REGION = var.cluster_location
      CLOUD_ACCOUNT  = var.project_id
    }

    secret_environment_variables {
      key        = "INGEST_TOKEN"
      project_id = var.project_id
      secret     = google_secret_manager_secret.ingest_token.secret_id
      version    = "latest"
    }
  }

  event_trigger {
    trigger_region        = var.region
    event_type            = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic          = google_pubsub_topic.audit.id
    retry_policy          = "RETRY_POLICY_RETRY"
    service_account_email = google_service_account.forwarder.email
  }

  depends_on = [
    google_secret_manager_secret_version.ingest_token,
    google_secret_manager_secret_iam_member.forwarder_accessor,
  ]
}
