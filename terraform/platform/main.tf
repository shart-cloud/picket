resource "cloudflare_r2_bucket" "lake" {
  account_id = var.cloudflare_account_id
  name       = var.r2_bucket_name
}

resource "cloudflare_d1_database" "alert_state" {
  account_id = var.cloudflare_account_id
  name       = var.d1_database_name
  read_replication = {
    mode = "disabled"
  }
}

resource "cloudflare_d1_database" "picket_auth" {
  account_id = var.cloudflare_account_id
  name       = var.auth_d1_database_name
  read_replication = {
    mode = "disabled"
  }
}

resource "cloudflare_queue" "alerts" {
  account_id = var.cloudflare_account_id
  queue_name = var.alert_queue_name
}

# Inbound queue for async R2 SQL jobs. picket-admin enqueues a `{ job_id }`
# message on POST /api/v1/query; picket-query-runner consumes, executes
# against R2 SQL, and writes the result back to the `query_jobs` row in D1.
resource "cloudflare_queue" "query_jobs" {
  account_id = var.cloudflare_account_id
  queue_name = var.query_jobs_queue_name
}

resource "cloudflare_workers_kv_namespace" "config" {
  account_id = var.cloudflare_account_id
  title      = var.kv_namespace_title
}

# R2 Data Catalog turns the lake bucket into an Iceberg REST catalog endpoint
# and makes it queryable via R2 SQL. The warehouse identifier surfaced by the
# R2 SQL HTTP API is "<account_id>_<bucket_name>".
resource "cloudflare_r2_data_catalog" "lake" {
  account_id  = var.cloudflare_account_id
  bucket_name = cloudflare_r2_bucket.lake.name
}

# Cloudflare Pipelines (open beta) keeps an internal record of catalog table
# names even after the sink that created them is gone, and refuses to let a
# new sink reuse the name (`1012: writing to existing Catalog tables is not
# yet supported`). Suffixing the table names with a random_pet sidesteps
# the bug: every fresh apply mints names that the platform's stale cache
# has never seen. The suffix is stable across plans (no keepers), so
# subsequent applies don't churn tables; only `terraform destroy + apply`
# generates a new suffix.
resource "random_pet" "tables" {
  length    = 2
  separator = "_"
}

locals {
  # `table_name` is the Iceberg table R2 SQL queries hit; the suffix is
  # exposed as `r2_catalog_table_suffix` output so @picket/query can be
  # configured to match (the CLI's --table-suffix flag, or via env).
  table_suffix = random_pet.tables.id

  pipelines = {
    aws_cloudtrail = {
      pipeline_name = "picket_aws_cloudtrail"
      table_name    = "aws_cloudtrail_${local.table_suffix}"
    }
    aws_vpc_flow = {
      pipeline_name = "picket_aws_vpc_flow"
      table_name    = "aws_vpc_flow_${local.table_suffix}"
    }
    aws_guardduty = {
      pipeline_name = "picket_aws_guardduty"
      table_name    = "aws_guardduty_${local.table_suffix}"
    }
    gcp_cloud_audit = {
      pipeline_name = "picket_gcp_cloud_audit"
      table_name    = "gcp_cloud_audit_${local.table_suffix}"
    }
    azure_activity = {
      pipeline_name = "picket_azure_activity"
      table_name    = "azure_activity_${local.table_suffix}"
    }
    azure_ad_signin = {
      pipeline_name = "picket_azure_ad_signin"
      table_name    = "azure_ad_signin_${local.table_suffix}"
    }
    github_audit = {
      pipeline_name = "picket_github_audit"
      table_name    = "github_audit_${local.table_suffix}"
    }
    m365_management = {
      pipeline_name = "picket_m365_management"
      table_name    = "m365_management_${local.table_suffix}"
    }
    kubernetes_audit = {
      pipeline_name = "picket_kubernetes_audit"
      table_name    = "kubernetes_audit_${local.table_suffix}"
    }
    cloudflare_audit = {
      pipeline_name = "picket_cloudflare_audit"
      table_name    = "cloudflare_audit_${local.table_suffix}"
    }
    alerts = {
      pipeline_name = "picket_alerts"
      table_name    = "picket_alerts_${local.table_suffix}"
    }
    threat_intel = {
      pipeline_name = "picket_threat_intel"
      table_name    = "threat_intel_${local.table_suffix}"
    }
    assets = {
      pipeline_name = "picket_assets"
      table_name    = "assets_${local.table_suffix}"
    }
    users = {
      pipeline_name = "picket_users"
      table_name    = "users_${local.table_suffix}"
    }
  }

  # Field columns flattened from OcsfEvent by @picket/core flattenOcsfEvent.
  # The terraform-provider-cloudflare v5.19.1 surface only exposes primitive
  # types (no struct/list with nested children), so the wire format from
  # the workers is flattened to dotted snake_case keys before being sent.
  event_field_columns = [
    { name = "time", type = "timestamp", required = true },
    { name = "source", type = "string", required = true },
    { name = "category", type = "string", required = true },
    { name = "class_name", type = "string", required = true },
    { name = "activity_name", type = "string", required = true },
    { name = "status", type = "string", required = true },
    { name = "message", type = "string", required = false },
    { name = "actor_user_uid", type = "string", required = false },
    { name = "actor_user_name", type = "string", required = false },
    { name = "actor_user_email", type = "string", required = false },
    { name = "actor_user_type", type = "string", required = false },
    { name = "actor_session_uid", type = "string", required = false },
    { name = "user_uid", type = "string", required = false },
    { name = "user_name", type = "string", required = false },
    { name = "user_email", type = "string", required = false },
    { name = "user_type", type = "string", required = false },
    { name = "src_endpoint_ip", type = "string", required = false },
    { name = "src_endpoint_name", type = "string", required = false },
    { name = "src_endpoint_uid", type = "string", required = false },
    { name = "src_endpoint_country", type = "string", required = false },
    { name = "src_endpoint_region", type = "string", required = false },
    { name = "src_endpoint_city", type = "string", required = false },
    { name = "dst_endpoint_ip", type = "string", required = false },
    { name = "dst_endpoint_name", type = "string", required = false },
    { name = "dst_endpoint_uid", type = "string", required = false },
    { name = "dst_endpoint_country", type = "string", required = false },
    { name = "dst_endpoint_region", type = "string", required = false },
    { name = "dst_endpoint_city", type = "string", required = false },
    { name = "api_operation", type = "string", required = false },
    { name = "api_service_name", type = "string", required = false },
    { name = "cloud_provider", type = "string", required = false },
    { name = "cloud_region", type = "string", required = false },
    { name = "cloud_account_uid", type = "string", required = false },
    { name = "cloud_account_name", type = "string", required = false },
    { name = "http_request_user_agent", type = "string", required = false },
    { name = "http_request_url", type = "string", required = false },
    { name = "http_request_http_method", type = "string", required = false },
    # Ingest-time IOC enrichment (M4): stamped by @picket/core/enrichment when a
    # source/destination IP matches an IOC synced to the enrichment KV namespace.
    { name = "threat_match_indicator", type = "string", required = false },
    { name = "threat_match_indicator_type", type = "string", required = false },
    { name = "threat_match_field", type = "string", required = false },
    { name = "threat_match_feed_name", type = "string", required = false },
    { name = "threat_match_threat_type", type = "string", required = false },
    { name = "metadata_product_name", type = "string", required = true },
    { name = "metadata_original_uid", type = "string", required = false },
    { name = "metadata_raw_event", type = "json", required = false }
  ]

  event_stream_schema = {
    fields = local.event_field_columns
  }

  # Query-time enrichment dimensions. These are written as append-only streams
  # because Pipelines create Iceberg tables but do not provide row updates.
  # `active=false` rows are tombstones that queries should use to ignore older
  # active rows for the same natural key.
  threat_intel_stream_schema = {
    fields = [
      { name = "indicator", type = "string", required = true },
      { name = "indicator_type", type = "string", required = true },
      { name = "feed_name", type = "string", required = false },
      { name = "threat_type", type = "string", required = false },
      { name = "active", type = "bool", required = true },
      { name = "added_at", type = "timestamp", required = true },
      { name = "loaded_at", type = "timestamp", required = true }
    ]
  }

  assets_stream_schema = {
    fields = [
      { name = "asset_uid", type = "string", required = true },
      { name = "hostname", type = "string", required = false },
      { name = "ip", type = "string", required = false },
      { name = "owner", type = "string", required = false },
      { name = "department", type = "string", required = false },
      { name = "criticality", type = "string", required = false },
      { name = "active", type = "bool", required = true },
      { name = "loaded_at", type = "timestamp", required = true }
    ]
  }

  users_stream_schema = {
    fields = [
      { name = "user_uid", type = "string", required = true },
      { name = "user_name", type = "string", required = false },
      { name = "user_email", type = "string", required = false },
      { name = "department", type = "string", required = false },
      { name = "title", type = "string", required = false },
      { name = "criticality", type = "string", required = false },
      { name = "active", type = "bool", required = true },
      { name = "loaded_at", type = "timestamp", required = true }
    ]
  }

  # Alert columns: top-level alert primitives plus the nested OcsfEvent
  # flattened under an `event_` prefix (mirrors flattenAlert).
  alert_stream_schema = {
    fields = concat(
      [
        { name = "id", type = "string", required = true },
        { name = "rule_id", type = "string", required = true },
        { name = "title", type = "string", required = true },
        { name = "severity", type = "string", required = true },
        { name = "source", type = "string", required = true },
        { name = "status", type = "string", required = true },
        { name = "dedupe_key", type = "string", required = false },
        { name = "match_count", type = "int64", required = true },
        { name = "first_seen", type = "timestamp", required = true },
        { name = "last_seen", type = "timestamp", required = true }
      ],
      [
        for f in local.event_field_columns : {
          name     = "event_${f.name}"
          type     = f.type
          required = false
        }
      ]
    )
  }
}

resource "cloudflare_pipeline_stream" "source" {
  for_each = local.pipelines

  account_id = var.cloudflare_account_id
  name       = "${each.value.pipeline_name}_stream"

  # Fed by Workers (picket-ingest for sources, picket-detection for alerts).
  # The stream's name is what `wrangler.jsonc` references in the `pipelines`
  # binding's `pipeline` field.
  worker_binding = {
    enabled = true
  }

  # JSON in (Workers post normalized OCSF events / Alert records as JSON).
  # The terraform-provider-cloudflare v5.19.1 schema surface only exposes
  # primitive field types (int32/64, float32/64, bool, string, binary,
  # timestamp, json) — no struct/list with nested children — so the workers
  # flatten the OCSF wire format (see @picket/core flattenOcsfEvent /
  # flattenAlert) into a single-level object whose keys map 1:1 to the
  # columns enumerated here. `inferred = true` produced Iceberg tables that
  # only materialized the implicit `__ingest_ts` column, so we provide an
  # explicit schema. `timestamp_format = "rfc3339"` lets workers post ISO
  # strings directly into `timestamp` columns.
  schema = merge(
    each.key == "alerts" ? local.alert_stream_schema :
    each.key == "threat_intel" ? local.threat_intel_stream_schema :
    each.key == "assets" ? local.assets_stream_schema :
    each.key == "users" ? local.users_stream_schema :
    local.event_stream_schema,
    {
      format = {
        type             = "json"
        timestamp_format = "rfc3339"
      }
    }
  )

  # The Cloudflare Pipelines API (open beta) does NOT echo `format` /
  # `schema` back on refresh, so every plan reads them as `null` and
  # triggers a forced replacement. Ignore those attributes so plans stay
  # idempotent. Re-enable if/when the provider rounds-trips properly.
  lifecycle {
    ignore_changes = [format, schema]
  }
}

resource "cloudflare_pipeline_sink" "iceberg" {
  for_each = local.pipelines

  account_id = var.cloudflare_account_id
  name       = "${each.value.pipeline_name}_sink"
  type       = "r2_data_catalog"

  format = {
    type        = "parquet"
    compression = "zstd"
  }

  config = {
    account_id = var.cloudflare_account_id
    bucket     = cloudflare_r2_bucket.lake.name
    namespace  = var.r2_catalog_namespace
    table_name = each.value.table_name
    token      = var.r2_catalog_token

    rolling_policy = {
      interval_seconds = var.pipeline_roll_interval_seconds
    }
  }

  depends_on = [cloudflare_r2_data_catalog.lake]

  # Same Pipelines open-beta refresh quirk as the streams: `format` /
  # `schema` aren't echoed back, triggering spurious replacement. Ignore.
  lifecycle {
    ignore_changes = [format, schema]
  }
}

# Account-level Zero Trust org → exposes the team `auth_domain`
# (e.g. "yourteam.cloudflareaccess.com"), which picket-admin needs as
# CF_ACCESS_TEAM_DOMAIN to verify the Cf-Access-Jwt-Assertion JWT.
data "cloudflare_zero_trust_organization" "this" {
  account_id = var.cloudflare_account_id
}

# Look up the parent zone for picket_admin_domain so we can attach a
# Workers Custom Domain. Using the plural `cloudflare_zones` data source
# because the singular one wants a complex `filter` block whereas plural
# accepts `name` directly.
data "cloudflare_zones" "picket_admin_zone" {
  name = var.picket_admin_zone_name
}

data "cloudflare_zones" "picket_ingest_zone" {
  name = var.picket_ingest_zone_name
}

# Routes picket_admin_domain through the picket-admin Worker. This also
# provisions the DNS record and TLS cert automatically. Gated behind
# `picket_admin_worker_deployed` because Cloudflare's API requires the
# Worker to already exist on this account (`10007: This Worker does not
# exist on your account.`) — so this can't be created until after the
# first `pnpm deploy:cloudflare`.
resource "cloudflare_workers_custom_domain" "picket_admin" {
  count      = var.picket_admin_worker_deployed ? 1 : 0
  account_id = var.cloudflare_account_id
  zone_id    = data.cloudflare_zones.picket_admin_zone.result[0].id
  hostname   = var.picket_admin_domain
  service    = "picket-admin"
}

resource "cloudflare_workers_custom_domain" "picket_ingest" {
  account_id = var.cloudflare_account_id
  zone_id    = data.cloudflare_zones.picket_ingest_zone.result[0].id
  hostname   = var.picket_ingest_domain
  service    = "picket-ingest"
}

# Self-hosted Access application that fronts picket-admin. Gated on the same
# flag — without the Worker + custom domain, the destination URI doesn't
# resolve to anything, so creating the app early just produces a broken
# protected resource. The Worker's middleware verifies the
# Cf-Access-Jwt-Assertion JWT this app issues; its `aud` claim is the
# `cf_access_aud` output.
resource "cloudflare_zero_trust_access_application" "picket_admin" {
  count            = var.picket_admin_worker_deployed ? 1 : 0
  account_id       = var.cloudflare_account_id
  name             = "picket-admin"
  type             = "self_hosted"
  session_duration = var.picket_admin_session_duration

  destinations = [
    {
      type = "public"
      uri  = var.picket_admin_domain
    }
  ]

  # One inline allow-policy. GitHub org membership is the default admin gate;
  # optional email rules can be added as break-glass fallback.
  policies = [
    {
      name     = "picket-admin allowed users"
      decision = "allow"
      include = concat(
        length(var.picket_admin_github_teams) == 0 ? [
          {
            github_organization = {
              identity_provider_id = var.picket_admin_github_identity_provider_id
              name                 = var.picket_admin_github_org
            }
          }
          ] : [
          for team in var.picket_admin_github_teams : {
            github_organization = {
              identity_provider_id = var.picket_admin_github_identity_provider_id
              name                 = var.picket_admin_github_org
              team                 = team
            }
          }
        ],
        [for email in var.picket_admin_allowed_emails : {
          email = { email = email }
        }]
      )
    }
  ]
}

resource "cloudflare_pipeline" "flow" {
  for_each = local.pipelines

  account_id = var.cloudflare_account_id
  name       = each.value.pipeline_name

  # Cloudflare Pipelines SQL is `INSERT INTO <sink> SELECT ... FROM <stream>`.
  # Stream/sink are referenced by their `name`. Pipelines are immutable — any
  # change to this SQL forces a destroy+create.
  sql = "INSERT INTO ${cloudflare_pipeline_sink.iceberg[each.key].name} SELECT * FROM ${cloudflare_pipeline_stream.source[each.key].name}"
}
