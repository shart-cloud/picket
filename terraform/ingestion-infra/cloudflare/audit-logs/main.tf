locals {
  ingest_events_url = endswith(var.ingest_url, "/events") ? var.ingest_url : "${trimsuffix(var.ingest_url, "/")}/events"
  destination_sep   = strcontains(local.ingest_events_url, "?") ? "&" : "?"
  destination_conf  = "${local.ingest_events_url}${local.destination_sep}header_x-api-key=${urlencode(var.ingest_token)}&header_Content-Type=application/x-ndjson"
}

resource "cloudflare_logpush_job" "audit_logs" {
  account_id       = var.cloudflare_account_id
  name             = var.job_name
  dataset          = "audit_logs"
  destination_conf = local.destination_conf
  enabled          = var.enabled
}
