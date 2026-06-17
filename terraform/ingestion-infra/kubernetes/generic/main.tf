locals {
  common_labels = merge(
    {
      "app.kubernetes.io/name"       = "picket-k8s-audit"
      "app.kubernetes.io/component"  = "audit-log-forwarder"
      "app.kubernetes.io/part-of"    = "picket"
      "app.kubernetes.io/managed-by" = "terraform"
    },
    var.extra_labels,
  )

  ingest_url_parts = regex("^(?P<scheme>https?)://(?P<host>[^/]+)(?P<path>/.*)?$", var.ingest_url)
  ingest_host      = local.ingest_url_parts.host
  ingest_uri       = "/events"
  ingest_tls_on    = local.ingest_url_parts.scheme == "https" ? "On" : "Off"

  ingest_secret_name = "picket-ingest"
}

resource "kubernetes_namespace_v1" "this" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name   = var.namespace
    labels = local.common_labels
  }
}

resource "kubernetes_secret_v1" "ingest" {
  metadata {
    name      = local.ingest_secret_name
    namespace = var.namespace
    labels    = local.common_labels
  }

  data = {
    token = var.ingest_token
  }

  type = "Opaque"

  depends_on = [kubernetes_namespace_v1.this]
}

resource "helm_release" "fluent_bit" {
  name       = "picket-audit"
  namespace  = var.namespace
  repository = "https://fluent.github.io/helm-charts"
  chart      = "fluent-bit"
  version    = var.fluent_bit_chart_version

  values = [
    yamlencode({
      kind = "DaemonSet"

      nodeSelector = var.control_plane_node_selector
      tolerations  = var.control_plane_tolerations

      extraVolumes = [
        {
          name = "audit-log"
          hostPath = {
            path = dirname(var.audit_log_host_path)
            type = "DirectoryOrCreate"
          }
        }
      ]

      extraVolumeMounts = [
        {
          name      = "audit-log"
          mountPath = dirname(var.audit_log_host_path)
          readOnly  = true
        }
      ]

      env = [
        {
          name = "INGEST_TOKEN"
          valueFrom = {
            secretKeyRef = {
              name = local.ingest_secret_name
              key  = "token"
            }
          }
        },
        { name = "CLUSTER_NAME", value = var.cluster_name },
        { name = "CLUSTER_REGION", value = var.cluster_region },
      ]

      config = {
        service = <<-EOT
          [SERVICE]
              Daemon          Off
              Flush           5
              Log_Level       info
              Parsers_File    /fluent-bit/etc/parsers.conf
              HTTP_Server     On
              HTTP_Listen     0.0.0.0
              HTTP_Port       2020
        EOT

        inputs = <<-EOT
          [INPUT]
              Name            tail
              Path            ${var.audit_log_host_path}
              Tag             k8s.audit
              Parser          json
              DB              /var/log/flb_audit.db
              Refresh_Interval 5
              Skip_Long_Lines On
        EOT

        filters = <<-EOT
          [FILTER]
              Name            record_modifier
              Match           k8s.audit
              Record          cluster_name $${CLUSTER_NAME}
              Record          cluster_region $${CLUSTER_REGION}
              Record          cloud_provider generic
        EOT

        outputs = <<-EOT
          [OUTPUT]
              Name            http
              Match           k8s.audit
              Host            ${local.ingest_host}
              URI             ${local.ingest_uri}
              Port            ${local.ingest_url_parts.scheme == "https" ? 443 : 80}
              TLS             ${local.ingest_tls_on}
              TLS.Verify      On
              Format          json_lines
              Json_Date_Key   ts
              Json_Date_Format iso8601
              Header          X-Api-Key $${INGEST_TOKEN}
              Header          Content-Type application/json
              Retry_Limit     5
              Compress        gzip
        EOT
      }
    })
  ]

  depends_on = [kubernetes_secret_v1.ingest]
}
