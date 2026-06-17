// AUTO-GENERATED - do not edit. Run `pnpm build:rules` to regenerate.
import type { SigmaRule } from "@picket/sigma-engine";

export const SQL_RULES: SigmaRule[] = [
  {
    "id": "aws-cloudtrail-threat-intel-ip-match",
    "title": "CloudTrail activity from a known-malicious IP (threat intel match)",
    "description": "A CloudTrail event originated from a source IP present in the threat_intel enrichment feed. This is a query-time JOIN against the threat_intel Iceberg table, so it runs as a scheduled SQL detection rather than in the realtime engine.\n",
    "severity": "critical",
    "tags": [
      "attack.command_and_control",
      "threat_intel",
      "aws"
    ],
    "enabled": true,
    "execution": "sql",
    "logsource": {
      "source": "aws_cloudtrail",
      "class_name": "api_activity"
    },
    "dedupe_prefix": "aws-ti-ip",
    "sql": {
      "query": "SELECT e.actor_user_uid, e.src_endpoint_ip, ti.feed_name, ti.threat_type, COUNT(*) AS n\nFROM aws_cloudtrail e\nJOIN threat_intel ti\n  ON e.src_endpoint_ip = ti.indicator\nWHERE e.time > now() - interval '1' hour\n  AND ti.indicator_type = 'ipv4'\n  AND ti.active = true\n  AND NOT EXISTS (\n    SELECT 1\n    FROM threat_intel tombstone\n    WHERE tombstone.indicator = ti.indicator\n      AND tombstone.indicator_type = ti.indicator_type\n      AND tombstone.active = false\n      AND tombstone.loaded_at >= ti.loaded_at\n  )\nGROUP BY e.actor_user_uid, e.src_endpoint_ip, ti.feed_name, ti.threat_type\n",
      "interval": "15m",
      "threshold": 1,
      "count_field": "n",
      "group_by": "src_endpoint_ip"
    }
  },
  {
    "id": "aws-iam-privilege-escalation-spike",
    "title": "Spike in IAM privilege-granting actions by a single principal",
    "description": "A single principal performed an unusually high number of IAM privilege-granting actions within one hour. This aggregation cannot be expressed by the realtime engine, so it runs as a scheduled SQL detection. A spike can indicate privilege escalation or a compromised credential.\n",
    "severity": "high",
    "tags": [
      "attack.privilege_escalation",
      "aws"
    ],
    "enabled": true,
    "execution": "sql",
    "logsource": {
      "source": "aws_cloudtrail",
      "class_name": "api_activity"
    },
    "dedupe_prefix": "aws-iam-priv-spike",
    "sql": {
      "query": "SELECT actor_user_uid, COUNT(*) AS n\nFROM aws_cloudtrail\nWHERE time > now() - interval '1' hour\n  AND api_operation IN (\n    'AttachUserPolicy', 'PutUserPolicy',\n    'AttachRolePolicy', 'PutRolePolicy',\n    'CreateAccessKey'\n  )\nGROUP BY actor_user_uid\nHAVING COUNT(*) >= 5\n",
      "interval": "15m",
      "threshold": 5,
      "count_field": "n",
      "group_by": "actor_user_uid"
    }
  },
  {
    "id": "aws-k8s-cross-source-identity",
    "title": "Principal active in both AWS CloudTrail and Kubernetes audit within the hour",
    "description": "The same principal (actor_user_uid) generated activity in both the AWS CloudTrail and Kubernetes audit logs inside the same hour. This cross-source JOIN can only run as a scheduled SQL detection. It is a low-signal correlation meant to surface identities with a broad blast radius or possible lateral movement across the cloud and cluster control planes for analyst review.\n",
    "severity": "medium",
    "tags": [
      "attack.lateral_movement",
      "correlation",
      "aws",
      "kubernetes"
    ],
    "enabled": true,
    "execution": "sql",
    "logsource": {
      "source": "aws_cloudtrail",
      "class_name": "api_activity"
    },
    "dedupe_prefix": "aws-k8s-xsrc",
    "sql": {
      "query": "SELECT c.actor_user_uid, COUNT(*) AS n\nFROM aws_cloudtrail c\nJOIN kubernetes_audit k\n  ON c.actor_user_uid = k.actor_user_uid\nWHERE c.time > now() - interval '1' hour\n  AND k.time > now() - interval '1' hour\nGROUP BY c.actor_user_uid\n",
      "interval": "30m",
      "threshold": 1,
      "count_field": "n",
      "group_by": "actor_user_uid"
    }
  }
];
