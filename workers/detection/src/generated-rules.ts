// AUTO-GENERATED - do not edit. Run `pnpm build:rules` to regenerate.
import type { SigmaRule } from "@picket/sigma-engine";

export const SIGMA_RULES: SigmaRule[] = [
  {
    "id": "aws-root-account-usage",
    "title": "AWS root account console login",
    "description": "Detects successful console logins by the AWS root account.",
    "status": "stable",
    "severity": "high",
    "tags": [
      "aws",
      "cloudtrail",
      "identity",
      "privilege"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "aws_cloudtrail",
      "class_name": "authentication"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "activity_name": "ConsoleLogin",
        "status": "success",
        "actor.user.type": "Root"
      }
    },
    "dedupe_key": "cloud.account.uid",
    "dedupe_prefix": "aws-root"
  },
  {
    "id": "aws-console-login-without-mfa",
    "title": "AWS console login without MFA",
    "description": "Detects successful AWS console logins where CloudTrail reports MFAUsed as No.",
    "status": "stable",
    "severity": "medium",
    "tags": [
      "aws",
      "cloudtrail",
      "identity",
      "mfa"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "aws_cloudtrail",
      "class_name": "authentication"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "activity_name": "ConsoleLogin",
        "status": "success",
        "raw.additionalEventData.MFAUsed": "No"
      }
    },
    "dedupe_key": "actor.user.uid",
    "dedupe_prefix": "aws-console-no-mfa"
  },
  {
    "id": "aws-iam-policy-attached-to-user",
    "title": "IAM policy attached to user",
    "description": "Detects CloudTrail IAM policy attachment or inline policy changes made directly to an IAM user.",
    "status": "stable",
    "severity": "high",
    "tags": [
      "aws",
      "cloudtrail",
      "iam",
      "privilege-escalation"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "aws_cloudtrail"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "status": "success",
        "activity_name": [
          "AttachUserPolicy",
          "PutUserPolicy"
        ]
      }
    },
    "dedupe_key": "raw.requestParameters.userName",
    "dedupe_prefix": "aws-iam-user-policy"
  },
  {
    "id": "k8s-anonymous-api-request-succeeded",
    "title": "Kubernetes anonymous API request succeeded",
    "description": "Detects successful Kubernetes API requests made by anonymous or unauthenticated users.",
    "status": "stable",
    "severity": "high",
    "tags": [
      "kubernetes",
      "audit",
      "identity",
      "anonymous-access"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "kubernetes_audit",
      "class_name": "api_activity"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "status": "success",
        "actor.user.name": [
          "system:anonymous",
          "system:unauthenticated"
        ]
      }
    },
    "dedupe_key": "src_endpoint.ip",
    "dedupe_prefix": "k8s-anonymous-api"
  },
  {
    "id": "aws-guardduty-high-severity",
    "title": "AWS GuardDuty high severity finding",
    "description": "Detects high severity GuardDuty findings that should be reviewed promptly.",
    "status": "experimental",
    "severity": "high",
    "tags": [
      "aws",
      "guardduty",
      "finding"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "aws_guardduty",
      "class_name": "detection_finding"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "raw.detail.severity": [
          7,
          8,
          9,
          10
        ]
      }
    },
    "dedupe_key": "metadata.original_uid",
    "dedupe_prefix": "aws-guardduty"
  },
  {
    "id": "aws-vpc-flow-admin-port-accepted",
    "title": "AWS VPC Flow accepted administrative port traffic",
    "description": "Detects accepted VPC Flow Log records targeting common administrative ports from non-private source addresses.",
    "status": "experimental",
    "severity": "medium",
    "tags": [
      "aws",
      "vpc-flow",
      "network",
      "initial-access"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "aws_vpc_flow",
      "class_name": "network_activity"
    },
    "detection": {
      "condition": "selection and not filter_private_source_10 and not filter_private_source_172_16 and not filter_private_source_192_168",
      "selection": {
        "activity_name": "ACCEPT",
        "raw.dstport": [
          "22",
          "3389",
          "5985",
          "5986"
        ]
      },
      "filter_private_source_10": {
        "src_endpoint.ip|startswith": "10."
      },
      "filter_private_source_172_16": {
        "src_endpoint.ip|re": "^172\\.(1[6-9]|2[0-9]|3[0-1])\\."
      },
      "filter_private_source_192_168": {
        "src_endpoint.ip|startswith": "192.168."
      }
    },
    "dedupe_key": "dst_endpoint.ip",
    "dedupe_prefix": "aws-vpc-flow-admin-port"
  },
  {
    "id": "azure-activity-role-assignment-write",
    "title": "Azure role assignment created or changed",
    "description": "Detects Azure role assignment writes from Azure Activity Logs.",
    "status": "experimental",
    "severity": "medium",
    "tags": [
      "azure",
      "iam",
      "privilege-escalation"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "azure_activity",
      "class_name": "api_activity"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "api.operation|contains": "Microsoft.Authorization/roleAssignments/write"
      }
    },
    "dedupe_key": "actor.user.email",
    "dedupe_prefix": "azure-role-assignment-write"
  },
  {
    "id": "azure-ad-signin-failed-mfa",
    "title": "Azure AD sign-in failed MFA requirement",
    "description": "Detects Azure AD sign-ins that failed because the user needed to perform multi-factor authentication.",
    "status": "experimental",
    "severity": "medium",
    "tags": [
      "azure",
      "identity",
      "mfa"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "azure_ad_signin",
      "class_name": "authentication"
    },
    "detection": {
      "condition": "selection_code or selection_reason",
      "selection_code": {
        "status": "failure",
        "raw.status.errorCode": 50076
      },
      "selection_reason": {
        "status": "failure",
        "raw.status.failureReason|contains": "multi-factor authentication"
      }
    },
    "dedupe_key": "actor.user.email",
    "dedupe_prefix": "azure-ad-failed-mfa"
  },
  {
    "id": "azure-ad-signin-legacy-auth",
    "title": "Azure AD legacy authentication sign-in",
    "description": "Detects Azure AD sign-ins using legacy client applications or protocols.",
    "status": "experimental",
    "severity": "medium",
    "tags": [
      "azure",
      "identity",
      "defense-evasion"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "azure_ad_signin",
      "class_name": "authentication"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "raw.clientAppUsed": [
          "Exchange ActiveSync",
          "IMAP",
          "POP",
          "SMTP",
          "Other clients"
        ]
      }
    },
    "dedupe_key": "actor.user.email",
    "dedupe_prefix": "azure-ad-legacy-auth"
  },
  {
    "id": "azure-ad-signin-risky",
    "title": "Azure AD risky sign-in",
    "description": "Detects Azure AD sign-ins with elevated risk state or high aggregate risk level.",
    "status": "experimental",
    "severity": "high",
    "tags": [
      "azure",
      "identity",
      "initial-access"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "azure_ad_signin",
      "class_name": "authentication"
    },
    "detection": {
      "condition": "selection_state or selection_level",
      "selection_state": {
        "raw.riskState": [
          "atRisk",
          "confirmedCompromised"
        ]
      },
      "selection_level": {
        "raw.riskLevelAggregated": [
          "high"
        ]
      }
    },
    "dedupe_key": "actor.user.email",
    "dedupe_prefix": "azure-ad-risky-signin"
  },
  {
    "id": "cloudflare-audit-api-token-change",
    "title": "Cloudflare API token changed",
    "description": "Detects Cloudflare audit events for API token creation, update, or deletion.",
    "status": "experimental",
    "severity": "high",
    "tags": [
      "cloudflare",
      "identity",
      "credential-access"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "cloudflare_audit",
      "class_name": "api_activity"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "api.operation": [
          "api_token_create",
          "api_token_update",
          "api_token_delete"
        ]
      }
    },
    "dedupe_key": "actor.user.email",
    "dedupe_prefix": "cloudflare-api-token-change"
  },
  {
    "id": "cloudflare-audit-member-change",
    "title": "Cloudflare account member changed",
    "description": "Detects Cloudflare audit events for account member or user permission changes.",
    "status": "experimental",
    "severity": "medium",
    "tags": [
      "cloudflare",
      "iam",
      "privilege-escalation"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "cloudflare_audit",
      "class_name": "api_activity"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "api.operation": [
          "account_member_add",
          "account_member_update",
          "account_member_remove",
          "user_update"
        ]
      }
    },
    "dedupe_key": "actor.user.email",
    "dedupe_prefix": "cloudflare-member-change"
  },
  {
    "id": "cloudflare-audit-zone-settings-update",
    "title": "Cloudflare zone settings changed",
    "description": "Detects Cloudflare audit events for zone settings updates.",
    "status": "experimental",
    "severity": "medium",
    "tags": [
      "cloudflare",
      "configuration",
      "defense-evasion"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "cloudflare_audit",
      "class_name": "api_activity"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "api.operation": "zone_settings_update"
      }
    },
    "dedupe_key": "cloud.account.uid",
    "dedupe_prefix": "cloudflare-zone-settings-update"
  },
  {
    "id": "gcp-cloud-audit-iam-policy-change",
    "title": "GCP IAM policy changed",
    "description": "Detects IAM policy changes in GCP Cloud Audit Logs.",
    "status": "experimental",
    "severity": "medium",
    "tags": [
      "gcp",
      "iam",
      "persistence"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "gcp_cloud_audit",
      "class_name": "api_activity"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "api.operation": [
          "SetIamPolicy",
          "google.iam.admin.v1.SetIAMPolicy"
        ]
      }
    },
    "dedupe_key": "actor.user.email",
    "dedupe_prefix": "gcp-iam-policy-change"
  },
  {
    "id": "github-audit-actions-secret-or-workflow-change",
    "title": "GitHub Actions secret or workflow changed",
    "description": "Detects GitHub audit events for Actions secret changes or workflow configuration changes.",
    "status": "experimental",
    "severity": "medium",
    "tags": [
      "github",
      "ci-cd",
      "credential-access"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "github_audit",
      "class_name": "api_activity"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "api.operation": [
          "actions_secret.create",
          "actions_secret.update",
          "actions_secret.remove",
          "workflow.create",
          "workflow.update",
          "workflow.remove",
          "repo.actions_enabled",
          "repo.actions_disabled"
        ]
      }
    },
    "dedupe_key": "raw.repo",
    "dedupe_prefix": "github-actions-change"
  },
  {
    "id": "github-audit-org-member-permission-change",
    "title": "GitHub organization member permission changed",
    "description": "Detects GitHub audit events for organization, repository, or team membership and permission changes.",
    "status": "experimental",
    "severity": "medium",
    "tags": [
      "github",
      "iam",
      "privilege-escalation"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "github_audit"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "api.operation": [
          "org.add_member",
          "org.remove_member",
          "org.update_member",
          "team.add_member",
          "team.remove_member",
          "team.update_member",
          "repo.add_member",
          "repo.remove_member",
          "repo.update_member"
        ]
      }
    },
    "dedupe_key": "user.name",
    "dedupe_prefix": "github-member-change"
  },
  {
    "id": "github-audit-repo-visibility-public",
    "title": "GitHub repository made public",
    "description": "Detects GitHub audit events where a repository visibility change makes the repository public.",
    "status": "experimental",
    "severity": "high",
    "tags": [
      "github",
      "exposure",
      "data-loss"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "github_audit",
      "class_name": "api_activity"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "api.operation": "repo.visibility_change",
        "raw.visibility": "public"
      }
    },
    "dedupe_key": "raw.repo",
    "dedupe_prefix": "github-repo-public"
  },
  {
    "id": "m365-management-audit-log-disabled",
    "title": "Microsoft 365 audit logging disabled",
    "description": "Detects Microsoft 365 audit configuration changes that disable unified audit logging.",
    "status": "experimental",
    "severity": "critical",
    "tags": [
      "m365",
      "defense-evasion"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "m365_management",
      "class_name": "api_activity"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "api.operation": [
          "Set-AdminAuditLogConfig",
          "Set-MailboxAuditBypassAssociation"
        ]
      }
    },
    "dedupe_key": "actor.user.email",
    "dedupe_prefix": "m365-audit-disabled"
  },
  {
    "id": "m365-management-inbox-forwarding-rule",
    "title": "Microsoft 365 inbox forwarding rule created or modified",
    "description": "Detects Exchange inbox rule creation or modification events that may indicate mailbox persistence or collection.",
    "status": "experimental",
    "severity": "high",
    "tags": [
      "m365",
      "exchange",
      "collection"
    ],
    "enabled": true,
    "execution": "sigma",
    "logsource": {
      "source": "m365_management",
      "class_name": "api_activity"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "api.operation": [
          "New-InboxRule",
          "Set-InboxRule"
        ]
      }
    },
    "dedupe_key": "actor.user.email",
    "dedupe_prefix": "m365-inbox-rule"
  }
];

export const STATEFUL_RULES: SigmaRule[] = [
  {
    "id": "k8s-excessive-failed-auth",
    "title": "Excessive failed Kubernetes API authentication",
    "description": "Detects 10 or more forbidden or unauthorized Kubernetes API responses from the same source IP in 5 minutes.",
    "status": "stable",
    "severity": "medium",
    "tags": [
      "kubernetes",
      "audit",
      "identity",
      "brute-force"
    ],
    "enabled": true,
    "execution": "stateful",
    "logsource": {
      "source": "kubernetes_audit",
      "class_name": "api_activity"
    },
    "detection": {
      "condition": "selection",
      "selection": {
        "raw.responseStatus.code": [
          401,
          403
        ]
      }
    },
    "dedupe_key": "src_endpoint.ip",
    "dedupe_prefix": "k8s-failed-auth",
    "stateful": {
      "type": "threshold",
      "field": "src_endpoint.ip",
      "threshold": 10,
      "window": "5m",
      "suppress_for": "15m"
    }
  }
];
