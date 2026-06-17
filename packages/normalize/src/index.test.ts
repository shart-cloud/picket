import { describe, expect, it } from "vitest";

import { validateOcsfEvent } from "@picket/core";
import cloudflareAuditFixture from "../../../fixtures/cloudflare-audit/user-update.json";
import cloudTrailFixture from "../../../fixtures/cloudtrail/root-console-login.json";
import guardDutyFixture from "../../../fixtures/guardduty/unauthorized-access.json";
import gcpCloudAuditFixture from "../../../fixtures/gcp-cloud-audit/iam-policy-set.json";
import azureActivityFixture from "../../../fixtures/azure-activity/role-assignment-write.json";
import azureAdSigninFixture from "../../../fixtures/azure-ad-signin/failed-mfa.json";
import githubAuditFixture from "../../../fixtures/github-audit/repo-visibility-change.json";
import m365ManagementFixture from "../../../fixtures/m365-management/inbox-rule-created.json";
import oktaFixture from "../../../fixtures/okta/failed-login.json";
import eksFixture from "../../../fixtures/k8s-audit/eks-anonymous-success.json";
import gkeFixture from "../../../fixtures/k8s-audit/gke-serviceaccount-create.json";
import aksFixture from "../../../fixtures/k8s-audit/aks-rbac-update.json";
import genericFixture from "../../../fixtures/k8s-audit/generic-secret-create.json";
import {
  flavorOfRecord,
  normalizeCloudflareAudit,
  normalizeCloudTrail,
  normalizeGuardDuty,
  normalizeGcpCloudAudit,
  normalizeAzureAdSignin,
  normalizeGithubAudit,
  normalizeM365Management,
  normalizeAzureActivity,
  normalizeK8sAudit,
  normalizeOkta,
  normalizeVpcFlowLog,
  parseVpcFlowLogs,
  parseNdjson
} from "./index";

const vpcFlowFixture = "2 123456789012 eni-0abc123def4567890 10.0.1.10 198.51.100.42 44321 443 6 12 840 1716739200 1716739260 ACCEPT OK";

describe("normalizeCloudTrail", () => {
  it("maps a root console login to an authentication event", () => {
    const event = normalizeCloudTrail(cloudTrailFixture);

    expect(event.source).toBe("aws_cloudtrail");
    expect(event.class_name).toBe("authentication");
    expect(event.activity_name).toBe("ConsoleLogin");
    expect(event.status).toBe("success");
    expect(event.actor?.user?.type).toBe("Root");
    expect(event.src_endpoint?.ip).toBe("203.0.113.10");
    expect(event.cloud?.account?.uid).toBe("123456789012");
  });
});

describe("normalizeOkta", () => {
  it("maps a failed login to an authentication event", () => {
    const event = normalizeOkta(oktaFixture);

    expect(event.source).toBe("okta_auth");
    expect(event.class_name).toBe("authentication");
    expect(event.status).toBe("failure");
    expect(event.user?.email).toBe("alice@example.com");
    expect(event.src_endpoint?.ip).toBe("198.51.100.23");
  });
});

describe("normalizeVpcFlowLog", () => {
  it("maps an accepted VPC Flow Log record to network activity", () => {
    const records = parseVpcFlowLogs(vpcFlowFixture);
    const event = normalizeVpcFlowLog(records[0] ?? {});

    expect(records).toHaveLength(1);
    expect(event.source).toBe("aws_vpc_flow");
    expect(event.category).toBe("network_activity");
    expect(event.class_name).toBe("network_activity");
    expect(event.status).toBe("success");
    expect(event.src_endpoint?.ip).toBe("10.0.1.10");
    expect(event.dst_endpoint?.ip).toBe("198.51.100.42");
    expect(event.cloud?.account?.uid).toBe("123456789012");
    expect(validateOcsfEvent(event)).toEqual([]);
  });
});

describe("normalizeGuardDuty", () => {
  it("maps an EventBridge GuardDuty finding to a detection finding", () => {
    const event = normalizeGuardDuty(guardDutyFixture);

    expect(event.source).toBe("aws_guardduty");
    expect(event.category).toBe("findings");
    expect(event.class_name).toBe("detection_finding");
    expect(event.status).toBe("failure");
    expect(event.src_endpoint?.ip).toBe("198.51.100.66");
    expect(event.cloud?.account?.uid).toBe("123456789012");
    expect(validateOcsfEvent(event)).toEqual([]);
  });
});

describe("normalizeGcpCloudAudit", () => {
  it("maps a GCP Cloud Audit log entry to API activity", () => {
    const event = normalizeGcpCloudAudit(gcpCloudAuditFixture);

    expect(event.source).toBe("gcp_cloud_audit");
    expect(event.class_name).toBe("api_activity");
    expect(event.activity_name).toBe("SetIamPolicy");
    expect(event.status).toBe("success");
    expect(event.actor?.user?.email).toBe("admin@example.com");
    expect(event.cloud?.account?.uid).toBe("prod-project");
    expect(validateOcsfEvent(event)).toEqual([]);
  });
});

describe("normalizeAzureActivity", () => {
  it("maps an Azure Activity record to API activity", () => {
    const event = normalizeAzureActivity(azureActivityFixture);

    expect(event.source).toBe("azure_activity");
    expect(event.class_name).toBe("api_activity");
    expect(event.activity_name).toBe("Microsoft.Authorization/roleAssignments/write");
    expect(event.status).toBe("success");
    expect(event.actor?.user?.email).toBe("admin@example.com");
    expect(event.src_endpoint?.ip).toBe("192.0.2.55");
    expect(validateOcsfEvent(event)).toEqual([]);
  });
});

describe("normalizeAzureAdSignin", () => {
  it("maps an Azure AD sign-in record to an authentication event", () => {
    const event = normalizeAzureAdSignin(azureAdSigninFixture);

    expect(event.source).toBe("azure_ad_signin");
    expect(event.class_name).toBe("authentication");
    expect(event.status).toBe("failure");
    expect(event.actor?.user?.email).toBe("alice@example.com");
    expect(event.src_endpoint?.ip).toBe("198.51.100.77");
    expect(event.cloud?.account?.uid).toBe("72f988bf-86f1-41af-91ab-222222222222");
    expect(validateOcsfEvent(event)).toEqual([]);
  });
});

describe("normalizeGithubAudit", () => {
  it("maps a GitHub audit record to API activity", () => {
    const event = normalizeGithubAudit(githubAuditFixture);

    expect(event.source).toBe("github_audit");
    expect(event.class_name).toBe("api_activity");
    expect(event.activity_name).toBe("repo.visibility_change");
    expect(event.actor?.user?.name).toBe("alice");
    expect(event.src_endpoint?.ip).toBe("203.0.113.88");
    expect(event.cloud?.account?.uid).toBe("example-org");
    expect(validateOcsfEvent(event)).toEqual([]);
  });
});

describe("normalizeM365Management", () => {
  it("maps a Microsoft 365 Management Activity record to API activity", () => {
    const event = normalizeM365Management(m365ManagementFixture);

    expect(event.source).toBe("m365_management");
    expect(event.class_name).toBe("api_activity");
    expect(event.activity_name).toBe("New-InboxRule");
    expect(event.status).toBe("success");
    expect(event.actor?.user?.email).toBe("alice@example.com");
    expect(event.src_endpoint?.ip).toBe("198.51.100.91");
    expect(event.cloud?.account?.uid).toBe("72f988bf-86f1-41af-91ab-222222222222");
    expect(validateOcsfEvent(event)).toEqual([]);
  });
});

describe("normalizeCloudflareAudit", () => {
  it("maps an audit record to an API activity event", () => {
    const event = normalizeCloudflareAudit(cloudflareAuditFixture);

    expect(event.source).toBe("cloudflare_audit");
    expect(event.class_name).toBe("api_activity");
    expect(event.activity_name).toBe("zone_settings_update");
    expect(event.actor?.user?.email).toBe("admin@example.com");
    expect(event.cloud?.provider).toBe("cloudflare");
  });
});

describe("parseNdjson", () => {
  it("parses newline-delimited JSON objects", () => {
    const body = '{"a":1}\n{"b":2}\n{"c":3}';
    expect(parseNdjson(body)).toEqual([{ a: 1 }, { b: 2 }, { c: 3 }]);
  });

  it("skips blank lines and malformed records", () => {
    const body = '{"a":1}\n\n  \nnot json\n[1,2,3]\n{"b":2}';
    // blanks skipped, malformed skipped, top-level arrays skipped (objects only)
    expect(parseNdjson(body)).toEqual([{ a: 1 }, { b: 2 }]);
  });

  it("returns an empty array for empty input", () => {
    expect(parseNdjson("")).toEqual([]);
    expect(parseNdjson("\n  \n")).toEqual([]);
  });
});

describe("flavorOfRecord", () => {
  it("maps cloud_provider to a k8s flavor", () => {
    expect(flavorOfRecord({ cloud_provider: "aws" })).toBe("eks");
    expect(flavorOfRecord({ cloud_provider: "gcp" })).toBe("gke");
    expect(flavorOfRecord({ cloud_provider: "azure" })).toBe("aks");
    expect(flavorOfRecord({ cloud_provider: "generic" })).toBe("generic");
  });

  it("returns undefined for an unknown or missing provider", () => {
    expect(flavorOfRecord({ cloud_provider: "ibm" })).toBeUndefined();
    expect(flavorOfRecord({})).toBeUndefined();
  });
});

describe("normalizeK8sAudit", () => {
  it("normalizes an EKS anonymous-success record", () => {
    const event = normalizeK8sAudit(eksFixture, { flavor: "eks" });

    expect(event.source).toBe("kubernetes_audit");
    expect(event.class_name).toBe("api_activity");
    expect(event.activity_name).toBe("list");
    expect(event.status).toBe("success");
    expect(event.actor?.user?.name).toBe("system:anonymous");
    expect(event.actor?.user?.type).toBe("Anonymous");
    expect(event.src_endpoint?.ip).toBe("203.0.113.42");
    expect(event.api?.service?.name).toBe("kubernetes");
    expect(event.cloud?.provider).toBe("aws");
    expect(event.cloud?.account?.uid).toBe("123456789012");
    expect(event.cloud?.account?.name).toBe("prod-use1");
    expect(event.metadata.original_uid).toBe("b2c3d4e5-0000-4000-8000-000000000002");
    expect(validateOcsfEvent(event)).toEqual([]);
  });

  it("normalizes a GKE Cloud Audit log entry", () => {
    const event = normalizeK8sAudit(gkeFixture, { flavor: "gke" });

    expect(event.source).toBe("kubernetes_audit");
    expect(event.class_name).toBe("api_activity");
    expect(event.activity_name).toBe("io.k8s.core.v1.serviceaccounts.create");
    expect(event.api?.operation).toBe("create");
    expect(event.status).toBe("success");
    expect(event.actor?.user?.email).toBe("deploy@my-prod-project.iam.gserviceaccount.com");
    expect(event.src_endpoint?.ip).toBe("34.120.0.1");
    expect(event.cloud?.provider).toBe("gcp");
    expect(event.cloud?.account?.name).toBe("prod-usc1");
    expect(validateOcsfEvent(event)).toEqual([]);
  });

  it("normalizes an AKS record, unwrapping the diagnostic envelope", () => {
    const event = normalizeK8sAudit(aksFixture, { flavor: "aks" });

    expect(event.source).toBe("kubernetes_audit");
    expect(event.activity_name).toBe("update");
    expect(event.status).toBe("success");
    expect(event.actor?.user?.name).toBe("masterclient");
    expect(event.src_endpoint?.ip).toBe("10.244.0.5");
    expect(event.cloud?.provider).toBe("azure");
    expect(event.cloud?.account?.name).toBe("aks-prod-eus");
    expect(event.metadata.original_uid).toBe("c3d4e5f6-0000-4000-8000-000000000003");
    expect(validateOcsfEvent(event)).toEqual([]);
  });

  it("normalizes a generic Fluent Bit record", () => {
    const event = normalizeK8sAudit(genericFixture, { flavor: "generic" });

    expect(event.source).toBe("kubernetes_audit");
    expect(event.activity_name).toBe("create");
    expect(event.status).toBe("success");
    expect(event.actor?.user?.name).toBe("kubernetes-admin");
    expect(event.actor?.user?.type).toBe("User");
    expect(event.src_endpoint?.ip).toBe("10.0.0.5");
    expect(event.cloud?.provider).toBe("generic");
    expect(validateOcsfEvent(event)).toEqual([]);
  });

  it("infers the flavor from cloud_provider when none is passed", () => {
    const inferred = normalizeK8sAudit(eksFixture);
    const explicit = normalizeK8sAudit(eksFixture, { flavor: "eks" });
    expect(inferred.cloud?.provider).toBe("aws");
    expect(inferred.activity_name).toBe(explicit.activity_name);
  });
});
