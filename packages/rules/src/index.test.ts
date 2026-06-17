import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { evaluateSigmaRules } from "@picket/sigma-engine";
import { normalizeAzureAdSignin, normalizeCloudflareAudit, normalizeCloudTrail, normalizeGithubAudit, normalizeK8sAudit, normalizeM365Management, normalizeVpcFlowLog } from "@picket/normalize";
import { describe, expect, it } from "vitest";

import { loadSigmaRule, loadSigmaRulesFromDir, toRuleMetadata } from "./index";
import iamPolicyAttachedFixture from "../../../fixtures/cloudtrail/iam-policy-attached-to-user.json";
import iamUserWithoutMfaFixture from "../../../fixtures/cloudtrail/iam-user-console-login-without-mfa.json";
import rootConsoleLoginFixture from "../../../fixtures/cloudtrail/root-console-login.json";
import azureAdSigninFixture from "../../../fixtures/azure-ad-signin/failed-mfa.json";
import cloudflareAuditFixture from "../../../fixtures/cloudflare-audit/user-update.json";
import githubAuditFixture from "../../../fixtures/github-audit/repo-visibility-change.json";
import m365ManagementFixture from "../../../fixtures/m365-management/inbox-rule-created.json";
import k8sAnonymousFixture from "../../../fixtures/k8s-audit/eks-anonymous-success.json";

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const rulesDir = resolve(rootDir, "rules");

describe("Sigma rule loading", () => {
  it("parses a Sigma YAML rule", () => {
    const rule = loadSigmaRule(`
id: test-rule
title: Test rule
description: Test description
severity: low
tags: [test]
logsource:
  source: aws_cloudtrail
  class_name: authentication
detection:
  selection:
    activity_name: ConsoleLogin
  condition: selection
dedupe_key: cloud.account.uid
dedupe_prefix: test
`);

    expect(rule).toMatchObject({
      id: "test-rule",
      execution: "sigma",
      enabled: true,
      logsource: { source: "aws_cloudtrail", class_name: "authentication" }
    });
  });

  it("loads all shipped rules", () => {
    const rules = loadSigmaRulesFromDir(rulesDir);

    expect(rules.map((rule) => rule.id)).toEqual([
      "aws-cloudtrail-threat-intel-ip-match",
      "aws-console-login-without-mfa",
      "aws-guardduty-high-severity",
      "aws-iam-policy-attached-to-user",
      "aws-iam-privilege-escalation-spike",
      "aws-k8s-cross-source-identity",
      "aws-root-account-usage",
      "aws-vpc-flow-admin-port-accepted",
      "aws-vpc-flow-rejected-traffic",
      "azure-activity-role-assignment-write",
      "azure-ad-signin-failed-mfa",
      "azure-ad-signin-legacy-auth",
      "azure-ad-signin-risky",
      "cloudflare-audit-api-token-change",
      "cloudflare-audit-member-change",
      "cloudflare-audit-zone-settings-update",
      "gcp-cloud-audit-iam-policy-change",
      "github-audit-actions-secret-or-workflow-change",
      "github-audit-org-member-permission-change",
      "github-audit-repo-visibility-public",
      "k8s-anonymous-api-request-succeeded",
      "k8s-excessive-failed-auth",
      "m365-management-audit-log-disabled",
      "m365-management-inbox-forwarding-rule",
      "okta-brute-force",
      "okta-impossible-travel"
    ]);
    expect(new Set(rules.map((rule) => rule.id)).size).toBe(rules.length);
  });

  it("ships JOIN-based scheduled SQL rule templates (threat-intel + cross-source)", () => {
    const rules = loadSigmaRulesFromDir(rulesDir);

    const ti = rules.find((rule) => rule.id === "aws-cloudtrail-threat-intel-ip-match");
    expect(ti?.execution).toBe("sql");
    expect(ti?.sql?.query).toContain("JOIN threat_intel");
    expect(ti?.sql).toMatchObject({ interval: "15m", count_field: "n", group_by: "src_endpoint_ip" });

    const xsrc = rules.find((rule) => rule.id === "aws-k8s-cross-source-identity");
    expect(xsrc?.execution).toBe("sql");
    expect(xsrc?.sql?.query).toContain("JOIN kubernetes_audit");
  });

  it("parses a scheduled SQL rule's sql block and omits detection", () => {
    const rules = loadSigmaRulesFromDir(rulesDir);
    const sqlRule = rules.find((rule) => rule.id === "aws-iam-privilege-escalation-spike");

    expect(sqlRule?.execution).toBe("sql");
    expect(sqlRule?.detection).toBeUndefined();
    expect(sqlRule?.sql).toMatchObject({
      interval: "15m",
      threshold: 5,
      count_field: "n",
      group_by: "actor_user_uid"
    });
    expect(sqlRule?.sql?.query).toContain("GROUP BY actor_user_uid");
  });

  it("infers execution: sql from a sql block and rejects sql rules without one", () => {
    const inferred = loadSigmaRule(
      `id: x\ntitle: X\ndescription: d\nseverity: low\nlogsource: { source: aws_cloudtrail }\nsql:\n  query: SELECT 1\n  interval: 5m\n`
    );
    expect(inferred.execution).toBe("sql");

    expect(() =>
      loadSigmaRule(
        `id: y\ntitle: Y\ndescription: d\nseverity: low\nexecution: sql\nlogsource: { source: aws_cloudtrail }\n`
      )
    ).toThrow(/requires a sql block/);
  });

  it("identifies stateful rules without failing parsing", () => {
    const rules = loadSigmaRulesFromDir(rulesDir);

    expect(rules.filter((rule) => rule.execution === "stateful").map((rule) => rule.id)).toEqual([
      "k8s-excessive-failed-auth",
      "okta-brute-force",
      "okta-impossible-travel"
    ]);
    expect(rules.find((rule) => rule.id === "k8s-excessive-failed-auth")?.stateful).toEqual({
      type: "threshold",
      field: "src_endpoint.ip",
      threshold: 10,
      window: "5m",
      suppress_for: "15m"
    });
    expect(rules.find((rule) => rule.id === "okta-brute-force")?.stateful).toEqual({
      type: "threshold",
      field: "src_endpoint.ip",
      threshold: 5,
      window: "15m"
    });
  });

  it("validates threshold stateful config", () => {
    expect(() =>
      loadSigmaRule(`
id: bad-stateful
title: Bad stateful
description: Bad stateful
severity: low
execution: stateful
logsource:
  source: okta_auth
detection:
  selection:
    status: failure
  condition: selection
stateful:
  type: threshold
  threshold: 5
  window: fifteen minutes
`)
    ).toThrow(/group_by or field/);

    expect(() =>
      loadSigmaRule(`
id: bad-stateful-duration
title: Bad stateful duration
description: Bad stateful duration
severity: low
execution: stateful
logsource:
  source: okta_auth
detection:
  selection:
    status: failure
  condition: selection
stateful:
  type: threshold
  field: src_endpoint.ip
  threshold: 5
  window: fifteen minutes
`)
    ).toThrow(/duration/);
  });

  it("projects metadata from parsed rules", () => {
    const [rule] = loadSigmaRulesFromDir(rulesDir).filter((candidate) => candidate.id === "aws-root-account-usage");

    expect(rule && toRuleMetadata(rule)).toMatchObject({
      id: "aws-root-account-usage",
      title: "AWS root account console login",
      severity: "high",
      source: "aws_cloudtrail",
      execution: "sigma"
    });
  });

  it("validates logsource values", () => {
    expect(() =>
      loadSigmaRule(`
id: bad
title: Bad
description: Bad
severity: low
logsource:
  source: unknown
detection:
  selection:
    status: success
  condition: selection
`)
    ).toThrow(/source/);
  });

  it("loads default rules that evaluate against matching fixtures", () => {
    const sigmaRules = loadSigmaRulesFromDir(rulesDir).filter((rule) => rule.execution === "sigma");

    expect(evaluateSigmaRules(normalizeCloudTrail(rootConsoleLoginFixture), sigmaRules)).toEqual(
      expect.arrayContaining([expect.objectContaining({ rule_id: "aws-root-account-usage" })])
    );
    expect(evaluateSigmaRules(normalizeCloudTrail(iamUserWithoutMfaFixture), sigmaRules)).toEqual(
      expect.arrayContaining([expect.objectContaining({ rule_id: "aws-console-login-without-mfa" })])
    );
    expect(evaluateSigmaRules(normalizeCloudTrail(iamPolicyAttachedFixture), sigmaRules)).toEqual([
      expect.objectContaining({ rule_id: "aws-iam-policy-attached-to-user" })
    ]);
    expect(evaluateSigmaRules(normalizeK8sAudit(k8sAnonymousFixture, { flavor: "eks" }), sigmaRules)).toEqual([
      expect.objectContaining({ rule_id: "k8s-anonymous-api-request-succeeded" })
    ]);
    expect(evaluateSigmaRules(normalizeVpcFlowLog({
      account_id: "123456789012",
      interface_id: "eni-1",
      srcaddr: "203.0.113.10",
      dstaddr: "10.0.1.10",
      srcport: "49152",
      dstport: "22",
      protocol: "6",
      packets: "1",
      bytes: "60",
      start: "1716739200",
      end: "1716739260",
      action: "ACCEPT",
      log_status: "OK"
    }), sigmaRules)).toEqual([
      expect.objectContaining({ rule_id: "aws-vpc-flow-admin-port-accepted" })
    ]);
    expect(evaluateSigmaRules(normalizeCloudflareAudit(cloudflareAuditFixture), sigmaRules)).toEqual([
      expect.objectContaining({ rule_id: "cloudflare-audit-zone-settings-update" })
    ]);
    expect(evaluateSigmaRules(normalizeCloudflareAudit({
      ...cloudflareAuditFixture,
      ID: "44444444-4444-4444-8444-444444444444",
      Action: "account_member_update"
    }), sigmaRules)).toEqual([
      expect.objectContaining({ rule_id: "cloudflare-audit-member-change" })
    ]);
    expect(evaluateSigmaRules(normalizeCloudflareAudit({
      ...cloudflareAuditFixture,
      ID: "55555555-5555-4555-8555-555555555555",
      Action: "api_token_create"
    }), sigmaRules)).toEqual([
      expect.objectContaining({ rule_id: "cloudflare-audit-api-token-change" })
    ]);
    expect(evaluateSigmaRules(normalizeGithubAudit(githubAuditFixture), sigmaRules)).toEqual([
      expect.objectContaining({ rule_id: "github-audit-repo-visibility-public" })
    ]);
    expect(evaluateSigmaRules(normalizeGithubAudit({
      ...githubAuditFixture,
      _document_id: "github-audit-0002",
      action: "org.update_member",
      user: "bob",
      visibility: undefined
    }), sigmaRules)).toEqual([
      expect.objectContaining({ rule_id: "github-audit-org-member-permission-change" })
    ]);
    expect(evaluateSigmaRules(normalizeGithubAudit({
      ...githubAuditFixture,
      _document_id: "github-audit-0003",
      action: "actions_secret.update",
      visibility: undefined
    }), sigmaRules)).toEqual([
      expect.objectContaining({ rule_id: "github-audit-actions-secret-or-workflow-change" })
    ]);
    expect(evaluateSigmaRules(normalizeAzureAdSignin(azureAdSigninFixture), sigmaRules)).toEqual([
      expect.objectContaining({ rule_id: "azure-ad-signin-failed-mfa" })
    ]);
    expect(evaluateSigmaRules(normalizeAzureAdSignin({
      ...azureAdSigninFixture,
      id: "66ea54eb-6301-4ee5-be62-ff5a759b0101",
      status: { errorCode: 0 },
      clientAppUsed: "IMAP"
    }), sigmaRules)).toEqual([
      expect.objectContaining({ rule_id: "azure-ad-signin-legacy-auth" })
    ]);
    expect(evaluateSigmaRules(normalizeAzureAdSignin({
      ...azureAdSigninFixture,
      id: "66ea54eb-6301-4ee5-be62-ff5a759b0102",
      status: { errorCode: 0 },
      riskState: "atRisk",
      riskLevelAggregated: "high"
    }), sigmaRules)).toEqual([
      expect.objectContaining({ rule_id: "azure-ad-signin-risky" })
    ]);
    expect(evaluateSigmaRules(normalizeM365Management(m365ManagementFixture), sigmaRules)).toEqual([
      expect.objectContaining({ rule_id: "m365-management-inbox-forwarding-rule" })
    ]);
    expect(evaluateSigmaRules(normalizeM365Management({
      ...m365ManagementFixture,
      Id: "m365-audit-2",
      Operation: "Set-AdminAuditLogConfig"
    }), sigmaRules)).toEqual([
      expect.objectContaining({ rule_id: "m365-management-audit-log-disabled" })
    ]);
  });

  it("loads default rules that do not match negative fixtures", () => {
    const sigmaRules = loadSigmaRulesFromDir(rulesDir).filter((rule) => rule.execution === "sigma");

    expect(
      evaluateSigmaRules(
        normalizeCloudTrail({ ...iamUserWithoutMfaFixture, additionalEventData: { MFAUsed: "Yes" } }),
        sigmaRules
      ).map((match) => match.rule_id)
    ).not.toContain("aws-console-login-without-mfa");
    expect(evaluateSigmaRules(normalizeCloudTrail({ ...iamPolicyAttachedFixture, eventName: "GetUser" }), sigmaRules)).toEqual([]);
    expect(evaluateSigmaRules(normalizeCloudflareAudit({ ...cloudflareAuditFixture, Action: "zone_read" }), sigmaRules)).toEqual([]);
    expect(evaluateSigmaRules(normalizeGithubAudit({ ...githubAuditFixture, visibility: "private" }), sigmaRules)).toEqual([]);
    expect(evaluateSigmaRules(normalizeAzureAdSignin({
      ...azureAdSigninFixture,
      status: { errorCode: 0 },
      clientAppUsed: "Browser",
      riskState: "none",
      riskLevelAggregated: "none"
    }), sigmaRules)).toEqual([]);
  });
});
