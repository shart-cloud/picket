import type { OcsfEvent } from "@picket/core";
import { normalizeCloudTrail, normalizeOkta } from "@picket/normalize";
import { describe, expect, it } from "vitest";

import {
  evaluateCondition,
  evaluateSigmaRules,
  matchSigmaValue,
  resolveFieldPath,
  type SigmaRule
} from "./index";
import iamPolicyAttachedFixture from "../../../fixtures/cloudtrail/iam-policy-attached-to-user.json";
import iamUserWithoutMfaFixture from "../../../fixtures/cloudtrail/iam-user-console-login-without-mfa.json";
import rootConsoleLoginFixture from "../../../fixtures/cloudtrail/root-console-login.json";
import oktaFailedLoginFixture from "../../../fixtures/okta/failed-login.json";

const sigmaRules: SigmaRule[] = [
  {
    id: "aws-root-account-usage",
    title: "AWS root account console login",
    description: "Detects successful console logins by the AWS root account.",
    severity: "high",
    tags: [],
    enabled: true,
    execution: "sigma",
    logsource: { source: "aws_cloudtrail", class_name: "authentication" },
    detection: {
      selection: { activity_name: "ConsoleLogin", status: "success", "actor.user.type": "Root" },
      condition: "selection"
    },
    dedupe_key: "cloud.account.uid",
    dedupe_prefix: "aws-root"
  },
  {
    id: "aws-console-login-without-mfa",
    title: "AWS console login without MFA",
    description: "Detects successful AWS console logins where CloudTrail reports MFAUsed as No.",
    severity: "medium",
    tags: [],
    enabled: true,
    execution: "sigma",
    logsource: { source: "aws_cloudtrail", class_name: "authentication" },
    detection: {
      selection: { activity_name: "ConsoleLogin", status: "success", "raw.additionalEventData.MFAUsed": "No" },
      condition: "selection"
    },
    dedupe_key: "actor.user.uid",
    dedupe_prefix: "aws-console-no-mfa"
  },
  {
    id: "aws-iam-policy-attached-to-user",
    title: "IAM policy attached to user",
    description: "Detects CloudTrail IAM policy attachment or inline policy changes made directly to an IAM user.",
    severity: "high",
    tags: [],
    enabled: true,
    execution: "sigma",
    logsource: { source: "aws_cloudtrail" },
    detection: {
      selection: { status: "success", activity_name: ["AttachUserPolicy", "PutUserPolicy"] },
      condition: "selection"
    },
    dedupe_key: "raw.requestParameters.userName",
    dedupe_prefix: "aws-iam-user-policy"
  }
];

describe("field resolution", () => {
  const event = normalizeCloudTrail(iamUserWithoutMfaFixture);

  it("resolves dot paths", () => {
    expect(resolveFieldPath(event, "actor.user.uid")).toBe("AIDAEXAMPLE");
  });

  it("resolves raw event paths", () => {
    expect(resolveFieldPath(event, "raw.additionalEventData.MFAUsed")).toBe("No");
  });

  it("returns undefined for missing fields", () => {
    expect(resolveFieldPath(event, "actor.user.missing")).toBeUndefined();
  });
});

describe("value matching", () => {
  it("matches exact strings case-insensitively", () => {
    expect(matchSigmaValue("ConsoleLogin", "consolelogin")).toBe(true);
  });

  it("supports contains", () => {
    expect(matchSigmaValue("Administrator", "admin", "contains")).toBe(true);
  });

  it("supports startswith", () => {
    expect(matchSigmaValue("AttachUserPolicy", "Attach", "startswith")).toBe(true);
  });

  it("supports endswith", () => {
    expect(matchSigmaValue("AttachUserPolicy", "Policy", "endswith")).toBe(true);
  });

  it("supports regex", () => {
    expect(matchSigmaValue("AttachUserPolicy", "attach.*policy", "re")).toBe(true);
  });

  it("fails closed for regex syntax unsupported by RE2", () => {
    expect(matchSigmaValue("foobar", "foo(?=bar)", "re")).toBe(false);
  });

  it("uses linear-time regex matching for catastrophic backtracking patterns", () => {
    expect(matchSigmaValue(`${"a".repeat(5_000)}!`, "(a+)+$", "re")).toBe(false);
  });
});

describe("condition evaluation", () => {
  it("evaluates and, or, not, and parentheses", () => {
    expect(evaluateCondition("(selection1 or selection2) and not filter", { selection1: false, selection2: true, filter: false })).toBe(true);
  });

  it("evaluates wildcard any", () => {
    expect(evaluateCondition("1 of selection*", { selection_a: false, selection_b: true, filter: true })).toBe(true);
  });

  it("evaluates wildcard all", () => {
    expect(evaluateCondition("all of selection*", { selection_a: true, selection_b: true, filter: false })).toBe(true);
  });

  it("evaluates them", () => {
    expect(evaluateCondition("1 of them", { selection: false, other: true })).toBe(true);
  });
});

describe("evaluateSigmaRules", () => {
  it("skips stateful rules", () => {
    const event = normalizeOkta(oktaFailedLoginFixture);
    const statefulRule: SigmaRule = {
      id: "okta-brute-force",
      title: "Okta brute force authentication failures",
      description: "Requires stateful threshold evaluation.",
      severity: "medium",
      tags: [],
      enabled: true,
      execution: "stateful",
      logsource: { source: "okta_auth", class_name: "authentication" },
      detection: { selection: { status: "failure" }, condition: "selection" },
      dedupe_key: "src_endpoint.ip",
      dedupe_prefix: "okta-brute-force"
    };

    expect(evaluateSigmaRules(event, [statefulRule])).toEqual([]);
  });

  it("matches AWS root console login", () => {
    const event = normalizeCloudTrail(rootConsoleLoginFixture);

    expect(evaluateSigmaRules(event, sigmaRules)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          rule_id: "aws-root-account-usage",
          severity: "high",
          dedupe_key: "aws-root:123456789012"
        })
      ])
    );
  });

  it("matches AWS console login without MFA", () => {
    const event = normalizeCloudTrail(iamUserWithoutMfaFixture);

    expect(evaluateSigmaRules(event, sigmaRules)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          rule_id: "aws-console-login-without-mfa",
          severity: "medium",
          dedupe_key: "aws-console-no-mfa:AIDAEXAMPLE"
        })
      ])
    );
  });

  it("matches IAM policy attached to a user", () => {
    const event = normalizeCloudTrail(iamPolicyAttachedFixture);

    expect(evaluateSigmaRules(event, sigmaRules)).toEqual([
      expect.objectContaining({
        rule_id: "aws-iam-policy-attached-to-user",
        severity: "high",
        dedupe_key: "aws-iam-user-policy:alice"
      })
    ]);
  });

  it("does not match console login with MFA", () => {
    const event = normalizeCloudTrail({
      ...iamUserWithoutMfaFixture,
      additionalEventData: { MFAUsed: "Yes" }
    });

    expect(evaluateSigmaRules(event, sigmaRules).map((match) => match.rule_id)).not.toContain("aws-console-login-without-mfa");
  });

  it("does not match unrelated IAM API events", () => {
    const event = normalizeCloudTrail({
      ...iamPolicyAttachedFixture,
      eventName: "GetUser"
    });

    expect(evaluateSigmaRules(event, sigmaRules)).toEqual([]);
  });

  it("applies logsource filtering", () => {
    const event: OcsfEvent = { ...normalizeOkta(oktaFailedLoginFixture), activity_name: "ConsoleLogin", status: "success" };
    const rule: SigmaRule = {
      id: "aws-only",
      title: "AWS only",
      description: "AWS only",
      severity: "low",
      tags: [],
      enabled: true,
      execution: "sigma",
      logsource: { source: "aws_cloudtrail" },
      detection: { selection: { activity_name: "ConsoleLogin" }, condition: "selection" },
      dedupe_prefix: "test"
    };

    expect(evaluateSigmaRules(event, [rule])).toEqual([]);
  });
});

describe("sql rules", () => {
  it("are skipped by the realtime engine without throwing on a missing detection", () => {
    const event = normalizeCloudTrail(iamPolicyAttachedFixture);
    const sqlRule: SigmaRule = {
      id: "aws-iam-privilege-escalation-spike",
      title: "Spike",
      description: "d",
      severity: "high",
      tags: [],
      enabled: true,
      execution: "sql",
      logsource: { source: "aws_cloudtrail" },
      sql: { query: "SELECT 1", interval: "15m", threshold: 5, count_field: "n", group_by: "actor_user_uid" }
    };

    expect(evaluateSigmaRules(event, [sqlRule])).toEqual([]);
  });
});
