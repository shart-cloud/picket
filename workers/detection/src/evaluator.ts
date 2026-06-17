import type { Alert, OcsfEvent } from "@picket/core";
import { evaluateSigmaRules, type SigmaMatch } from "@picket/sigma-engine";

import { SIGMA_RULES } from "./generated-rules";

export function evaluateEvent(event: OcsfEvent): Alert[] {
  return evaluateSigmaRules(event, SIGMA_RULES).map((match) => createAlert(match, event));
}

export function createAlert(match: SigmaMatch, event: OcsfEvent): Alert {
  const now = new Date().toISOString();

  return {
    id: crypto.randomUUID(),
    rule_id: match.rule_id,
    title: match.title,
    severity: match.severity,
    source: event.source,
    status: "open",
    dedupe_key: match.dedupe_key,
    match_count: 1,
    first_seen: event.time || now,
    last_seen: event.time || now,
    event
  };
}
