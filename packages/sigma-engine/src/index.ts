import type { AlertSeverity, OcsfClass, OcsfEvent, SourceId } from "@picket/core";
import { RE2JS } from "re2js";

// Pure-JS RE2 port. We use this over `re2-wasm` because `re2-wasm`'s loader
// calls `__dirname` at module init, which Cloudflare Workers doesn't define
// and can't polyfill (Workers has no filesystem to point at). `re2js` is the
// same algorithm — DFA/NFA single-pass, linear-time, ReDoS-safe — just in JS
// instead of compiled C++. Throughput is lower; the safety property is the
// same one we picked RE2 for.

type CompiledRe2 = ReturnType<typeof RE2JS.compile>;

export type RuleExecutionKind = "sigma" | "sql" | "stateful";
export type SigmaScalar = string | number | boolean;
export type SigmaFieldValue = SigmaScalar | SigmaScalar[];
export type SigmaSelection = Record<string, SigmaFieldValue>;

export interface ThresholdStatefulConfig {
  type: "threshold";
  field?: string;
  group_by?: string;
  threshold: number;
  window: string;
  suppress_for?: string;
}

export interface GeoVelocityStatefulConfig {
  type: "geo_velocity";
  field: string;
  location_field: string;
  max_speed_kmh: number;
  window: string;
}

export type StatefulConfig = ThresholdStatefulConfig | GeoVelocityStatefulConfig;

// Config for `execution: sql` rules — aggregation detections the realtime engine
// can't express, run on a schedule by the scheduled-detection worker (Milestone 3).
export interface ScheduledSqlConfig {
  // R2 SQL the rule runs. Should encode its own time window in the WHERE clause.
  query: string;
  // How often the rule should run, e.g. "15m" / "1h".
  interval: string;
  // A returned row fires an alert when row[count_field] >= threshold. When
  // count_field is omitted, every returned row fires (the SQL itself is the
  // filter) and threshold is ignored.
  threshold?: number;
  count_field?: string;
  // Result column(s) that identify the entity an alert is about; used to build a
  // stable per-row dedupe key (comma-separated for composite keys).
  group_by?: string;
}

export interface SigmaLogsource {
  source: SourceId;
  class_name?: OcsfClass;
}

export interface SigmaDetection {
  condition: string;
  [selectionName: string]: string | SigmaSelection;
}

export interface SigmaRule {
  id: string;
  title: string;
  description: string;
  status?: string;
  severity: AlertSeverity;
  tags: string[];
  enabled: boolean;
  execution: RuleExecutionKind;
  logsource: SigmaLogsource;
  // Optional: `execution: sql` rules carry a `sql` block instead of a detection.
  detection?: SigmaDetection;
  dedupe_key?: string;
  dedupe_prefix?: string;
  stateful?: StatefulConfig;
  sql?: ScheduledSqlConfig;
}

export interface SigmaMatch {
  rule_id: string;
  title: string;
  severity: AlertSeverity;
  dedupe_key: string;
}

type SelectionResults = Record<string, boolean>;
type FieldModifier = "equals" | "contains" | "startswith" | "endswith" | "re";
const RE2_FLAGS = RE2JS.CASE_INSENSITIVE;
const MAX_RE2_CACHE_SIZE = 256;
const re2Cache = new Map<string, CompiledRe2>();

export function evaluateSigmaRules(event: OcsfEvent, rules: SigmaRule[]): SigmaMatch[] {
  const matches: SigmaMatch[] = [];

  for (const rule of rules) {
    if (!rule.enabled || rule.execution !== "sigma") continue;
    if (!rule.detection) continue;
    if (!matchesLogsource(event, rule)) continue;

    const selectionResults = evaluateSelections(event, rule);
    if (!evaluateCondition(rule.detection.condition, selectionResults)) continue;

    matches.push({
      rule_id: rule.id,
      title: rule.title,
      severity: rule.severity,
      dedupe_key: buildDedupeKey(event, rule)
    });
  }

  return matches;
}

export function resolveFieldPath(event: OcsfEvent, path: string): unknown {
  const root: unknown = path.startsWith("raw.") ? event.metadata.raw_event : event;
  const parts = path.startsWith("raw.") ? path.slice(4).split(".") : path.split(".");

  let current = root;
  for (const part of parts) {
    if (!current || typeof current !== "object" || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[part];
  }

  return current;
}

export function matchSigmaValue(actual: unknown, expected: SigmaScalar, modifier: FieldModifier = "equals"): boolean {
  if (actual === undefined || actual === null) return false;

  if (modifier === "re") {
    return matchRe2(String(actual), String(expected));
  }

  const actualString = String(actual).toLowerCase();
  const expectedString = String(expected).toLowerCase();

  if (modifier === "contains") return actualString.includes(expectedString);
  if (modifier === "startswith") return actualString.startsWith(expectedString);
  if (modifier === "endswith") return actualString.endsWith(expectedString);
  return actualString === expectedString;
}

function matchRe2(actual: string, pattern: string): boolean {
  try {
    const matcher = cachedRe2(pattern);
    return matcher.test(actual);
  } catch {
    return false;
  }
}

function cachedRe2(pattern: string): CompiledRe2 {
  const cacheKey = `${RE2_FLAGS}\0${pattern}`;
  const cached = re2Cache.get(cacheKey);
  if (cached) return cached;

  if (re2Cache.size >= MAX_RE2_CACHE_SIZE) re2Cache.clear();

  const matcher = RE2JS.compile(pattern, RE2_FLAGS);
  re2Cache.set(cacheKey, matcher);
  return matcher;
}

export function evaluateCondition(condition: string, selections: SelectionResults): boolean {
  const parser = new ConditionParser(tokenize(condition), selections);
  return parser.parse();
}

function matchesLogsource(event: OcsfEvent, rule: SigmaRule): boolean {
  if (event.source !== rule.logsource.source) return false;
  return !rule.logsource.class_name || event.class_name === rule.logsource.class_name;
}

function evaluateSelections(event: OcsfEvent, rule: SigmaRule): SelectionResults {
  const results: SelectionResults = {};
  if (!rule.detection) return results;

  for (const [name, selection] of Object.entries(rule.detection)) {
    if (name === "condition" || typeof selection === "string") continue;
    results[name] = evaluateSelection(event, selection);
  }

  return results;
}

function evaluateSelection(event: OcsfEvent, selection: SigmaSelection): boolean {
  for (const [field, expected] of Object.entries(selection)) {
    const { path, modifier } = parseField(field);
    const actual = resolveFieldPath(event, path);
    const expectedValues = Array.isArray(expected) ? expected : [expected];

    if (!expectedValues.some((candidate) => matchSigmaValue(actual, candidate, modifier))) return false;
  }

  return true;
}

function parseField(field: string): { path: string; modifier: FieldModifier } {
  const [path, rawModifier] = field.split("|");
  if (!path) throw new Error(`Invalid Sigma field: ${field}`);

  if (
    rawModifier === "contains" ||
    rawModifier === "startswith" ||
    rawModifier === "endswith" ||
    rawModifier === "re"
  ) {
    return { path, modifier: rawModifier };
  }

  return { path, modifier: "equals" };
}

function buildDedupeKey(event: OcsfEvent, rule: SigmaRule): string {
  const value = rule.dedupe_key ? resolveFieldPath(event, rule.dedupe_key) : undefined;
  const suffix = value === undefined || value === null || value === "" ? "unknown" : String(value);
  return rule.dedupe_prefix ? `${rule.dedupe_prefix}:${suffix}` : suffix;
}

type Token = { type: "word" | "(" | ")"; value: string };

function tokenize(condition: string): Token[] {
  const tokens: Token[] = [];
  const pattern = /\(|\)|[^\s()]+/g;
  const matches = condition.match(pattern) ?? [];

  for (const value of matches) {
    if (value === "(" || value === ")") tokens.push({ type: value, value });
    else tokens.push({ type: "word", value });
  }

  return tokens;
}

class ConditionParser {
  private index = 0;

  constructor(
    private readonly tokens: Token[],
    private readonly selections: SelectionResults
  ) {}

  parse(): boolean {
    const value = this.parseOr();
    if (this.peek()) throw new Error(`Unexpected token in Sigma condition: ${this.peek()?.value}`);
    return value;
  }

  private parseOr(): boolean {
    let value = this.parseAnd();
    while (this.matchWord("or")) value = this.parseAnd() || value;
    return value;
  }

  private parseAnd(): boolean {
    let value = this.parseNot();
    while (this.matchWord("and")) value = this.parseNot() && value;
    return value;
  }

  private parseNot(): boolean {
    if (this.matchWord("not")) return !this.parseNot();
    return this.parsePrimary();
  }

  private parsePrimary(): boolean {
    if (this.matchType("(")) {
      const value = this.parseOr();
      this.expectType(")");
      return value;
    }

    const token = this.expectWord();
    if ((token.value === "1" || token.value === "all") && this.matchWord("of")) {
      return this.evaluateWildcard(token.value);
    }

    return this.selections[token.value] ?? false;
  }

  private evaluateWildcard(quantifier: string): boolean {
    const pattern = this.expectWord().value;
    const values = Object.entries(this.selections)
      .filter(([name]) => pattern === "them" || (pattern.endsWith("*") && name.startsWith(pattern.slice(0, -1))) || name === pattern)
      .map(([, value]) => value);

    if (values.length === 0) return false;
    return quantifier === "all" ? values.every(Boolean) : values.some(Boolean);
  }

  private matchWord(value: string): boolean {
    const token = this.peek();
    if (token?.type !== "word" || token.value !== value) return false;
    this.index += 1;
    return true;
  }

  private matchType(type: "(" | ")"): boolean {
    if (this.peek()?.type !== type) return false;
    this.index += 1;
    return true;
  }

  private expectType(type: "(" | ")"): void {
    if (!this.matchType(type)) throw new Error(`Expected ${type} in Sigma condition`);
  }

  private expectWord(): Token {
    const token = this.peek();
    if (token?.type !== "word") throw new Error("Expected word in Sigma condition");
    this.index += 1;
    return token;
  }

  private peek(): Token | undefined {
    return this.tokens[this.index];
  }
}
