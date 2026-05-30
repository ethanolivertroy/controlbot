import { readFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import type { ControlBotProfile, Severity } from "./profile.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

export type CustomComplianceStatus =
  | "PASS"
  | "FAIL"
  | "NOT_APPLICABLE"
  | "UNKNOWN";

export interface CustomComplianceRule {
  id: string;
  title: string;
  complianceLabel: boolean;
  objective: string;
  successCriteria?: string;
  failureCriteria?: string;
  controls: string[];
  severity: Severity;
  ruleSource: "org" | "local";
  ruleSourcePath: string;
  overriddenRuleSource?: "org" | "local";
  overriddenRuleSourcePath?: string;
}

export interface CustomComplianceSourceSummary {
  kind: "org" | "local";
  path: string;
  configuredRules: number;
  enabledRules: number;
}

export interface CustomComplianceOverride {
  action: "override" | "disable";
  ruleId: string;
  title: string;
  sourcePath: string;
  overriddenSourcePath?: string;
}

export interface CustomComplianceChecklist {
  sourcePath: string;
  sources: CustomComplianceSourceSummary[];
  overrides: CustomComplianceOverride[];
  rules: CustomComplianceRule[];
}

export interface CustomComplianceEvidence {
  path?: string;
  line?: number;
  detail: string;
}

export interface CustomComplianceAssessment {
  ruleId: string;
  title: string;
  status: CustomComplianceStatus;
  summary: string;
  evidence: CustomComplianceEvidence[];
  remediation?: string;
  controls: string[];
  severity: Severity;
  complianceLabel: boolean;
  blocking: boolean;
  source: "cursor-agent" | "not_assessed";
  ruleSource: "org" | "local";
  ruleSourcePath: string;
  overriddenRuleSource?: "org" | "local";
  overriddenRuleSourcePath?: string;
}

export interface CustomComplianceStats {
  configured: number;
  org_rules: number;
  local_rules: number;
  overrides: number;
  disabled: number;
  assessed: number;
  passed: number;
  failed: number;
  not_applicable: number;
  unknown: number;
  blocking: number;
}

export interface CustomComplianceResults {
  sourcePath: string;
  sources: CustomComplianceSourceSummary[];
  overrides: CustomComplianceOverride[];
  assessedAt: string;
  assessor: "cursor-agent" | "not_assessed";
  assessments: CustomComplianceAssessment[];
  stats: CustomComplianceStats;
}

interface RawChecklist {
  pr_compliances?: unknown;
}

type RawComplianceRule = Record<string, unknown>;

interface AgentAssessment {
  rule_id?: unknown;
  status?: unknown;
  summary?: unknown;
  evidence?: unknown;
  remediation?: unknown;
}

interface ParsedComplianceRule extends CustomComplianceRule {
  enabled: boolean;
}

interface ParsedComplianceChecklist {
  sourcePath: string;
  sourceKind: "org" | "local";
  configuredRules: number;
  rules: ParsedComplianceRule[];
}

export interface LoadCustomComplianceChecklistOptions {
  localPath?: string;
  orgPath?: string | false;
}

const DEFAULT_LOCAL_CHECKLIST_PATH = resolve(ROOT, ".controlbot/checklist.yaml");
const DEFAULT_ORG_CHECKLIST_PATH = resolve(ROOT, ".controlbot/org/checklist.yaml");
const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export function formatArtifactPath(pathValue: string): string {
  if (!pathValue) return pathValue;

  const normalized = pathValue.replace(/\\/g, "/");
  const absolute = isAbsolute(pathValue) ? pathValue : resolve(ROOT, pathValue);
  const repoRelative = relative(ROOT, absolute).replace(/\\/g, "/");

  if (repoRelative && !repoRelative.startsWith("..") && !isAbsolute(repoRelative)) {
    return repoRelative;
  }
  if (!isAbsolute(pathValue) && !normalized.startsWith("..")) {
    return normalized.replace(/^\.\//, "");
  }

  return `external:${basename(pathValue) || "checklist"}`;
}

function isMissingFileError(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    (err as NodeJS.ErrnoException).code === "ENOENT"
  );
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function readString(
  raw: RawComplianceRule,
  field: string,
  errors: string[],
  context: string,
  required = true,
): string | undefined {
  const value = raw[field];
  if (typeof value === "string" && value.trim() !== "") return value.trim();
  if (required) errors.push(`${context}: \`${field}\` must be a non-empty string`);
  return undefined;
}

function readOptionalString(
  raw: RawComplianceRule,
  field: string,
  alias?: string,
): string | undefined {
  const value = raw[field] ?? (alias ? raw[alias] : undefined);
  return typeof value === "string" && value.trim() !== ""
    ? value.trim()
    : undefined;
}

function readComplianceLabel(
  raw: RawComplianceRule,
  errors: string[],
  context: string,
  required = true,
): boolean {
  const value = raw.compliance_label ?? raw.complianceLabel;
  if (typeof value === "boolean") return value;
  if (required) {
    errors.push(`${context}: \`compliance_label\` must be true or false`);
  }
  return false;
}

function readStringArray(raw: RawComplianceRule, field: string): string[] {
  const value = raw[field];
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is string => typeof item === "string")
    .map((item) => item.trim())
    .filter(Boolean);
}

function readSeverity(raw: RawComplianceRule, errors: string[], context: string) {
  const value = raw.severity;
  if (value === undefined) return "MEDIUM" satisfies Severity;
  if (typeof value === "string") {
    const severity = value.toUpperCase() as Severity;
    if (SEVERITIES.includes(severity)) return severity;
  }
  errors.push(
    `${context}: \`severity\` must be one of ${SEVERITIES.join(", ")}`,
  );
  return "MEDIUM" satisfies Severity;
}

function ruleIdFor(
  raw: RawComplianceRule,
  title: string | undefined,
  index: number,
  used: Set<string>,
): string {
  const explicit = typeof raw.id === "string" ? slugify(raw.id) : "";
  const generated = title ? slugify(title) : "";
  const base = explicit || generated || `custom-compliance-${index + 1}`;
  let candidate = base;
  let suffix = 2;

  while (used.has(candidate)) {
    candidate = `${base}-${suffix}`;
    suffix += 1;
  }

  used.add(candidate);
  return candidate;
}

function normalizeChecklist(
  raw: unknown,
  sourcePath: string,
  sourceKind: "org" | "local",
): ParsedComplianceChecklist {
  const checklist = (raw ?? {}) as RawChecklist;
  const rawRules = checklist.pr_compliances;

  if (rawRules === undefined) {
    return { sourcePath, sourceKind, configuredRules: 0, rules: [] };
  }
  if (!Array.isArray(rawRules)) {
    throw new Error(
      `Invalid custom compliance checklist ${sourcePath}: \`pr_compliances\` must be an array`,
    );
  }

  const errors: string[] = [];
  const usedIds = new Set<string>();
  const rules = rawRules.map((item, index) => {
    const context = `pr_compliances[${index}]`;
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      errors.push(`${context}: entry must be an object`);
      item = {};
    }

    const rawRule = item as RawComplianceRule;
    const enabled = rawRule.enabled !== false;
    const title = readString(rawRule, "title", errors, context, enabled);
    const objective = readString(rawRule, "objective", errors, context, enabled);
    const successCriteria = readOptionalString(
      rawRule,
      "success_criteria",
      "successCriteria",
    );
    const failureCriteria = readOptionalString(
      rawRule,
      "failure_criteria",
      "failureCriteria",
    );

    if (!enabled && typeof rawRule.id !== "string") {
      errors.push(`${context}: disabled rules must include an explicit \`id\``);
    }

    if (enabled && !successCriteria && !failureCriteria) {
      errors.push(
        `${context}: at least one of \`success_criteria\` or \`failure_criteria\` is required`,
      );
    }

    return {
      id: ruleIdFor(rawRule, title, index, usedIds),
      title: title ?? `Custom compliance ${index + 1}`,
      complianceLabel: readComplianceLabel(rawRule, errors, context, enabled),
      objective: objective ?? "",
      successCriteria,
      failureCriteria,
      controls: readStringArray(rawRule, "controls"),
      severity: readSeverity(rawRule, errors, context),
      enabled,
      ruleSource: sourceKind,
      ruleSourcePath: sourcePath,
    };
  });

  if (errors.length > 0) {
    throw new Error(
      `Invalid custom compliance checklist ${sourcePath}:\n- ${errors.join("\n- ")}`,
    );
  }

  return {
    sourcePath,
    sourceKind,
    configuredRules: rawRules.length,
    rules,
  };
}

async function loadChecklistSource(
  path: string,
  sourceKind: "org" | "local",
): Promise<ParsedComplianceChecklist> {
  try {
    const raw = await readFile(path, "utf8");
    return normalizeChecklist(parseYaml(raw), path, sourceKind);
  } catch (err) {
    if (isMissingFileError(err)) {
      return {
        sourcePath: path,
        sourceKind,
        configuredRules: 0,
        rules: [],
      };
    }
    throw err;
  }
}

function mergeChecklistSources(
  orgChecklist: ParsedComplianceChecklist,
  localChecklist: ParsedComplianceChecklist,
): CustomComplianceChecklist {
  const byId = new Map<string, CustomComplianceRule>();
  const overrides: CustomComplianceOverride[] = [];
  const sources = [orgChecklist, localChecklist]
    .filter((source) => source.configuredRules > 0)
    .map((source) => ({
      kind: source.sourceKind,
      path: source.sourcePath,
      configuredRules: source.configuredRules,
      enabledRules: source.rules.filter((rule) => rule.enabled).length,
    }));

  for (const rule of orgChecklist.rules) {
    if (!rule.enabled) continue;
    const { enabled: _enabled, ...enabledRule } = rule;
    byId.set(rule.id, enabledRule);
  }

  for (const rule of localChecklist.rules) {
    const existing = byId.get(rule.id);

    if (!rule.enabled) {
      if (existing) {
        byId.delete(rule.id);
        overrides.push({
          action: "disable",
          ruleId: rule.id,
          title: existing.title,
          sourcePath: rule.ruleSourcePath,
          overriddenSourcePath: existing.ruleSourcePath,
        });
      }
      continue;
    }

    const { enabled: _enabled, ...enabledRule } = rule;
    if (existing) {
      enabledRule.overriddenRuleSource = existing.ruleSource;
      enabledRule.overriddenRuleSourcePath = existing.ruleSourcePath;
      overrides.push({
        action: "override",
        ruleId: rule.id,
        title: rule.title,
        sourcePath: rule.ruleSourcePath,
        overriddenSourcePath: existing.ruleSourcePath,
      });
    }

    byId.set(rule.id, enabledRule);
  }

  return {
    sourcePath: localChecklist.sourcePath,
    sources,
    overrides,
    rules: [...byId.values()],
  };
}

function parseChecklistOptions(
  optionsOrPath?: LoadCustomComplianceChecklistOptions | string,
): LoadCustomComplianceChecklistOptions {
  if (typeof optionsOrPath === "string") return { localPath: optionsOrPath };
  return optionsOrPath ?? {};
}

export async function loadCustomComplianceChecklist(
  optionsOrPath?: LoadCustomComplianceChecklistOptions | string,
): Promise<CustomComplianceChecklist> {
  const options = parseChecklistOptions(optionsOrPath);
  const localPath = options.localPath ?? DEFAULT_LOCAL_CHECKLIST_PATH;
  const orgPath =
    options.orgPath === false
      ? false
      : (options.orgPath ??
        process.env.CONTROLBOT_ORG_CHECKLIST ??
        DEFAULT_ORG_CHECKLIST_PATH);
  const [orgChecklist, localChecklist] = await Promise.all([
    orgPath
      ? loadChecklistSource(resolve(orgPath), "org")
      : Promise.resolve({
          sourcePath: "",
          sourceKind: "org" as const,
          configuredRules: 0,
          rules: [],
        }),
    loadChecklistSource(resolve(localPath), "local"),
  ]);

  return mergeChecklistSources(orgChecklist, localChecklist);
}

export function computeCustomComplianceStats(
  assessments: CustomComplianceAssessment[],
  configured: number,
  checklist?: Pick<CustomComplianceChecklist, "rules" | "overrides">,
): CustomComplianceStats {
  return {
    configured,
    org_rules: checklist?.rules.filter((rule) => rule.ruleSource === "org")
      .length ?? 0,
    local_rules: checklist?.rules.filter((rule) => rule.ruleSource === "local")
      .length ?? 0,
    overrides:
      checklist?.overrides.filter((override) => override.action === "override")
        .length ?? 0,
    disabled:
      checklist?.overrides.filter((override) => override.action === "disable")
        .length ?? 0,
    assessed: assessments.filter((a) => a.source !== "not_assessed").length,
    passed: assessments.filter((a) => a.status === "PASS").length,
    failed: assessments.filter((a) => a.status === "FAIL").length,
    not_applicable: assessments.filter((a) => a.status === "NOT_APPLICABLE")
      .length,
    unknown: assessments.filter((a) => a.status === "UNKNOWN").length,
    blocking: assessments.filter((a) => a.blocking).length,
  };
}

export function buildUnassessedCustomComplianceResults(
  checklist: CustomComplianceChecklist,
  reason = "Custom compliance requires the Cursor agent and was not assessed.",
): CustomComplianceResults {
  const artifactChecklist = checklistForArtifacts(checklist);
  const assessments = artifactChecklist.rules.map((rule) => ({
    ruleId: rule.id,
    title: rule.title,
    status: "UNKNOWN" as const,
    summary: reason,
    evidence: [],
    controls: rule.controls,
    severity: rule.severity,
    complianceLabel: rule.complianceLabel,
    blocking: false,
    source: "not_assessed" as const,
    ruleSource: rule.ruleSource,
    ruleSourcePath: rule.ruleSourcePath,
    overriddenRuleSource: rule.overriddenRuleSource,
    overriddenRuleSourcePath: rule.overriddenRuleSourcePath,
  }));

  return {
    sourcePath: artifactChecklist.sourcePath,
    sources: artifactChecklist.sources,
    overrides: artifactChecklist.overrides,
    assessedAt: new Date().toISOString(),
    assessor: "not_assessed",
    assessments,
    stats: computeCustomComplianceStats(
      assessments,
      artifactChecklist.rules.length,
      artifactChecklist,
    ),
  };
}

function checklistForArtifacts(
  checklist: CustomComplianceChecklist,
): CustomComplianceChecklist {
  return {
    sourcePath: formatArtifactPath(checklist.sourcePath),
    sources: checklist.sources.map((source) => ({
      ...source,
      path: formatArtifactPath(source.path),
    })),
    overrides: checklist.overrides.map((override) => ({
      ...override,
      sourcePath: formatArtifactPath(override.sourcePath),
      overriddenSourcePath: override.overriddenSourcePath
        ? formatArtifactPath(override.overriddenSourcePath)
        : undefined,
    })),
    rules: checklist.rules.map((rule) => ({
      ...rule,
      ruleSourcePath: formatArtifactPath(rule.ruleSourcePath),
      overriddenRuleSourcePath: rule.overriddenRuleSourcePath
        ? formatArtifactPath(rule.overriddenRuleSourcePath)
        : undefined,
    })),
  };
}

function resultsForArtifacts(
  results: CustomComplianceResults,
): CustomComplianceResults {
  return {
    ...results,
    sourcePath: formatArtifactPath(results.sourcePath),
    sources: results.sources.map((source) => ({
      ...source,
      path: formatArtifactPath(source.path),
    })),
    overrides: results.overrides.map((override) => ({
      ...override,
      sourcePath: formatArtifactPath(override.sourcePath),
      overriddenSourcePath: override.overriddenSourcePath
        ? formatArtifactPath(override.overriddenSourcePath)
        : undefined,
    })),
    assessments: results.assessments.map((assessment) => ({
      ...assessment,
      evidence: assessment.evidence.map((item) => ({
        ...item,
        path: item.path ? formatArtifactPath(item.path) : undefined,
      })),
      ruleSourcePath: formatArtifactPath(assessment.ruleSourcePath),
      overriddenRuleSourcePath: assessment.overriddenRuleSourcePath
        ? formatArtifactPath(assessment.overriddenRuleSourcePath)
        : undefined,
    })),
  };
}

function normalizeStatus(value: unknown): CustomComplianceStatus {
  if (typeof value !== "string") return "UNKNOWN";
  const normalized = value.toUpperCase().replace(/[\s-]+/g, "_");
  if (
    normalized === "PASS" ||
    normalized === "FAIL" ||
    normalized === "NOT_APPLICABLE" ||
    normalized === "UNKNOWN"
  ) {
    return normalized;
  }
  return "UNKNOWN";
}

function normalizeEvidence(value: unknown): CustomComplianceEvidence[] {
  if (!Array.isArray(value)) return [];

  return value.flatMap((item) => {
    if (typeof item === "string" && item.trim() !== "") {
      return [{ detail: item.trim() }];
    }
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      return [];
    }

    const raw = item as Record<string, unknown>;
    const detail =
      typeof raw.detail === "string" && raw.detail.trim() !== ""
        ? raw.detail.trim()
        : typeof raw.summary === "string" && raw.summary.trim() !== ""
          ? raw.summary.trim()
          : "";
    if (!detail) return [];

    return [
      {
        path:
          typeof raw.path === "string" && raw.path.trim() !== ""
            ? raw.path.trim()
            : undefined,
        line: typeof raw.line === "number" ? raw.line : undefined,
        detail,
      },
    ];
  });
}

export function buildCustomComplianceResults(
  checklist: CustomComplianceChecklist,
  rawAssessments: unknown[],
): CustomComplianceResults {
  const artifactChecklist = checklistForArtifacts(checklist);
  const agentAssessments = rawAssessments.filter(
    (assessment): assessment is AgentAssessment =>
      typeof assessment === "object" &&
      assessment !== null &&
      !Array.isArray(assessment),
  );
  const byRule = new Map(
    agentAssessments
      .filter((assessment) => typeof assessment.rule_id === "string")
      .map((assessment) => [assessment.rule_id as string, assessment]),
  );

  const assessments = artifactChecklist.rules.map((rule) => {
    const raw = byRule.get(rule.id);
    const status = normalizeStatus(raw?.status);
    const summary =
      typeof raw?.summary === "string" && raw.summary.trim() !== ""
        ? raw.summary.trim()
        : "The Cursor agent did not return a clear assessment for this rule.";
    const remediation =
      typeof raw?.remediation === "string" && raw.remediation.trim() !== ""
        ? raw.remediation.trim()
        : undefined;

    return {
      ruleId: rule.id,
      title: rule.title,
      status,
      summary,
      evidence: normalizeEvidence(raw?.evidence),
      remediation,
      controls: rule.controls,
      severity: rule.severity,
      complianceLabel: rule.complianceLabel,
      blocking: status === "FAIL" && rule.complianceLabel,
      source: "cursor-agent" as const,
      ruleSource: rule.ruleSource,
      ruleSourcePath: rule.ruleSourcePath,
      overriddenRuleSource: rule.overriddenRuleSource,
      overriddenRuleSourcePath: rule.overriddenRuleSourcePath,
    };
  });

  return {
    sourcePath: artifactChecklist.sourcePath,
    sources: artifactChecklist.sources,
    overrides: artifactChecklist.overrides,
    assessedAt: new Date().toISOString(),
    assessor: "cursor-agent",
    assessments,
    stats: computeCustomComplianceStats(
      assessments,
      artifactChecklist.rules.length,
      artifactChecklist,
    ),
  };
}

export async function loadCustomComplianceResults(
  path: string,
  checklist: CustomComplianceChecklist,
): Promise<CustomComplianceResults> {
  try {
    const raw = await readFile(path, "utf8");
    const parsed = JSON.parse(raw) as CustomComplianceResults;
    const assessments = Array.isArray(parsed.assessments)
      ? parsed.assessments
      : [];
    return resultsForArtifacts({
      ...parsed,
      sourcePath: parsed.sourcePath ?? checklist.sourcePath,
      sources: parsed.sources ?? checklist.sources,
      overrides: parsed.overrides ?? checklist.overrides,
      assessedAt: parsed.assessedAt ?? new Date().toISOString(),
      assessor: parsed.assessor ?? "not_assessed",
      assessments,
      stats: computeCustomComplianceStats(
        assessments,
        checklist.rules.length,
        checklist,
      ),
    });
  } catch (err) {
    if (isMissingFileError(err)) {
      return buildUnassessedCustomComplianceResults(
        checklist,
        "No custom compliance assessment artifact was found.",
      );
    }
    throw err;
  }
}

export function buildCustomComplianceAssessmentPrompt(
  checklist: CustomComplianceChecklist,
  scanDir: string,
  profile: ControlBotProfile,
): string {
  const rules = checklist.rules.map((rule) => ({
    rule_id: rule.id,
    title: rule.title,
    compliance_label: rule.complianceLabel,
    objective: rule.objective,
    success_criteria: rule.successCriteria,
    failure_criteria: rule.failureCriteria,
    controls: rule.controls,
    severity: rule.severity,
    source: rule.ruleSource,
    source_path: formatArtifactPath(rule.ruleSourcePath),
    overridden_source: rule.overriddenRuleSource,
    overridden_source_path: rule.overriddenRuleSourcePath
      ? formatArtifactPath(rule.overriddenRuleSourcePath)
      : undefined,
  }));

  return `You are ControlBot's custom compliance assessor. Assess only the custom checklist below.

## Scope
- Repository root: ${ROOT}
- Terraform scan directory: ${scanDir}
- Baseline: ${profile.baseline}
- Checklist sources: ${checklist.sources.map((source) => `${source.kind}:${formatArtifactPath(source.path)}`).join(", ") || "none"}
- Local overrides: ${checklist.overrides.length}

## Separation rule
- Do not restate deterministic Checkov/NIST findings as custom compliance failures.
- Custom compliance is LLM-judged policy/process assessment. Mark a rule FAIL only when the repository evidence clearly violates that rule.
- If evidence is missing or the rule cannot be assessed from local files, return UNKNOWN.
- Use NOT_APPLICABLE when the rule is irrelevant to the changed or scanned infrastructure.

## Checklist
${JSON.stringify(rules, null, 2)}

## Output
Return only valid JSON with this exact shape:
{
  "assessments": [
    {
      "rule_id": "string from checklist",
      "status": "PASS | FAIL | NOT_APPLICABLE | UNKNOWN",
      "summary": "one concrete sentence",
      "evidence": [
        { "path": "repo-relative path", "line": 1, "detail": "specific evidence" }
      ],
      "remediation": "specific remediation when status is FAIL"
    }
  ]
}

Assess every checklist item exactly once.`;
}
