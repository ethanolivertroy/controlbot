import { readFile } from "node:fs/promises";
import { relative, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import type { ControlBotProfile } from "./profile.js";
import { isFullyInherited } from "./profile.js";

export interface NistMappingEntry {
  controls: string[];
  family: string;
  intent: string;
  severity?: string;
}

export type NistMappingTable = Record<string, NistMappingEntry>;

export interface CheckovFailedCheck {
  check_id: string;
  bc_check_id?: string;
  check_name?: string;
  file_path: string;
  file_abs_path?: string;
  repo_file_path?: string;
  file_line_range: number[];
  resource: string;
  guideline?: string;
  severity?: string | null;
}

export interface CheckovOutput {
  results?: {
    failed_checks?: CheckovFailedCheck[];
  };
}

export interface EnrichedFinding {
  checkId: string;
  checkName: string;
  resource: string;
  filePath: string;
  repoPath: string;
  lineRange: [number, number];
  severity: string;
  guideline: string;
  nistControls: string[];
  nistFamily: string;
  controlIntent: string;
  mapped: boolean;
  inherited: boolean;
}

export interface InlineReviewComment {
  path: string;
  line: number;
  startLine?: number;
  side: "RIGHT";
  body: string;
}

export interface ReviewPayload {
  event: "REQUEST_CHANGES" | "COMMENT";
  body: string;
  comments: InlineReviewComment[];
  stats: {
    total: number;
    blocking: number;
    inherited_skipped: number;
    unmapped: number;
    inline_posted: number;
  };
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

export async function loadNistMappings(): Promise<NistMappingTable> {
  const raw = await readFile(
    resolve(ROOT, "mappings/checkov-to-nist.yaml"),
    "utf8",
  );
  return parseYaml(raw) as NistMappingTable;
}

export async function loadCheckovFindings(
  path = resolve(ROOT, "findings.json"),
): Promise<CheckovFailedCheck[]> {
  const raw = await readFile(path, "utf8");
  const parsed = JSON.parse(raw) as CheckovOutput | CheckovOutput[];

  const payload = Array.isArray(parsed) ? parsed[0] : parsed;
  return payload.results?.failed_checks ?? [];
}

export function normalizeRepoPath(check: CheckovFailedCheck): string {
  if (check.repo_file_path) {
    return check.repo_file_path.replace(/^\/+/, "").replace(/\\/g, "/");
  }

  if (check.file_abs_path) {
    const rel = relative(ROOT, check.file_abs_path);
    if (!rel.startsWith("..")) {
      return rel.replace(/\\/g, "/");
    }
  }

  return (check.file_path ?? "").replace(/^\/+/, "").replace(/\\/g, "/");
}

export function enrichFindings(
  checks: CheckovFailedCheck[],
  mappings: NistMappingTable,
  profile: ControlBotProfile,
  _scanDir?: string,
): EnrichedFinding[] {
  return checks.map((check) => {
    const mapping = mappings[check.check_id];
    const lineRange = check.file_line_range;
    const nistControls = mapping?.controls ?? [];
    const severity =
      mapping?.severity?.toUpperCase() ??
      check.severity?.toUpperCase() ??
      "MEDIUM";

    return {
      checkId: check.check_id,
      checkName: check.check_name ?? check.check_id,
      resource: check.resource,
      filePath: check.file_path,
      repoPath: normalizeRepoPath(check),
      lineRange: [lineRange[0] ?? 1, lineRange[1] ?? lineRange[0] ?? 1],
      severity,
      guideline: check.guideline ?? "",
      nistControls,
      nistFamily: mapping?.family ?? "UNMAPPED",
      controlIntent:
        mapping?.intent ?? "No NIST mapping defined for this check.",
      mapped: Boolean(mapping),
      inherited: isFullyInherited(nistControls, profile),
    };
  });
}

export function filterFindingsForPr(
  findings: EnrichedFinding[],
  changedFiles: string[],
): EnrichedFinding[] {
  if (changedFiles.length === 0) return findings;

  const changed = new Set(
    changedFiles.map((f) => f.replace(/^\/+/, "").replace(/\\/g, "/")),
  );

  return findings.filter((f) => {
    const repo = f.repoPath.replace(/^\/+/, "");
    return (
      changed.has(repo) ||
      [...changed].some(
        (c) => repo.endsWith(c) || c.endsWith(repo) || repo.includes(c),
      )
    );
  });
}

export function summarizeByControl(findings: EnrichedFinding[]) {
  const byControl = new Map<string, EnrichedFinding[]>();

  for (const finding of findings) {
    if (finding.inherited) continue;

    if (finding.nistControls.length === 0) {
      const bucket = byControl.get("UNMAPPED") ?? [];
      bucket.push(finding);
      byControl.set("UNMAPPED", bucket);
      continue;
    }
    for (const control of finding.nistControls) {
      const bucket = byControl.get(control) ?? [];
      bucket.push(finding);
      byControl.set(control, bucket);
    }
  }

  return [...byControl.entries()].sort(([a], [b]) => a.localeCompare(b));
}

export function buildInlineCommentBody(finding: EnrichedFinding): string {
  const controls =
    finding.nistControls.length > 0
      ? finding.nistControls.join(", ")
      : "_unmapped_";
  const severityBadge =
    finding.severity === "HIGH" || finding.severity === "CRITICAL"
      ? "🔴"
      : finding.severity === "MEDIUM"
        ? "🟡"
        : "🟢";

  return [
    `### ${severityBadge} ${finding.checkId} — NIST ${controls}`,
    "",
    `**Resource:** \`${finding.resource}\``,
    "",
    `**Control intent:** ${finding.controlIntent}`,
    "",
    finding.checkName ? `**Check:** ${finding.checkName}` : "",
    finding.guideline ? `[Policy reference](${finding.guideline})` : "",
    "",
    "_Posted by ControlBot — deterministic Checkov finding enriched with NIST 800-53 mapping._",
  ]
    .filter(Boolean)
    .join("\n");
}

function groupComments(
  findings: EnrichedFinding[],
): InlineReviewComment[] {
  const grouped = new Map<string, EnrichedFinding[]>();

  for (const finding of findings) {
    const key = `${finding.repoPath}:${finding.lineRange[0]}`;
    const bucket = grouped.get(key) ?? [];
    bucket.push(finding);
    grouped.set(key, bucket);
  }

  return [...grouped.entries()].map(([key, items]) => {
    const first = items[0];
    const body =
      items.length === 1
        ? buildInlineCommentBody(first)
        : items.map((f) => buildInlineCommentBody(f)).join("\n\n---\n\n");

    return {
      path: first.repoPath,
      line: first.lineRange[0],
      startLine:
        first.lineRange[0] !== first.lineRange[1]
          ? first.lineRange[0]
          : undefined,
      side: "RIGHT" as const,
      body,
    };
  });
}

export function buildReviewPayload(
  findings: EnrichedFinding[],
  profile: ControlBotProfile,
): ReviewPayload {
  const active = findings.filter((f) => !f.inherited);
  const inheritedSkipped = findings.length - active.length;
  const unmapped = active.filter((f) => !f.mapped).length;
  const blocking = active.filter((f) =>
    profile.block_on_severity.includes(
      f.severity as "HIGH" | "CRITICAL" | "MEDIUM" | "LOW",
    ),
  );

  const shouldBlock =
    blocking.length > 0 || unmapped > profile.block_on_unmapped_count;

  const bySeverity = {
    CRITICAL: active.filter((f) => f.severity === "CRITICAL").length,
    HIGH: active.filter((f) => f.severity === "HIGH").length,
    MEDIUM: active.filter((f) => f.severity === "MEDIUM").length,
    LOW: active.filter((f) => f.severity === "LOW").length,
  };

  const controlSummary = summarizeByControl(active)
    .slice(0, 15)
    .map(([control, items]) => `- **${control}**: ${items.length} finding(s)`)
    .join("\n");

  const body = [
    `## ${profile.bot_name} — NIST 800-53 Review`,
    "",
    `**Baseline:** \`${profile.baseline}\` · **Findings:** ${active.length} (${blocking.length} blocking)`,
    "",
    "| Severity | Count |",
    "| --- | --- |",
    `| 🔴 HIGH | ${bySeverity.HIGH} |`,
    `| 🟡 MEDIUM | ${bySeverity.MEDIUM} |`,
    `| 🟢 LOW | ${bySeverity.LOW} |`,
    "",
    "### Top affected controls",
    controlSummary || "_No mapped control gaps._",
    "",
    inheritedSkipped > 0
      ? `_Skipped ${inheritedSkipped} finding(s) mapped only to inherited controls._`
      : "",
    unmapped > 0
      ? `⚠️ **${unmapped} unmapped** Checkov rule(s) — extend \`mappings/checkov-to-nist.yaml\`.`
      : "",
    "",
    shouldBlock
      ? "❌ **Merge blocked** — resolve blocking control findings or update `.controlbot/profile.yaml`."
      : "✅ **No blocking control findings** — review inline comments before merge.",
    "",
    `<details><summary>Full report</summary>`,
    "",
    "Download the `controlbot-report` artifact for the complete Markdown report.",
    "",
    "</details>",
  ]
    .filter((line) => line !== "")
    .join("\n");

  const inlineFindings = profile.inline_comments ? active : [];
  const comments = groupComments(inlineFindings).slice(
    0,
    profile.max_inline_comments,
  );

  return {
    event: shouldBlock ? "REQUEST_CHANGES" : "COMMENT",
    body,
    comments,
    stats: {
      total: active.length,
      blocking: blocking.length,
      inherited_skipped: inheritedSkipped,
      unmapped,
      inline_posted: comments.length,
    },
  };
}

export function buildAgentPrompt(
  findings: EnrichedFinding[],
  scanDir: string,
  profile: ControlBotProfile,
): string {
  const active = findings.filter((f) => !f.inherited);
  const controlSummary = summarizeByControl(active);
  const findingsJson = JSON.stringify(active, null, 2);
  const controlBlocks = controlSummary
    .map(([control, items]) => {
      const lines = items
        .map(
          (f) =>
            `  - ${f.severity} ${f.checkId} on ${f.resource} (${f.repoPath}:${f.lineRange[0]})`,
        )
        .join("\n");
      return `### ${control}\n${lines}`;
    })
    .join("\n\n");

  return `You are a FedRAMP-oriented IaC assessor. Review Terraform scan results and produce a NIST SP 800-53 Rev 5 compliance report.

## Rules
- Do NOT invent findings. Only analyze the scanner output below and read Terraform files for context.
- For each finding, explain **control intent** (what an assessor tests), not just control IDs.
- Group output by NIST control family (AC, AU, CM, SC, etc.).
- Provide concrete HCL remediation snippets where possible.
- Baseline: ${profile.baseline}
- Inherited controls (do not flag): ${profile.inherited_controls.join(", ") || "none"}
- Mark unmapped scanner checks separately.

## Scan target
Directory: ${scanDir}

## Pre-mapped findings (Checkov → NIST)
${findingsJson}

## Findings grouped by control
${controlBlocks || "_No failed checks._"}

## Required report sections
1. **Executive summary** — count by severity, top 3 risks
2. **Control coverage matrix** — table: Control | Status (Fail/Partial/Pass) | Evidence | Gap
3. **Findings by severity** — HIGH first, with NIST controls and remediation HCL
4. **Unmapped checks** — scanner hits without NIST mapping
5. **Recommended next steps** — CI gates, module swaps, inheritance documentation

Write the report in Markdown. Be specific and cite resource names from the scan.`;
}
