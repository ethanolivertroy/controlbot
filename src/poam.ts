import { writeFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  formatArtifactPath,
  loadCustomComplianceChecklist,
  loadCustomComplianceResults,
  type CustomComplianceAssessment,
  type CustomComplianceResults,
} from "./custom-compliance.js";
import {
  enrichFindings,
  filterFindingsForPr,
  loadCheckovFindings,
  loadNistMappings,
  type EnrichedFinding,
} from "./lib.js";
import {
  isBlockingSeverity,
  loadControlBotProfile,
  type ControlBotProfile,
  type Severity,
} from "./profile.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

type PoamSeedSource = "checkov" | "custom_compliance";

export interface PoamEvidence {
  path: string;
  line?: number;
  end_line?: number;
  resource?: string;
  detail: string;
}

export interface PoamProvenance {
  check_id?: string;
  check_name?: string;
  guideline?: string;
  mapped?: boolean;
  nist_family?: string;
  custom_rule_id?: string;
  custom_rule_source?: "org" | "local";
  custom_rule_source_path?: string;
  overridden_rule_source?: "org" | "local";
  overridden_rule_source_path?: string;
  assessor?: string;
}

export interface PoamSeed {
  id: string;
  control: string;
  controls: string[];
  weakness: string;
  source: PoamSeedSource;
  severity: Severity;
  evidence: PoamEvidence[];
  recommended_remediation: string;
  owner: string;
  status: "Open";
  due_date: string;
  merge_blocking: boolean;
  provenance: PoamProvenance;
}

export interface PoamSeedDocument {
  schema: "controlbot.poam-seeds.v1";
  generated_at: string;
  baseline: string;
  summary: {
    total: number;
    checkov: number;
    custom_compliance: number;
    merge_blocking: number;
  };
  seeds: PoamSeed[];
}

function parseArgs(argv: string[]) {
  const args = {
    scanDir: resolve(ROOT, "fixtures/terraform"),
    findingsPath: resolve(ROOT, "findings.json"),
    customResultsPath: resolve(ROOT, "custom-compliance-results.json"),
    jsonPath: resolve(ROOT, "poam-seeds.json"),
    markdownPath: resolve(ROOT, "poam-seeds.md"),
    orgChecklistPath: undefined as string | undefined,
    changedFiles: [] as string[],
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--scan-dir" && argv[i + 1]) args.scanDir = resolve(argv[++i]);
    else if (arg === "--findings" && argv[i + 1])
      args.findingsPath = resolve(argv[++i]);
    else if (arg === "--custom-results" && argv[i + 1])
      args.customResultsPath = resolve(argv[++i]);
    else if (arg === "--json" && argv[i + 1])
      args.jsonPath = resolve(argv[++i]);
    else if (arg === "--markdown" && argv[i + 1])
      args.markdownPath = resolve(argv[++i]);
    else if (arg === "--org-checklist" && argv[i + 1])
      args.orgChecklistPath = resolve(argv[++i]);
    else if (arg === "--changed-file" && argv[i + 1])
      args.changedFiles.push(argv[++i]);
    else if (arg === "--changed-files" && argv[i + 1]) {
      const list = argv[++i].split(",").map((f) => f.trim()).filter(Boolean);
      args.changedFiles.push(...list);
    } else if (arg === "--help") {
      console.log(`Usage: npm run poam -- [options]

Build POA&M seed artifacts from ControlBot findings.

Options:
  --scan-dir <path>        Terraform scan root
  --findings <path>        Checkov JSON output
  --custom-results <path>  Custom compliance results JSON
  --json <path>            Output POA&M JSON path
  --markdown <path>        Output POA&M Markdown path
  --org-checklist <path>   Shared org custom compliance checklist
  --changed-file <path>    Limit deterministic findings to PR-changed file (repeatable)
  --changed-files <csv>    Comma-separated changed files
`);
      process.exit(0);
    }
  }

  return args;
}

function normalizeSeverity(severity: string): Severity {
  const normalized = severity.toUpperCase();
  if (
    normalized === "CRITICAL" ||
    normalized === "HIGH" ||
    normalized === "MEDIUM" ||
    normalized === "LOW"
  ) {
    return normalized;
  }
  return "MEDIUM";
}

function addDays(date: Date, days: number): string {
  const next = new Date(date);
  next.setUTCDate(next.getUTCDate() + days);
  return next.toISOString().slice(0, 10);
}

function dueDateForSeverity(severity: Severity, generatedAt: Date): string {
  switch (severity) {
    case "CRITICAL":
      return addDays(generatedAt, 15);
    case "HIGH":
      return addDays(generatedAt, 30);
    case "MEDIUM":
      return addDays(generatedAt, 60);
    case "LOW":
      return addDays(generatedAt, 90);
  }
}

function controlsForFinding(finding: EnrichedFinding): string[] {
  return finding.nistControls.length > 0 ? finding.nistControls : ["UNMAPPED"];
}

function deterministicRemediation(finding: EnrichedFinding): string {
  const guideline = finding.guideline
    ? ` Follow scanner guidance: ${finding.guideline}`
    : "";
  return `Remediate ${finding.checkName} for ${finding.resource} and preserve ${finding.controlIntent}${guideline}`;
}

function seedId(prefix: string, parts: string[]): string {
  const body = parts
    .join("-")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 90);
  return `${prefix}-${body}`;
}

function buildFindingSeed(
  finding: EnrichedFinding,
  profile: ControlBotProfile,
  generatedAt: Date,
  unmappedBlocks: boolean,
): PoamSeed {
  const severity = normalizeSeverity(finding.severity);
  const controls = controlsForFinding(finding);
  const mergeBlocking =
    isBlockingSeverity(severity, profile) || (!finding.mapped && unmappedBlocks);

  return {
    id: seedId("checkov", [
      finding.checkId,
      finding.resource,
      finding.repoPath,
    ]),
    control: controls.join(", "),
    controls,
    weakness: finding.checkName,
    source: "checkov",
    severity,
    evidence: [
      {
        path: finding.repoPath,
        line: finding.lineRange[0],
        end_line: finding.lineRange[1],
        resource: finding.resource,
        detail: finding.controlIntent,
      },
    ],
    recommended_remediation: deterministicRemediation(finding),
    owner: "TBD",
    status: "Open",
    due_date: dueDateForSeverity(severity, generatedAt),
    merge_blocking: mergeBlocking,
    provenance: {
      check_id: finding.checkId,
      check_name: finding.checkName,
      guideline: finding.guideline || undefined,
      mapped: finding.mapped,
      nist_family: finding.nistFamily,
    },
  };
}

function provenanceName(assessment: CustomComplianceAssessment): string {
  if (assessment.ruleSource === "local" && assessment.overriddenRuleSource) {
    return "local override";
  }
  return assessment.ruleSource;
}

function buildCustomSeed(
  assessment: CustomComplianceAssessment,
  generatedAt: Date,
): PoamSeed {
  const severity = normalizeSeverity(assessment.severity);
  const controls =
    assessment.controls.length > 0 ? assessment.controls : ["UNMAPPED"];
  const evidence =
    assessment.evidence.length > 0
      ? assessment.evidence.map((item) => ({
          path: formatArtifactPath(item.path ?? assessment.ruleSourcePath),
          line: item.line,
          detail: item.detail,
        }))
      : [
          {
            path: formatArtifactPath(assessment.ruleSourcePath),
            detail: `${assessment.title} failed (${provenanceName(assessment)} rule).`,
          },
        ];

  return {
    id: seedId("custom", [assessment.ruleId]),
    control: controls.join(", "),
    controls,
    weakness: assessment.title,
    source: "custom_compliance",
    severity,
    evidence,
    recommended_remediation:
      assessment.remediation ??
      `Resolve the failed custom compliance rule: ${assessment.summary}`,
    owner: "TBD",
    status: "Open",
    due_date: dueDateForSeverity(severity, generatedAt),
    merge_blocking: assessment.blocking,
    provenance: {
      custom_rule_id: assessment.ruleId,
      custom_rule_source: assessment.ruleSource,
      custom_rule_source_path: formatArtifactPath(assessment.ruleSourcePath),
      overridden_rule_source: assessment.overriddenRuleSource,
      overridden_rule_source_path: assessment.overriddenRuleSourcePath
        ? formatArtifactPath(assessment.overriddenRuleSourcePath)
        : undefined,
      assessor: assessment.source,
    },
  };
}

export function buildPoamSeedDocument(
  findings: EnrichedFinding[],
  profile: ControlBotProfile,
  customCompliance: CustomComplianceResults,
  generatedAt = new Date(),
): PoamSeedDocument {
  const active = findings.filter((finding) => !finding.inherited);
  const unmapped = active.filter((finding) => !finding.mapped).length;
  const unmappedBlocks = unmapped > profile.block_on_unmapped_count;
  const deterministicSeeds = active.map((finding) =>
    buildFindingSeed(finding, profile, generatedAt, unmappedBlocks),
  );
  const customSeeds = customCompliance.assessments
    .filter((assessment) => assessment.status === "FAIL")
    .map((assessment) => buildCustomSeed(assessment, generatedAt));
  const seeds = [...deterministicSeeds, ...customSeeds];

  return {
    schema: "controlbot.poam-seeds.v1",
    generated_at: generatedAt.toISOString(),
    baseline: profile.baseline,
    summary: {
      total: seeds.length,
      checkov: deterministicSeeds.length,
      custom_compliance: customSeeds.length,
      merge_blocking: seeds.filter((seed) => seed.merge_blocking).length,
    },
    seeds,
  };
}

function markdownEscape(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

export function renderPoamMarkdown(document: PoamSeedDocument): string {
  const lines = [
    "# ControlBot POA&M Seeds",
    "",
    `Generated: ${document.generated_at}`,
    `Baseline: ${document.baseline}`,
    "",
    `Seeds: **${document.summary.total}** · Checkov: **${document.summary.checkov}** · Custom compliance: **${document.summary.custom_compliance}** · Merge-blocking: **${document.summary.merge_blocking}**`,
    "",
    "| ID | Source | Severity | Controls | Weakness | Evidence | Due | Blocking |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
  ];

  for (const seed of document.seeds) {
    const evidence = seed.evidence
      .map((item) =>
        item.line ? `${item.path}:${item.line}` : item.path,
      )
      .join("<br>");
    lines.push(
      `| ${markdownEscape(seed.id)} | ${seed.source} | ${seed.severity} | ${markdownEscape(seed.control)} | ${markdownEscape(seed.weakness)} | ${markdownEscape(evidence)} | ${seed.due_date} | ${seed.merge_blocking ? "yes" : "no"} |`,
    );
  }

  lines.push("", "## Remediation Details", "");

  for (const seed of document.seeds) {
    lines.push(
      `### ${seed.id}`,
      "",
      `- **Source:** ${seed.source}`,
      `- **Controls:** ${seed.control}`,
      `- **Severity:** ${seed.severity}`,
      `- **Owner:** ${seed.owner}`,
      `- **Status:** ${seed.status}`,
      `- **Due date:** ${seed.due_date}`,
      `- **Merge blocking:** ${seed.merge_blocking ? "yes" : "no"}`,
      `- **Recommended remediation:** ${seed.recommended_remediation}`,
      "",
    );
  }

  return lines.join("\n");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const profile = await loadControlBotProfile();
  const checklist = await loadCustomComplianceChecklist({
    orgPath: args.orgChecklistPath,
  });
  const customCompliance = await loadCustomComplianceResults(
    args.customResultsPath,
    checklist,
  );
  const mappings = await loadNistMappings();
  const checks = await loadCheckovFindings(args.findingsPath);
  let findings = enrichFindings(checks, mappings, profile, args.scanDir);

  if (args.changedFiles.length > 0) {
    findings = filterFindingsForPr(findings, args.changedFiles);
    console.log(
      `Filtered POA&M seeds to ${findings.length} deterministic finding(s) on ${args.changedFiles.length} changed file(s)`,
    );
  }

  const document = buildPoamSeedDocument(findings, profile, customCompliance);
  await writeFile(args.jsonPath, JSON.stringify(document, null, 2), "utf8");
  await writeFile(args.markdownPath, renderPoamMarkdown(document), "utf8");

  console.log(
    `POA&M seeds: ${document.summary.total} total, ${document.summary.merge_blocking} merge-blocking`,
  );
  console.log(`Wrote ${args.jsonPath}`);
  console.log(`Wrote ${args.markdownPath}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
