import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";

export interface NistMappingEntry {
  controls: string[];
  family: string;
  intent: string;
}

export type NistMappingTable = Record<string, NistMappingEntry>;

export interface CheckovFailedCheck {
  check_id: string;
  bc_check_id?: string;
  check_name?: string;
  file_path: string;
  file_line_range: number[];
  resource: string;
  guideline?: string;
  severity?: string;
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
  lineRange: [number, number];
  severity: string;
  guideline: string;
  nistControls: string[];
  nistFamily: string;
  controlIntent: string;
  mapped: boolean;
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

export function enrichFindings(
  checks: CheckovFailedCheck[],
  mappings: NistMappingTable,
): EnrichedFinding[] {
  return checks.map((check) => {
    const mapping = mappings[check.check_id];
    const lineRange = check.file_line_range;
    return {
      checkId: check.check_id,
      checkName: check.check_name ?? check.check_id,
      resource: check.resource,
      filePath: check.file_path,
      lineRange: [lineRange[0] ?? 0, lineRange[1] ?? 0],
      severity: check.severity ?? "MEDIUM",
      guideline: check.guideline ?? "",
      nistControls: mapping?.controls ?? [],
      nistFamily: mapping?.family ?? "UNMAPPED",
      controlIntent: mapping?.intent ?? "No NIST mapping defined for this check.",
      mapped: Boolean(mapping),
    };
  });
}

export function summarizeByControl(findings: EnrichedFinding[]) {
  const byControl = new Map<string, EnrichedFinding[]>();

  for (const finding of findings) {
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

export function buildAgentPrompt(
  findings: EnrichedFinding[],
  scanDir: string,
): string {
  const controlSummary = summarizeByControl(findings);
  const findingsJson = JSON.stringify(findings, null, 2);
  const controlBlocks = controlSummary
    .map(([control, items]) => {
      const lines = items
        .map(
          (f) =>
            `  - ${f.severity} ${f.checkId} on ${f.resource} (${f.filePath}:${f.lineRange[0]})`,
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
- Flag inheritance caveats when a control may be inherited from a cloud provider boundary.
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
