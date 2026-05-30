import { writeFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Agent, CursorAgentError } from "@cursor/sdk";
import {
  buildCustomComplianceAssessmentPrompt,
  buildCustomComplianceResults,
  buildUnassessedCustomComplianceResults,
  loadCustomComplianceChecklist,
  type CustomComplianceResults,
} from "./custom-compliance.js";
import {
  buildAgentPrompt,
  enrichFindings,
  loadCheckovFindings,
  loadNistMappings,
} from "./lib.js";
import { loadControlBotProfile } from "./profile.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

function parseArgs(argv: string[]) {
  const args = {
    scanDir: resolve(ROOT, "fixtures/terraform"),
    findingsPath: resolve(ROOT, "findings.json"),
    reportPath: resolve(ROOT, "report.md"),
    customResultsPath: resolve(ROOT, "custom-compliance-results.json"),
    orgChecklistPath: undefined as string | undefined,
    scanOnly: false,
    failOnFindings: false,
    model: "composer-2.5",
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--scan-dir" && argv[i + 1]) args.scanDir = resolve(argv[++i]);
    else if (arg === "--findings" && argv[i + 1])
      args.findingsPath = resolve(argv[++i]);
    else if (arg === "--report" && argv[i + 1])
      args.reportPath = resolve(argv[++i]);
    else if (arg === "--custom-results" && argv[i + 1])
      args.customResultsPath = resolve(argv[++i]);
    else if (arg === "--org-checklist" && argv[i + 1])
      args.orgChecklistPath = resolve(argv[++i]);
    else if (arg === "--scan-only") args.scanOnly = true;
    else if (arg === "--fail-on-findings") args.failOnFindings = true;
    else if (arg === "--model" && argv[i + 1]) args.model = argv[++i];
    else if (arg === "--help") {
      console.log(`Usage: npm run review -- [options]

Options:
  --scan-dir <path>   Terraform directory (default: fixtures/terraform)
  --findings <path>   Checkov JSON output (default: findings.json)
  --report <path>     Markdown report output (default: report.md)
  --custom-results <path>
                      Custom compliance JSON output (default: custom-compliance-results.json)
  --org-checklist <path>
                      Shared org custom compliance checklist
  --scan-only         Skip Cursor agent; write scan summary only
  --fail-on-findings  Exit 2 when any findings exist (CI gate mode)
  --model <id>        Cursor model id (default: composer-2.5)
`);
      process.exit(0);
    }
  }

  return args;
}

async function writeScanOnlyReport(
  reportPath: string,
  findings: ReturnType<typeof enrichFindings>,
  customCompliance: CustomComplianceResults,
) {
  const lines = [
    "# Terraform NIST Scan Summary (scan-only)",
    "",
    `Findings: **${findings.length}**`,
    "",
    "| Severity | Check | Resource | NIST | File |",
    "| --- | --- | --- | --- | --- |",
  ];

  for (const f of findings) {
    lines.push(
      `| ${f.severity} | ${f.checkId} | ${f.resource} | ${f.nistControls.join(", ") || "UNMAPPED"} | ${f.filePath}:${f.lineRange[0]} |`,
    );
  }

  if (customCompliance.stats.configured > 0) {
    lines.push(
      "",
      "## Custom Compliance (not assessed)",
      "",
      `Configured rules: **${customCompliance.stats.configured}**`,
      "",
      "| Rule | Source | Controls | Status |",
      "| --- | --- | --- | --- |",
    );

    for (const assessment of customCompliance.assessments) {
      const source =
        assessment.ruleSource === "local" && assessment.overriddenRuleSource
          ? "local override"
          : assessment.ruleSource;
      lines.push(
        `| ${assessment.title} | ${source} | ${assessment.controls.join(", ") || "-"} | ${assessment.status} |`,
      );
    }
  }

  lines.push(
    "",
    "_Set `CURSOR_API_KEY` and re-run without `--scan-only` for full NIST control intent analysis._",
  );

  await writeFile(reportPath, lines.join("\n"), "utf8");
}

function extractJsonObject(value: string): unknown {
  const trimmed = value.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    // Continue with common agent wrapper formats below.
  }

  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenced) return JSON.parse(fenced[1].trim());

  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start >= 0 && end > start) {
    return JSON.parse(trimmed.slice(start, end + 1));
  }

  throw new Error("Cursor agent did not return a JSON object.");
}

async function assessCustomCompliance(
  prompt: string,
  model: string,
): Promise<unknown> {
  const result = await Agent.prompt(prompt, {
    apiKey: process.env.CURSOR_API_KEY,
    model: { id: model },
    local: {
      cwd: ROOT,
      settingSources: [],
    },
  });

  if (result.status === "error") {
    throw new Error(
      `Custom compliance agent run failed: ${result.id ?? "unknown run"}`,
    );
  }

  const output =
    typeof result.result === "string"
      ? result.result
      : JSON.stringify(result.result, null, 2);
  return extractJsonObject(output);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const profile = await loadControlBotProfile();
  const checklist = await loadCustomComplianceChecklist({
    orgPath: args.orgChecklistPath,
  });
  const mappings = await loadNistMappings();
  const checks = await loadCheckovFindings(args.findingsPath);
  const findings = enrichFindings(checks, mappings, profile, args.scanDir);
  let customCompliance = buildUnassessedCustomComplianceResults(checklist);

  console.log(
    `Loaded ${findings.length} failed check(s) from ${args.findingsPath}`,
  );
  if (checklist.rules.length > 0) {
    console.log(
      `Loaded ${checklist.rules.length} effective custom compliance rule(s) from ${checklist.sources.length} source(s)`,
    );
  }

  if (args.scanOnly || !process.env.CURSOR_API_KEY) {
    if (!process.env.CURSOR_API_KEY) {
      console.warn("CURSOR_API_KEY not set — running scan-only mode.");
    }
    await writeFile(
      args.customResultsPath,
      JSON.stringify(customCompliance, null, 2),
      "utf8",
    );
    await writeScanOnlyReport(args.reportPath, findings, customCompliance);
    console.log(`Wrote ${args.reportPath}`);
    console.log(`Wrote ${args.customResultsPath}`);
    const shouldFail =
      args.failOnFindings &&
      findings.some((f) => f.severity === "HIGH" || f.severity === "CRITICAL");
    process.exit(shouldFail ? 2 : 0);
  }

  try {
    if (checklist.rules.length > 0) {
      const assessmentPayload = await assessCustomCompliance(
        buildCustomComplianceAssessmentPrompt(checklist, args.scanDir, profile),
        args.model,
      );
      const rawAssessments =
        typeof assessmentPayload === "object" &&
        assessmentPayload !== null &&
        "assessments" in assessmentPayload &&
        Array.isArray(
          (assessmentPayload as { assessments?: unknown }).assessments,
        )
          ? ((assessmentPayload as { assessments: unknown[] }).assessments)
          : [];
      customCompliance = buildCustomComplianceResults(checklist, rawAssessments);
    }

    await writeFile(
      args.customResultsPath,
      JSON.stringify(customCompliance, null, 2),
      "utf8",
    );

    const prompt = buildAgentPrompt(
      findings,
      args.scanDir,
      profile,
      checklist,
      customCompliance,
    );

    const result = await Agent.prompt(prompt, {
      apiKey: process.env.CURSOR_API_KEY,
      model: { id: args.model },
      local: {
        cwd: ROOT,
        settingSources: [],
      },
    });

    if (result.status === "error") {
      console.error(`Agent run failed: ${result.id ?? "unknown run"}`);
      process.exit(2);
    }

    const report =
      typeof result.result === "string"
        ? result.result
        : JSON.stringify(result.result, null, 2);

    await writeFile(args.reportPath, report, "utf8");
    console.log(`Wrote ${args.reportPath}`);
    console.log(`Wrote ${args.customResultsPath}`);
    process.exit(0);
  } catch (err) {
    if (err instanceof CursorAgentError) {
      const agentError = err as Error & { isRetryable?: boolean };
      console.error(
        `Startup failed: ${agentError.message} (retryable=${agentError.isRetryable})`,
      );
      process.exit(1);
    }
    throw err;
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
