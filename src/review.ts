import { writeFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Agent, CursorAgentError } from "@cursor/sdk";
import {
  buildAgentPrompt,
  enrichFindings,
  loadCheckovFindings,
  loadNistMappings,
} from "./lib.js";
import { loadComplianceProfile } from "./profile.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

function parseArgs(argv: string[]) {
  const args = {
    scanDir: resolve(ROOT, "fixtures/terraform"),
    findingsPath: resolve(ROOT, "findings.json"),
    reportPath: resolve(ROOT, "report.md"),
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
    else if (arg === "--scan-only") args.scanOnly = true;
    else if (arg === "--fail-on-findings") args.failOnFindings = true;
    else if (arg === "--model" && argv[i + 1]) args.model = argv[++i];
    else if (arg === "--help") {
      console.log(`Usage: npm run review -- [options]

Options:
  --scan-dir <path>   Terraform directory (default: fixtures/terraform)
  --findings <path>   Checkov JSON output (default: findings.json)
  --report <path>     Markdown report output (default: report.md)
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

  lines.push(
    "",
    "_Set `CURSOR_API_KEY` and re-run without `--scan-only` for full NIST control intent analysis._",
  );

  await writeFile(reportPath, lines.join("\n"), "utf8");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const profile = await loadComplianceProfile();
  const mappings = await loadNistMappings();
  const checks = await loadCheckovFindings(args.findingsPath);
  const findings = enrichFindings(checks, mappings, profile, args.scanDir);

  console.log(`Loaded ${findings.length} failed check(s) from ${args.findingsPath}`);

  if (args.scanOnly || !process.env.CURSOR_API_KEY) {
    if (!process.env.CURSOR_API_KEY) {
      console.warn("CURSOR_API_KEY not set — running scan-only mode.");
    }
    await writeScanOnlyReport(args.reportPath, findings);
    console.log(`Wrote ${args.reportPath}`);
    const shouldFail =
      args.failOnFindings &&
      findings.some((f) => f.severity === "HIGH" || f.severity === "CRITICAL");
    process.exit(shouldFail ? 2 : 0);
  }

  const prompt = buildAgentPrompt(findings, args.scanDir, profile);

  try {
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
    process.exit(0);
  } catch (err) {
    if (err instanceof CursorAgentError) {
      console.error(
        `Startup failed: ${err.message} (retryable=${err.isRetryable})`,
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
