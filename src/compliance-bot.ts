import { writeFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildReviewPayload,
  enrichFindings,
  filterFindingsForPr,
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
    payloadPath: resolve(ROOT, "review-payload.json"),
    changedFiles: [] as string[],
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--scan-dir" && argv[i + 1]) args.scanDir = resolve(argv[++i]);
    else if (arg === "--findings" && argv[i + 1])
      args.findingsPath = resolve(argv[++i]);
    else if (arg === "--payload" && argv[i + 1])
      args.payloadPath = resolve(argv[++i]);
    else if (arg === "--changed-file" && argv[i + 1])
      args.changedFiles.push(argv[++i]);
    else if (arg === "--changed-files" && argv[i + 1]) {
      const list = argv[++i].split(",").map((f) => f.trim()).filter(Boolean);
      args.changedFiles.push(...list);
    } else if (arg === "--help") {
      console.log(`Usage: npm run compliance-bot -- [options]

Build Bugbot-style PR review payload with inline NIST comments.

Options:
  --scan-dir <path>        Terraform scan root
  --findings <path>        Checkov JSON output
  --payload <path>         Output review payload JSON
  --changed-file <path>    Limit to PR-changed file (repeatable)
  --changed-files <csv>    Comma-separated changed files
`);
      process.exit(0);
    }
  }

  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const profile = await loadComplianceProfile();
  const mappings = await loadNistMappings();
  const checks = await loadCheckovFindings(args.findingsPath);

  let findings = enrichFindings(checks, mappings, profile, args.scanDir);

  if (args.changedFiles.length > 0) {
    findings = filterFindingsForPr(findings, args.changedFiles);
    console.log(
      `Filtered to ${findings.length} finding(s) on ${args.changedFiles.length} changed file(s)`,
    );
  }

  const payload = buildReviewPayload(findings, profile);
  await writeFile(args.payloadPath, JSON.stringify(payload, null, 2), "utf8");

  console.log(`Review event: ${payload.event}`);
  console.log(
    `Findings: ${payload.stats.total} total, ${payload.stats.blocking} blocking, ${payload.stats.inline_posted} inline comment(s)`,
  );
  console.log(`Wrote ${args.payloadPath}`);

  process.exit(payload.event === "REQUEST_CHANGES" ? 2 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
