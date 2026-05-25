# Terraform NIST Reviewer

Scan Terraform with [Checkov](https://www.checkov.io/), map findings to **NIST SP 800-53 Rev 5** controls, and enrich the report with a **Cursor SDK** agent for control intent and remediation guidance.

## How it works

```text
Terraform (.tf)
    → Checkov (deterministic findings)
    → NIST mapping table (checkov-to-nist.yaml)
    → Cursor SDK agent (control intent + HCL fixes)
    → report.md (+ PR comment in CI)
```

The agent **does not invent findings** — it only analyzes Checkov output and reads Terraform for context.

## Quick start (local)

```bash
cd terraform-nist-reviewer
npm install
pip install checkov   # if not already installed

# 1. Scan sample fixture (intentionally weak config)
npm run scan

# 2a. Scan-only summary (no API key needed)
npm run review -- --scan-only

# 2b. Full NIST report (requires Cursor API key)
export CURSOR_API_KEY="cursor_..."
npm run review
cat report.md
```

Get an API key from [Cursor Dashboard → Integrations](https://cursor.com/dashboard/integrations).

## GitHub Actions

1. Push this repo to GitHub.
2. Add repository secret: **`CURSOR_API_KEY`**
3. Workflow runs on:
   - pushes to `main` (fixture/mapping changes)
   - PRs that touch `*.tf`
   - manual `workflow_dispatch`

Without the secret, CI still runs Checkov and uploads a **scan-only** summary.

Artifacts: `findings.json`, `report.md`. PRs get a comment with the report.

## Customize

| File | Purpose |
|------|---------|
| `mappings/checkov-to-nist.yaml` | Map Checkov `check_id` → NIST controls + intent |
| `fixtures/terraform/` | Demo Terraform with known misconfigs |
| `src/review.ts` | CLI — scan enrichment + Cursor agent |
| `.github/workflows/iac-nist.yml` | CI pipeline |

Scan a different directory:

```bash
npm run scan -- path/to/terraform findings.json
npm run review -- --scan-dir path/to/terraform
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | SDK startup failure (auth, config, network) |
| `2` | Run failed or HIGH severity findings (scan-only mode) |

## License

MIT
