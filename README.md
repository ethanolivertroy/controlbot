# Terraform NIST Reviewer + Compliance Bot

Scan Terraform with [Checkov](https://www.checkov.io/), map findings to **NIST SP 800-53 Rev 5** controls, and review PRs **Bugbot-style** with inline comments and merge gates.

## Compliance Bot (Bugbot parity)

On every PR that touches `*.tf`:

1. **Scans** only the changed Terraform (via Checkov)
2. **Maps** findings → NIST 800-53 controls
3. **Posts inline review comments** on the exact lines (like Cursor Bugbot)
4. **Requests changes** when blocking severity findings exist
5. **Fails the check** so the PR can't merge until resolved

Configure behavior in [`.compliance/profile.yaml`](.compliance/profile.yaml):

```yaml
baseline: fedramp-moderate
inherited_controls: [PE-1, PE-2]   # skip — CSP inherited
block_on_severity: [HIGH, CRITICAL]
inline_comments: true
```

## Architecture

```text
PR diff (*.tf)
  → Checkov scan
  → NIST mapping (mappings/checkov-to-nist.yaml)
  → Compliance Bot (inline comment payload)
  → GitHub PR review (REQUEST_CHANGES + line comments)
  → Optional: Cursor SDK agent (full report in artifact)
```

## Quick start (local)

```bash
npm install
pip install checkov

npm run scan
npm run review -- --scan-only
npm run compliance-bot

# Inspect Bugbot-style payload
cat review-payload.json | head -80
```

Full agent report:

```bash
export CURSOR_API_KEY="cursor_..."
npm run review
```

## Example Terraform

[`fixtures/terraform/main.tf`](fixtures/terraform/main.tf) — intentionally weak config (open SG, unencrypted RDS, etc.) for demo scans.

## GitHub setup

1. Push to GitHub
2. Add secret **`CURSOR_API_KEY`** (optional — enables full agent report; inline bot works without it)
3. Open a PR that changes `fixtures/terraform/main.tf`
4. Compliance Bot posts inline NIST comments and blocks merge on HIGH findings

Workflow: [`.github/workflows/compliance-bot.yml`](.github/workflows/compliance-bot.yml)

## Scripts

| Command | Purpose |
|---------|---------|
| `npm run scan` | Checkov → `findings.json` |
| `npm run review` | Agent or scan-only → `report.md` |
| `npm run compliance-bot` | Build `review-payload.json`, exit 2 if blocking |
| `npm run post-review` | Post payload to GitHub (CI only) |

Simulate a PR review locally:

```bash
npm run scan
npm run compliance-bot -- --changed-file fixtures/terraform/main.tf
```

## Customize

| File | Purpose |
|------|---------|
| `.compliance/profile.yaml` | Baseline, inheritance, merge gate severity |
| `mappings/checkov-to-nist.yaml` | Checkov rule → NIST control + severity |
| `fixtures/terraform/` | Demo Terraform |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Pass |
| `1` | Tooling error |
| `2` | Blocking compliance findings (`compliance-bot`) |

## License

MIT
