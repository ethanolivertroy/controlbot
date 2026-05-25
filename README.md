# ControlBot

**Bugbot for compliance on infrastructure code.**

ControlBot reviews Terraform PRs like Cursor Bugbot reviews code — inline comments on the exact lines, NIST 800-53 control mapping, control intent, and a merge gate when findings block your baseline.

Built on [Checkov](https://www.checkov.io/) (deterministic facts) + [Cursor SDK](https://cursor.com/docs/sdk) (assessor-grade narratives).

> **Today:** IaC → controls → PR reviews  
> **Tomorrow:** SSP narratives, POA&M seeds, risk scoring, audit packages — one bot, growing into full GRC

## Demo

**Repo:** https://github.com/ethanolivertroy/controlbot  
**Sample PR:** https://github.com/ethanolivertroy/controlbot/pull/1

## How it works

```text
PR with Terraform
  → Checkov (deterministic scan)
  → NIST 800-53 mapping
  → ControlBot (inline PR comments + merge gate)
  → Optional: Cursor agent (full report artifact)
```

The agent **never invents findings** — it enriches Checkov output with control intent and remediation language.

## Quick start

```bash
npm install
pip install checkov

npm run scan
npm run review -- --scan-only
npm run controlbot

cat review-payload.json   # Bugbot-style inline comment payload
```

Full agent report (optional):

```bash
export CURSOR_API_KEY="cursor_..."
npm run review
```

## GitHub Actions

1. Add **`CURSOR_API_KEY`** secret (optional — inline bot works without it)
2. PRs touching `*.tf` trigger [`.github/workflows/controlbot.yml`](.github/workflows/controlbot.yml)
3. ControlBot posts inline NIST comments and fails the check on blocking findings

## Configure

[`.controlbot/profile.yaml`](.controlbot/profile.yaml):

```yaml
baseline: fedramp-moderate
inherited_controls: [PE-1, PE-2]   # CSP-inherited — skip
block_on_severity: [HIGH, CRITICAL]
inline_comments: true
bot_name: ControlBot
```

Extend [`mappings/checkov-to-nist.yaml`](mappings/checkov-to-nist.yaml) for your rule → control mappings.

## Example Terraform

[`fixtures/terraform/main.tf`](fixtures/terraform/main.tf) — intentionally weak config for demos.

## Commands

| Command | Purpose |
|---------|---------|
| `npm run scan` | Checkov → `findings.json` |
| `npm run review` | Agent or scan-only → `report.md` |
| `npm run controlbot` | Build PR review payload, exit 2 if blocking |
| `npm run post-review` | Post to GitHub (CI) |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Pass |
| `1` | Tooling error |
| `2` | Blocking control findings |

## License

MIT
