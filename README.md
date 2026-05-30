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
Custom compliance checks are a separate lane: they are Qodo-style checklist items assessed by the Cursor agent and reported separately from deterministic Checkov/NIST findings.

## Quick start

```bash
npm install
pip install checkov

npm run scan
npm run review -- --scan-only
npm run controlbot
npm run poam

cat review-payload.json   # Bugbot-style inline comment payload
cat poam-seeds.md         # POA&M seed summary
```

Full agent report (optional):

```bash
export CURSOR_API_KEY="cursor_..."
npm run review
```

Custom compliance results are written to `custom-compliance-results.json` when `npm run review` runs. In scan-only mode, checklist rules are marked `UNKNOWN` and do not block.

## GitHub Actions

1. Add **`CURSOR_API_KEY`** secret (optional — inline bot works without it)
2. PRs touching `*.tf` trigger [`.github/workflows/controlbot.yml`](.github/workflows/controlbot.yml)
3. ControlBot updates one sticky PR summary, applies triage labels, posts inline NIST comments, and fails the check on blocking findings

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

Qodo-style custom compliance checklist: [`.controlbot/checklist.yaml`](.controlbot/checklist.yaml)

```yaml
pr_compliances:
  - id: resource-ownership-tags
    title: "Resource Ownership Tags"
    compliance_label: true
    objective: "Terraform-managed AWS resources must identify an owner and data classification."
    success_criteria: "Resources include owner and data_classification tags or inherit them from a module/default tag configuration."
    failure_criteria: "Resources are declared without ownership or data-classification tags and no inherited tagging mechanism is visible."
    controls: [CM-8, PL-2]
    severity: MEDIUM
```

`compliance_label: true` means a Cursor-agent `FAIL` is treated as a blocking custom compliance violation in the PR review payload. These results appear under `stats.custom_compliance` and are not merged into Checkov/NIST inline findings.

Hierarchical checklist loading:

1. Shared org checklist loads first from `.controlbot/org/checklist.yaml` by default.
2. Set `CONTROLBOT_ORG_CHECKLIST=/path/to/checklist.yaml` or pass `--org-checklist <path>` to use an external org baseline.
3. Local `.controlbot/checklist.yaml` loads second.
4. A local rule with the same `id` overrides the org rule.
5. A local rule with the same `id` and `enabled: false` disables the inherited org rule.

The effective checklist preserves provenance in `custom-compliance-results.json` and `review-payload.json`: each assessment records whether the active rule came from `org`, `local`, or a `local override`.

## PR labels and sticky summary

ControlBot writes a single persistent PR summary comment keyed by `<!-- controlbot-summary -->`, so reruns update the same summary instead of adding a new top-level comment each time.

Managed labels are synced from the current review payload:

| Label | Meaning |
|-------|---------|
| `controlbot:blocking` | Merge-blocking deterministic or custom compliance findings exist |
| `controlbot:custom-compliance` | At least one custom compliance checklist item failed |
| `controlbot:family-SC`, `controlbot:family-AC`, etc. | Findings affect the named NIST control family |
| `effort:1` ... `effort:5` | Deterministic remediation effort estimate based on severity, volume, and custom blockers |

Stale `controlbot:*` and `effort:*` labels are removed on each PR run before current labels are applied.

## POA&M seeds

`npm run poam` writes:

- `poam-seeds.json` — structured `controlbot.poam-seeds.v1` data for downstream GRC tooling
- `poam-seeds.md` — reviewer-friendly summary table and remediation detail

Seeds are generated from every active deterministic Checkov/NIST finding plus every failed custom compliance assessment. Each seed preserves controls, severity, evidence path, recommended remediation, source/provenance, owner placeholder, open status, due date, and merge-blocking status.

Due dates are seeded by severity: CRITICAL 15 days, HIGH 30 days, MEDIUM 60 days, LOW 90 days. Treat them as starting points for an actual POA&M workflow.

## Example Terraform

[`fixtures/terraform/main.tf`](fixtures/terraform/main.tf) — intentionally weak config for demos.

## Commands

| Command | Purpose |
|---------|---------|
| `npm run scan` | Checkov → `findings.json` |
| `npm run review` | Agent or scan-only → `report.md` + `custom-compliance-results.json` |
| `npm run controlbot` | Build PR review payload, exit 2 if blocking |
| `npm run poam` | Build `poam-seeds.json` + `poam-seeds.md` |
| `npm run post-review` | Post to GitHub (CI) |
| `npm test` | Regression tests for checklist merge, labels, and POA&M seeds |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Pass |
| `1` | Tooling error |
| `2` | Blocking control or custom compliance findings |

## License

MIT
