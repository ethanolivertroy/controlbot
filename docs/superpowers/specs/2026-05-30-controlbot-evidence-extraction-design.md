# ControlBot Evidence Extraction Layer Design

## Objective

Add a ControlBot evidence extraction layer that emits normalized repo evidence
facts from Terraform, GitHub workflow files, package manifests, CODEOWNERS, and
local policy files. These facts map to NIST/FedRAMP-ready summaries without
being mixed into Checkov findings.

## Current State

ControlBot currently has two review lanes:

- Deterministic scanner lane: Checkov writes `findings.json`, ControlBot maps
  failed checks to NIST controls, then emits inline review comments,
  `review-payload.json`, and POA&M seeds.
- Custom compliance lane: `.controlbot/checklist.yaml` and optional org
  checklist files produce `custom-compliance-results.json`, which remains
  separate from deterministic Checkov findings.

The evidence layer becomes a third lane. It extracts compliance-relevant facts
from repo files, including positive and missing evidence, but it does not create
Checkov findings and does not affect merge blocking in v1.

## Design Principles

- Evidence facts are not scanner findings.
- Evidence facts can be positive, neutral, missing, or warning-level facts.
- Evidence extraction is deterministic in v1.
- Evidence summaries are useful for PR review, SSP preparation, and audit
  packages.
- Evidence output must preserve repo-relative provenance.
- V1 is report-only and non-blocking.

## Evidence Fact Schema

`evidence-facts.json` uses schema `controlbot.evidence-facts.v1`.

Each fact has:

- `id`: stable identifier derived from source, subject, and path.
- `type`: normalized evidence category.
- `source`: extractor source, such as `terraform`, `github_workflow`,
  `package_manifest`, `codeowners`, or `local_policy`.
- `path`: repo-relative evidence path.
- `line`: optional source line number.
- `subject`: resource, workflow, file, or policy object the fact describes.
- `summary`: concise human-readable fact.
- `controls`: mapped NIST/FedRAMP control IDs.
- `confidence`: `deterministic` in v1.
- `disposition`: `observed`, `missing`, `not_applicable`, or `warning`.
- `metadata`: small structured details for downstream consumers.

Example:

```json
{
  "id": "terraform.aws_security_group.app.public_ingress",
  "type": "network_exposure",
  "source": "terraform",
  "path": "fixtures/terraform/main.tf",
  "line": 24,
  "subject": "aws_security_group.app",
  "summary": "Security group allows SSH ingress from 0.0.0.0/0.",
  "controls": ["SC-7", "AC-4"],
  "confidence": "deterministic",
  "disposition": "warning",
  "metadata": {
    "from_port": 22,
    "to_port": 22,
    "cidr_blocks": ["0.0.0.0/0"]
  }
}
```

The document summary contains total facts, counts by source, counts by
disposition, and counts by control family.

## Extractors

### Terraform Extractor

Inputs:

- `*.tf` files under the scan directory.

V1 facts:

- Provider regions.
- Resource inventory by Terraform type.
- AWS resource tags when a tags block is visible.
- Public ingress in security group ingress blocks.
- Public database exposure when `publicly_accessible = true`.
- Encryption attributes such as `storage_encrypted` when visible.

Controls:

- Regions and configuration: `CM-6`, `SC-7`.
- Resource inventory and tags: `CM-8`, `PL-2`.
- Public ingress and public data stores: `SC-7`, `AC-4`.
- Encryption attributes: `SC-13`, `SC-28`.

Implementation note:

V1 may use a conservative text/token parser instead of a full Terraform HCL
parser. It should extract only facts it can identify deterministically. If a
resource shape is too complex, skip it rather than guessing.

### GitHub Workflow Extractor

Inputs:

- `.github/workflows/*.yml`
- `.github/workflows/*.yaml`

V1 facts:

- Workflow names and trigger types.
- Jobs present.
- Top-level and job-level permissions.
- Test/typecheck command steps.
- Artifact upload steps.
- Pull request trigger coverage.

Controls:

- Change controls and CI evidence: `CM-3`, `CM-5`, `SA-10`.
- Artifact and audit evidence: `AU-6`, `AU-12`.

### Package Manifest Extractor

Inputs:

- `package.json`
- `package-lock.json`

V1 facts:

- Package manager and lockfile presence.
- Runtime dependency count.
- Dev dependency count.
- Security-relevant scripts such as `test`, `typecheck`, `scan`, or `review`.
- Node engine constraints if declared.

Controls:

- Dependency and supply-chain evidence: `SA-12`, `CM-6`, `SI-2`.
- Test and build scripts: `SA-10`, `CM-3`.

### CODEOWNERS Extractor

Inputs:

- `CODEOWNERS`
- `.github/CODEOWNERS`
- `docs/CODEOWNERS`

V1 facts:

- CODEOWNERS present or missing.
- Ownership rule count.
- Broad ownership patterns.

Controls:

- Change ownership and authorization: `CM-3`, `CM-5`, `AC-6`.

If no CODEOWNERS file exists, emit one `missing` fact. This is non-blocking in
v1.

### Local Policy Extractor

Inputs:

- `.controlbot/profile.yaml`
- `.controlbot/checklist.yaml`
- `.controlbot/org/checklist.yaml`
- `mappings/checkov-to-nist.yaml`

V1 facts:

- ControlBot profile present.
- Baseline selected.
- Inherited controls configured.
- Local checklist present and rule count.
- Org checklist present and rule count.
- Checkov-to-NIST mapping present and mapping count.

Controls:

- Compliance planning and boundary evidence: `PL-2`, `CA-2`, `CM-6`.
- Custom policy and review evidence: `CM-3`, `RA-5`.

## NIST/FedRAMP Mapping

V1 uses a small built-in mapping table in the evidence module. If this grows,
move it to `mappings/evidence-to-nist.yaml`.

Mapping is fact-type based, not finding based. For example:

- `resource_inventory` -> `CM-8`
- `ownership_metadata` -> `CM-8`, `PL-2`
- `network_exposure` -> `SC-7`, `AC-4`
- `encryption_configuration` -> `SC-13`, `SC-28`
- `ci_control` -> `CM-3`, `SA-10`
- `dependency_manifest` -> `SA-12`, `SI-2`
- `local_policy` -> `PL-2`, `CM-6`

## CLI and Artifacts

Add:

- `src/evidence.ts`
- `npm run evidence`
- `evidence-facts.json`

`npm run evidence` writes `evidence-facts.json` and prints summary counts.

Update:

- `npm run review` loads or generates evidence facts and includes an evidence
  section in scan-only and agent prompts.
- `npm run controlbot` loads evidence facts and includes an evidence summary in
  `review-payload.json`.
- GitHub Actions uploads `evidence-facts.json` in `controlbot-report`.
- `.gitignore` excludes generated `evidence-facts.json`.

## Review Payload Integration

Extend `ReviewPayload` with:

```ts
evidence?: {
  schema: "controlbot.evidence-facts.v1";
  summary: {
    total: number;
    observed: number;
    missing: number;
    warnings: number;
    by_source: Record<string, number>;
    by_control_family: Record<string, number>;
  };
  facts: EvidenceFact[];
};
```

The sticky PR summary gets a short "Evidence" section:

- total facts
- missing facts
- warning facts
- top control families represented

No evidence facts are posted as inline comments in v1.

## Report Integration

`report.md` gets a separate "Evidence Facts" section. The section lists source
coverage, missing evidence, warning facts, and representative observed facts.

The Cursor agent prompt receives evidence facts as a separate JSON block with an
instruction to treat them as evidence, not as scanner findings.

## POA&M Integration

V1 does not create POA&M seeds from evidence facts. POA&M seeds remain based on
active deterministic Checkov findings and failed custom compliance assessments.

Rationale: evidence facts can be positive or informational. Creating POA&M
items from them would blur the distinction between evidence and findings. A
future policy layer can choose which evidence gaps become POA&M items.

## Error Handling

- Missing optional source classes produce `missing` or `not_applicable` facts,
  not process failures.
- Invalid YAML or JSON in expected source files should produce a warning fact
  and continue when possible.
- The CLI should fail only when it cannot write the evidence artifact or when an
  unexpected runtime error prevents deterministic extraction.

## Testing

Add tests for:

- Terraform evidence extraction from `fixtures/terraform/main.tf`.
- Workflow evidence extraction from `.github/workflows/controlbot.yml`.
- Package manifest evidence from `package.json` and `package-lock.json`.
- Missing CODEOWNERS emits a non-blocking `missing` fact.
- Local policy facts cover profile, checklist, org checklist, and mapping file.
- Review payload includes evidence summary without changing Checkov finding
  stats.
- `npm run evidence` writes `evidence-facts.json`.

## Non-Goals

- No merge blocking from evidence facts in v1.
- No new inline comments from evidence facts in v1.
- No evidence facts mixed into `findings.json` or `EnrichedFinding`.
- No external GitHub API checks for branch protection in v1.
- No LLM-only evidence conclusions in v1.

## Completion Criteria

- `npm run evidence` writes a valid `evidence-facts.json`.
- The artifact includes Terraform, GitHub workflow, package manifest,
  CODEOWNERS, and local policy facts.
- Missing CODEOWNERS is represented as a non-blocking evidence fact.
- `review-payload.json` includes an evidence summary.
- `report.md` includes an evidence section.
- Existing Checkov stats and custom compliance stats remain unchanged by
  evidence facts.
- GitHub Actions uploads `evidence-facts.json`.
- Tests and typecheck pass.
