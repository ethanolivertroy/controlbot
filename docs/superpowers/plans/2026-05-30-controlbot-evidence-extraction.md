# ControlBot Evidence Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a non-blocking ControlBot evidence extraction lane that emits normalized repo evidence facts and maps them to NIST/FedRAMP-ready summaries without mixing them into Checkov findings.

**Architecture:** Add `src/evidence.ts` as a focused evidence module with deterministic extractors for Terraform, GitHub workflows, package manifests, CODEOWNERS, and local policy files. Existing commands load the generated `evidence-facts.json` and render evidence summaries in `report.md` and `review-payload.json`, while Checkov finding stats and custom-compliance stats remain unchanged.

**Tech Stack:** TypeScript, Node.js `fs/promises`, `yaml`, Node test runner, existing ControlBot CLI scripts.

---

## File Structure

- Create `src/evidence.ts`: evidence types, mapping table, extractors, summary builder, CLI entrypoint.
- Create `tests/evidence.test.ts`: unit coverage for all extractors and evidence document summary behavior.
- Modify `src/lib.ts`: add `EvidenceDocument` support in `ReviewPayload`, render evidence summary in PR body, and pass evidence to agent prompt.
- Modify `src/review.ts`: load or generate evidence facts, write evidence facts before report generation, include evidence in scan-only report and agent prompt.
- Modify `src/controlbot.ts`: load evidence facts and include them in `review-payload.json` without changing Checkov stats.
- Modify `.github/workflows/controlbot.yml`: run evidence extraction and upload `evidence-facts.json`.
- Modify `package.json`: add `evidence` script.
- Modify `.gitignore`: ignore generated `evidence-facts.json`.
- Modify `README.md`: document the evidence lane and generated artifact.

---

### Task 1: Evidence Types, Summary, and Terraform Extractor

**Files:**
- Create: `src/evidence.ts`
- Create: `tests/evidence.test.ts`

- [ ] **Step 1: Write failing tests for Terraform facts and document summary**

Add to `tests/evidence.test.ts`:

```ts
import test from "node:test";
import assert from "node:assert/strict";
import {
  buildEvidenceDocument,
  extractTerraformEvidenceFromText,
} from "../src/evidence.js";

test("extracts Terraform evidence facts from provider and resources", () => {
  const terraform = `
provider "aws" {
  region = "us-gov-west-1"
}

resource "aws_security_group" "app" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "app_db" {
  publicly_accessible = true
  storage_encrypted   = false
}
`;

  const facts = extractTerraformEvidenceFromText(
    terraform,
    "fixtures/terraform/main.tf",
  );

  assert.ok(
    facts.some(
      (fact) =>
        fact.type === "configuration_baseline" &&
        fact.subject === "provider.aws" &&
        fact.metadata.region === "us-gov-west-1",
    ),
  );
  assert.ok(
    facts.some(
      (fact) =>
        fact.type === "network_exposure" &&
        fact.subject === "aws_security_group.app" &&
        fact.disposition === "warning" &&
        fact.controls.includes("SC-7") &&
        fact.controls.includes("AC-4"),
    ),
  );
  assert.ok(
    facts.some(
      (fact) =>
        fact.type === "encryption_configuration" &&
        fact.subject === "aws_db_instance.app_db" &&
        fact.disposition === "warning" &&
        fact.metadata.attribute === "storage_encrypted",
    ),
  );
});

test("builds evidence summary counts by source disposition and control family", () => {
  const document = buildEvidenceDocument([
    {
      id: "terraform.provider.aws.region",
      type: "configuration_baseline",
      source: "terraform",
      path: "fixtures/terraform/main.tf",
      line: 2,
      subject: "provider.aws",
      summary: "AWS provider region is us-gov-west-1.",
      controls: ["CM-6", "SC-7"],
      confidence: "deterministic",
      disposition: "observed",
      metadata: { region: "us-gov-west-1" },
    },
    {
      id: "codeowners.missing",
      type: "ownership_metadata",
      source: "codeowners",
      path: "CODEOWNERS",
      subject: "CODEOWNERS",
      summary: "No CODEOWNERS file was found.",
      controls: ["CM-3", "CM-5", "AC-6"],
      confidence: "deterministic",
      disposition: "missing",
      metadata: {},
    },
  ]);

  assert.equal(document.schema, "controlbot.evidence-facts.v1");
  assert.equal(document.summary.total, 2);
  assert.equal(document.summary.observed, 1);
  assert.equal(document.summary.missing, 1);
  assert.equal(document.summary.warnings, 0);
  assert.deepEqual(document.summary.by_source, {
    codeowners: 1,
    terraform: 1,
  });
  assert.deepEqual(document.summary.by_control_family, {
    AC: 1,
    CM: 2,
    SC: 1,
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
node --import tsx --test tests/evidence.test.ts
```

Expected: FAIL because `src/evidence.ts` does not exist.

- [ ] **Step 3: Implement evidence types, summary, and Terraform text extraction**

Create `src/evidence.ts`:

```ts
import { readdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

export type EvidenceSource =
  | "terraform"
  | "github_workflow"
  | "package_manifest"
  | "codeowners"
  | "local_policy";

export type EvidenceDisposition =
  | "observed"
  | "missing"
  | "not_applicable"
  | "warning";

export interface EvidenceFact {
  id: string;
  type: string;
  source: EvidenceSource;
  path: string;
  line?: number;
  subject: string;
  summary: string;
  controls: string[];
  confidence: "deterministic";
  disposition: EvidenceDisposition;
  metadata: Record<string, unknown>;
}

export interface EvidenceDocument {
  schema: "controlbot.evidence-facts.v1";
  generated_at: string;
  summary: {
    total: number;
    observed: number;
    missing: number;
    warnings: number;
    not_applicable: number;
    by_source: Record<string, number>;
    by_control_family: Record<string, number>;
  };
  facts: EvidenceFact[];
}

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function controlFamily(control: string): string {
  return control.split("-")[0] || "UNMAPPED";
}

function lineFor(text: string, index: number): number {
  return text.slice(0, Math.max(index, 0)).split("\n").length;
}

function fact(
  input: Omit<EvidenceFact, "confidence" | "metadata"> & {
    metadata?: Record<string, unknown>;
  },
): EvidenceFact {
  return {
    ...input,
    confidence: "deterministic",
    metadata: input.metadata ?? {},
  };
}

export function buildEvidenceDocument(
  facts: EvidenceFact[],
  generatedAt = new Date(),
): EvidenceDocument {
  const sorted = [...facts].sort((a, b) => a.id.localeCompare(b.id));
  const bySource: Record<string, number> = {};
  const byControlFamily: Record<string, number> = {};

  for (const item of sorted) {
    bySource[item.source] = (bySource[item.source] ?? 0) + 1;
    for (const control of item.controls) {
      const family = controlFamily(control);
      byControlFamily[family] = (byControlFamily[family] ?? 0) + 1;
    }
  }

  return {
    schema: "controlbot.evidence-facts.v1",
    generated_at: generatedAt.toISOString(),
    summary: {
      total: sorted.length,
      observed: sorted.filter((item) => item.disposition === "observed").length,
      missing: sorted.filter((item) => item.disposition === "missing").length,
      warnings: sorted.filter((item) => item.disposition === "warning").length,
      not_applicable: sorted.filter(
        (item) => item.disposition === "not_applicable",
      ).length,
      by_source: Object.fromEntries(Object.entries(bySource).sort()),
      by_control_family: Object.fromEntries(
        Object.entries(byControlFamily).sort(),
      ),
    },
    facts: sorted,
  };
}

function parseAttributes(block: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  for (const match of block.matchAll(/^\s*([A-Za-z0-9_]+)\s*=\s*(.+)$/gm)) {
    attrs[match[1]] = match[2].trim().replace(/^"|"$/g, "");
  }
  return attrs;
}

function blockEnd(text: string, openBraceIndex: number): number {
  let depth = 0;
  for (let i = openBraceIndex; i < text.length; i++) {
    if (text[i] === "{") depth += 1;
    if (text[i] === "}") {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
  }
  return text.length;
}

function terraformBlocks(
  text: string,
  kind: "provider" | "resource",
): Array<{
  type: string;
  name?: string;
  body: string;
  start: number;
}> {
  const pattern =
    kind === "provider"
      ? /provider\s+"([^"]+)"\s*\{/g
      : /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/g;
  const blocks = [];

  for (const match of text.matchAll(pattern)) {
    const open = (match.index ?? 0) + match[0].lastIndexOf("{");
    const end = blockEnd(text, open);
    blocks.push({
      type: match[1],
      name: kind === "resource" ? match[2] : undefined,
      body: text.slice(open + 1, end - 1),
      start: match.index ?? 0,
    });
  }

  return blocks;
}

export function extractTerraformEvidenceFromText(
  text: string,
  path: string,
): EvidenceFact[] {
  const facts: EvidenceFact[] = [];

  for (const provider of terraformBlocks(text, "provider")) {
    const attrs = parseAttributes(provider.body);
    if (provider.type === "aws" && attrs.region) {
      facts.push(
        fact({
          id: `terraform.provider.aws.region.${slug(attrs.region)}`,
          type: "configuration_baseline",
          source: "terraform",
          path,
          line: lineFor(text, provider.start),
          subject: "provider.aws",
          summary: `AWS provider region is ${attrs.region}.`,
          controls: ["CM-6", "SC-7"],
          disposition: "observed",
          metadata: { region: attrs.region },
        }),
      );
    }
  }

  for (const resource of terraformBlocks(text, "resource")) {
    const subject = `${resource.type}.${resource.name}`;
    const attrs = parseAttributes(resource.body);
    facts.push(
      fact({
        id: `terraform.${subject}.inventory`,
        type: "resource_inventory",
        source: "terraform",
        path,
        line: lineFor(text, resource.start),
        subject,
        summary: `Terraform declares ${subject}.`,
        controls: ["CM-8"],
        disposition: "observed",
        metadata: { resource_type: resource.type, resource_name: resource.name },
      }),
    );

    if (/tags\s*=\s*\{/.test(resource.body)) {
      facts.push(
        fact({
          id: `terraform.${subject}.tags.present`,
          type: "ownership_metadata",
          source: "terraform",
          path,
          line: lineFor(text, resource.start),
          subject,
          summary: `${subject} includes a tags block.`,
          controls: ["CM-8", "PL-2"],
          disposition: "observed",
          metadata: {},
        }),
      );
    }

    if (
      resource.type === "aws_security_group" &&
      /ingress\s*\{[\s\S]*cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"/.test(
        resource.body,
      )
    ) {
      const fromPort = resource.body.match(/from_port\s*=\s*(\d+)/)?.[1];
      const toPort = resource.body.match(/to_port\s*=\s*(\d+)/)?.[1];
      facts.push(
        fact({
          id: `terraform.${subject}.public_ingress`,
          type: "network_exposure",
          source: "terraform",
          path,
          line: lineFor(text, resource.start),
          subject,
          summary: `${subject} allows ingress from 0.0.0.0/0.`,
          controls: ["SC-7", "AC-4"],
          disposition: "warning",
          metadata: {
            from_port: fromPort ? Number(fromPort) : undefined,
            to_port: toPort ? Number(toPort) : undefined,
            cidr_blocks: ["0.0.0.0/0"],
          },
        }),
      );
    }

    if (attrs.publicly_accessible === "true") {
      facts.push(
        fact({
          id: `terraform.${subject}.publicly_accessible`,
          type: "network_exposure",
          source: "terraform",
          path,
          line: lineFor(text, resource.start),
          subject,
          summary: `${subject} is marked publicly accessible.`,
          controls: ["SC-7", "AC-4"],
          disposition: "warning",
          metadata: { attribute: "publicly_accessible", value: true },
        }),
      );
    }

    if (attrs.storage_encrypted === "false") {
      facts.push(
        fact({
          id: `terraform.${subject}.storage_encrypted.false`,
          type: "encryption_configuration",
          source: "terraform",
          path,
          line: lineFor(text, resource.start),
          subject,
          summary: `${subject} has storage_encrypted set to false.`,
          controls: ["SC-13", "SC-28"],
          disposition: "warning",
          metadata: { attribute: "storage_encrypted", value: false },
        }),
      );
    }
  }

  return facts;
}
```

- [ ] **Step 4: Run tests to verify Task 1 passes**

Run:

```bash
node --import tsx --test tests/evidence.test.ts
```

Expected: PASS for the two Task 1 tests.

- [ ] **Step 5: Commit Task 1**

Run:

```bash
git add src/evidence.ts tests/evidence.test.ts
git commit -m "Add evidence fact model and Terraform extractor"
```

---

### Task 2: Workflow, Package, CODEOWNERS, and Local Policy Extractors

**Files:**
- Modify: `src/evidence.ts`
- Modify: `tests/evidence.test.ts`

- [ ] **Step 1: Add failing tests for the remaining source classes**

Append to `tests/evidence.test.ts`:

```ts
import {
  extractCodeownersEvidence,
  extractLocalPolicyEvidence,
  extractPackageEvidence,
  extractWorkflowEvidenceFromText,
} from "../src/evidence.js";

test("extracts GitHub workflow controls from workflow YAML", () => {
  const workflow = `
name: ControlBot
on:
  pull_request:
permissions:
  contents: read
  pull-requests: write
jobs:
  controlbot:
    steps:
      - name: Typecheck and unit tests
        run: npm run typecheck && npm test
      - name: Upload report
        uses: actions/upload-artifact@v4
`;

  const facts = extractWorkflowEvidenceFromText(
    workflow,
    ".github/workflows/controlbot.yml",
  );

  assert.ok(facts.some((fact) => fact.type === "ci_control"));
  assert.ok(facts.some((fact) => fact.type === "artifact_retention"));
  assert.ok(
    facts.some(
      (fact) =>
        fact.subject === "ControlBot" &&
        fact.metadata.triggers instanceof Array &&
        fact.metadata.triggers.includes("pull_request"),
    ),
  );
});

test("extracts package manifest and lockfile evidence", () => {
  const facts = extractPackageEvidence(
    {
      name: "controlbot",
      scripts: {
        test: "node --test",
        typecheck: "tsc --noEmit",
      },
      dependencies: { yaml: "^2.8.1" },
      devDependencies: { typescript: "^5.8.3" },
      engines: { node: ">=20" },
    },
    true,
    "package.json",
  );

  assert.ok(
    facts.some(
      (fact) =>
        fact.type === "dependency_manifest" &&
        fact.disposition === "observed" &&
        fact.metadata.lockfile_present === true,
    ),
  );
  assert.ok(
    facts.some(
      (fact) =>
        fact.type === "ci_control" &&
        fact.subject === "package.json:scripts.test",
    ),
  );
});

test("emits missing CODEOWNERS fact when no CODEOWNERS file is present", () => {
  const facts = extractCodeownersEvidence(undefined);

  assert.deepEqual(facts.map((fact) => fact.disposition), ["missing"]);
  assert.equal(facts[0].source, "codeowners");
  assert.equal(facts[0].type, "ownership_metadata");
});

test("extracts local policy evidence from ControlBot config", () => {
  const facts = extractLocalPolicyEvidence({
    profile: {
      baseline: "fedramp-moderate",
      inherited_controls: ["PE-1", "PE-2"],
    },
    localChecklist: {
      pr_compliances: [{ id: "resource-ownership-tags" }],
    },
    orgChecklist: {
      pr_compliances: [{ id: "approved-aws-regions" }],
    },
    mappings: {
      CKV_AWS_1: { controls: ["SC-7"] },
      CKV_AWS_2: { controls: ["CM-6"] },
    },
  });

  assert.ok(
    facts.some(
      (fact) =>
        fact.type === "local_policy" &&
        fact.subject === ".controlbot/profile.yaml" &&
        fact.metadata.baseline === "fedramp-moderate",
    ),
  );
  assert.ok(
    facts.some(
      (fact) =>
        fact.subject === "mappings/checkov-to-nist.yaml" &&
        fact.metadata.mapping_count === 2,
    ),
  );
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
node --import tsx --test tests/evidence.test.ts
```

Expected: FAIL because the new extractor functions are not implemented.

- [ ] **Step 3: Implement the remaining extractor functions**

Add to `src/evidence.ts`:

```ts
export function extractWorkflowEvidenceFromText(
  text: string,
  path: string,
): EvidenceFact[] {
  const parsed = (parseYaml(text) ?? {}) as Record<string, unknown>;
  const workflowName =
    typeof parsed.name === "string" && parsed.name.trim()
      ? parsed.name.trim()
      : path;
  const onValue = parsed.on;
  const triggers = Array.isArray(onValue)
    ? onValue.filter((item): item is string => typeof item === "string")
    : typeof onValue === "string"
      ? [onValue]
      : onValue && typeof onValue === "object"
        ? Object.keys(onValue)
        : [];
  const jobs =
    parsed.jobs && typeof parsed.jobs === "object"
      ? (parsed.jobs as Record<string, unknown>)
      : {};
  const permissions =
    parsed.permissions && typeof parsed.permissions === "object"
      ? parsed.permissions
      : undefined;
  const facts: EvidenceFact[] = [
    fact({
      id: `workflow.${slug(workflowName)}.triggers`,
      type: "ci_control",
      source: "github_workflow",
      path,
      line: 1,
      subject: workflowName,
      summary: `${workflowName} workflow defines ${triggers.length} trigger(s).`,
      controls: ["CM-3", "SA-10"],
      disposition: triggers.length > 0 ? "observed" : "missing",
      metadata: { triggers },
    }),
    fact({
      id: `workflow.${slug(workflowName)}.jobs`,
      type: "ci_control",
      source: "github_workflow",
      path,
      line: 1,
      subject: workflowName,
      summary: `${workflowName} workflow defines ${Object.keys(jobs).length} job(s).`,
      controls: ["CM-3", "SA-10"],
      disposition: Object.keys(jobs).length > 0 ? "observed" : "missing",
      metadata: { jobs: Object.keys(jobs), permissions },
    }),
  ];

  if (/npm\s+run\s+typecheck|npm\s+test|npm\s+run\s+test/.test(text)) {
    facts.push(
      fact({
        id: `workflow.${slug(workflowName)}.tests`,
        type: "ci_control",
        source: "github_workflow",
        path,
        line: lineFor(text, text.search(/npm\s+run\s+typecheck|npm\s+test/)),
        subject: workflowName,
        summary: `${workflowName} runs typecheck or tests.`,
        controls: ["CM-3", "SA-10"],
        disposition: "observed",
        metadata: { command_pattern: "npm test/typecheck" },
      }),
    );
  }

  if (/actions\/upload-artifact@/.test(text)) {
    facts.push(
      fact({
        id: `workflow.${slug(workflowName)}.artifact-upload`,
        type: "artifact_retention",
        source: "github_workflow",
        path,
        line: lineFor(text, text.indexOf("actions/upload-artifact@")),
        subject: workflowName,
        summary: `${workflowName} uploads a review artifact.`,
        controls: ["AU-6", "AU-12"],
        disposition: "observed",
        metadata: { action: "actions/upload-artifact" },
      }),
    );
  }

  return facts;
}

export function extractPackageEvidence(
  packageJson: Record<string, unknown>,
  lockfilePresent: boolean,
  path = "package.json",
): EvidenceFact[] {
  const dependencies =
    packageJson.dependencies && typeof packageJson.dependencies === "object"
      ? Object.keys(packageJson.dependencies)
      : [];
  const devDependencies =
    packageJson.devDependencies &&
    typeof packageJson.devDependencies === "object"
      ? Object.keys(packageJson.devDependencies)
      : [];
  const scripts =
    packageJson.scripts && typeof packageJson.scripts === "object"
      ? (packageJson.scripts as Record<string, unknown>)
      : {};
  const facts: EvidenceFact[] = [
    fact({
      id: "package.package-json.dependency-manifest",
      type: "dependency_manifest",
      source: "package_manifest",
      path,
      subject: "package.json",
      summary: `package.json declares ${dependencies.length} runtime and ${devDependencies.length} development dependencies.`,
      controls: ["SA-12", "CM-6", "SI-2"],
      disposition: lockfilePresent ? "observed" : "warning",
      metadata: {
        dependency_count: dependencies.length,
        dev_dependency_count: devDependencies.length,
        lockfile_present: lockfilePresent,
        engines: packageJson.engines ?? {},
      },
    }),
  ];

  for (const scriptName of ["test", "typecheck", "scan", "review"]) {
    if (typeof scripts[scriptName] === "string") {
      facts.push(
        fact({
          id: `package.scripts.${scriptName}`,
          type: "ci_control",
          source: "package_manifest",
          path,
          subject: `package.json:scripts.${scriptName}`,
          summary: `package.json defines the ${scriptName} script.`,
          controls: ["CM-3", "SA-10"],
          disposition: "observed",
          metadata: { command: scripts[scriptName] },
        }),
      );
    }
  }

  return facts;
}

export function extractCodeownersEvidence(
  input:
    | {
        path: string;
        text: string;
      }
    | undefined,
): EvidenceFact[] {
  if (!input) {
    return [
      fact({
        id: "codeowners.missing",
        type: "ownership_metadata",
        source: "codeowners",
        path: "CODEOWNERS",
        subject: "CODEOWNERS",
        summary: "No CODEOWNERS file was found.",
        controls: ["CM-3", "CM-5", "AC-6"],
        disposition: "missing",
        metadata: {},
      }),
    ];
  }

  const rules = input.text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));

  return [
    fact({
      id: "codeowners.present",
      type: "ownership_metadata",
      source: "codeowners",
      path: input.path,
      subject: "CODEOWNERS",
      summary: `CODEOWNERS defines ${rules.length} ownership rule(s).`,
      controls: ["CM-3", "CM-5", "AC-6"],
      disposition: rules.length > 0 ? "observed" : "warning",
      metadata: { rule_count: rules.length },
    }),
  ];
}

export function extractLocalPolicyEvidence(input: {
  profile?: Record<string, unknown>;
  localChecklist?: Record<string, unknown>;
  orgChecklist?: Record<string, unknown>;
  mappings?: Record<string, unknown>;
}): EvidenceFact[] {
  const facts: EvidenceFact[] = [];
  const inherited = Array.isArray(input.profile?.inherited_controls)
    ? input.profile?.inherited_controls
    : [];
  if (input.profile) {
    facts.push(
      fact({
        id: "local-policy.profile",
        type: "local_policy",
        source: "local_policy",
        path: ".controlbot/profile.yaml",
        subject: ".controlbot/profile.yaml",
        summary: `ControlBot profile selects ${String(input.profile.baseline ?? "unknown")} baseline.`,
        controls: ["PL-2", "CA-2", "CM-6"],
        disposition: "observed",
        metadata: {
          baseline: input.profile.baseline,
          inherited_controls: inherited,
        },
      }),
    );
  }

  for (const [key, path] of [
    ["localChecklist", ".controlbot/checklist.yaml"],
    ["orgChecklist", ".controlbot/org/checklist.yaml"],
  ] as const) {
    const checklist = input[key];
    const rules = Array.isArray(checklist?.pr_compliances)
      ? checklist?.pr_compliances
      : [];
    facts.push(
      fact({
        id: `local-policy.${slug(path)}`,
        type: "local_policy",
        source: "local_policy",
        path,
        subject: path,
        summary: `${path} defines ${rules.length} custom compliance rule(s).`,
        controls: ["CM-3", "RA-5"],
        disposition: checklist ? "observed" : "missing",
        metadata: { rule_count: rules.length },
      }),
    );
  }

  if (input.mappings) {
    facts.push(
      fact({
        id: "local-policy.checkov-to-nist-mapping",
        type: "local_policy",
        source: "local_policy",
        path: "mappings/checkov-to-nist.yaml",
        subject: "mappings/checkov-to-nist.yaml",
        summary: `Checkov-to-NIST mapping defines ${Object.keys(input.mappings).length} mapping(s).`,
        controls: ["PL-2", "CM-6"],
        disposition: "observed",
        metadata: { mapping_count: Object.keys(input.mappings).length },
      }),
    );
  }

  return facts;
}
```

- [ ] **Step 4: Run tests to verify Task 2 passes**

Run:

```bash
node --import tsx --test tests/evidence.test.ts
```

Expected: PASS for all evidence tests.

- [ ] **Step 5: Commit Task 2**

Run:

```bash
git add src/evidence.ts tests/evidence.test.ts
git commit -m "Add repository evidence extractors"
```

---

### Task 3: Evidence CLI and Artifact Writer

**Files:**
- Modify: `src/evidence.ts`
- Modify: `package.json`
- Modify: `.gitignore`
- Create or modify: `tests/evidence.test.ts`

- [ ] **Step 1: Add failing CLI artifact test**

Append to `tests/evidence.test.ts`:

```ts
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { collectEvidenceFacts } from "../src/evidence.js";

test("collects evidence facts from a repo tree", async () => {
  const dir = await mkdtemp(join(tmpdir(), "controlbot-evidence-"));
  try {
    await writeFile(
      join(dir, "package.json"),
      JSON.stringify({
        name: "demo",
        scripts: { test: "node --test" },
        dependencies: { yaml: "^2.8.1" },
      }),
      "utf8",
    );
    await writeFile(join(dir, "package-lock.json"), "{}", "utf8");
    await writeFile(
      join(dir, "main.tf"),
      'provider "aws" { region = "us-gov-west-1" }',
      "utf8",
    );

    const facts = await collectEvidenceFacts({
      root: dir,
      scanDir: dir,
    });

    assert.ok(facts.some((fact) => fact.source === "terraform"));
    assert.ok(facts.some((fact) => fact.source === "package_manifest"));
    assert.ok(
      facts.some(
        (fact) =>
          fact.source === "codeowners" && fact.disposition === "missing",
      ),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
node --import tsx --test tests/evidence.test.ts
```

Expected: FAIL because `collectEvidenceFacts` is not implemented.

- [ ] **Step 3: Implement repo collection and CLI**

Append to `src/evidence.ts`:

```ts
export interface CollectEvidenceOptions {
  root?: string;
  scanDir?: string;
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function readJsonIfExists(path: string): Promise<Record<string, unknown> | undefined> {
  if (!(await fileExists(path))) return undefined;
  return JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
}

async function readYamlIfExists(path: string): Promise<Record<string, unknown> | undefined> {
  if (!(await fileExists(path))) return undefined;
  return (parseYaml(await readFile(path, "utf8")) ?? {}) as Record<string, unknown>;
}

async function findFiles(dir: string, suffixes: string[]): Promise<string[]> {
  if (!(await fileExists(dir))) return [];
  const entries = await readdir(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      files.push(...(await findFiles(full, suffixes)));
    } else if (suffixes.some((suffix) => entry.name.endsWith(suffix))) {
      files.push(full);
    }
  }
  return files;
}

function repoPath(root: string, path: string): string {
  return relative(root, path).replace(/\\/g, "/") || path;
}

export async function collectEvidenceFacts(
  options: CollectEvidenceOptions = {},
): Promise<EvidenceFact[]> {
  const root = resolve(options.root ?? ROOT);
  const scanDir = resolve(options.scanDir ?? join(root, "fixtures/terraform"));
  const facts: EvidenceFact[] = [];

  for (const tfPath of await findFiles(scanDir, [".tf"])) {
    facts.push(
      ...extractTerraformEvidenceFromText(
        await readFile(tfPath, "utf8"),
        repoPath(root, tfPath),
      ),
    );
  }

  const workflowDir = join(root, ".github/workflows");
  for (const workflowPath of await findFiles(workflowDir, [".yml", ".yaml"])) {
    facts.push(
      ...extractWorkflowEvidenceFromText(
        await readFile(workflowPath, "utf8"),
        repoPath(root, workflowPath),
      ),
    );
  }

  const packageJson = await readJsonIfExists(join(root, "package.json"));
  if (packageJson) {
    facts.push(
      ...extractPackageEvidence(
        packageJson,
        await fileExists(join(root, "package-lock.json")),
        "package.json",
      ),
    );
  }

  let codeowners:
    | {
        path: string;
        text: string;
      }
    | undefined;
  for (const candidate of [
    "CODEOWNERS",
    ".github/CODEOWNERS",
    "docs/CODEOWNERS",
  ]) {
    const full = join(root, candidate);
    if (await fileExists(full)) {
      codeowners = { path: candidate, text: await readFile(full, "utf8") };
      break;
    }
  }
  facts.push(...extractCodeownersEvidence(codeowners));

  facts.push(
    ...extractLocalPolicyEvidence({
      profile: await readYamlIfExists(join(root, ".controlbot/profile.yaml")),
      localChecklist: await readYamlIfExists(
        join(root, ".controlbot/checklist.yaml"),
      ),
      orgChecklist: await readYamlIfExists(
        join(root, ".controlbot/org/checklist.yaml"),
      ),
      mappings: await readYamlIfExists(join(root, "mappings/checkov-to-nist.yaml")),
    }),
  );

  return facts;
}

function parseArgs(argv: string[]) {
  const args = {
    root: ROOT,
    scanDir: resolve(ROOT, "fixtures/terraform"),
    output: resolve(ROOT, "evidence-facts.json"),
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--root" && argv[i + 1]) args.root = resolve(argv[++i]);
    else if (arg === "--scan-dir" && argv[i + 1])
      args.scanDir = resolve(argv[++i]);
    else if (arg === "--output" && argv[i + 1])
      args.output = resolve(argv[++i]);
    else if (arg === "--help") {
      console.log(`Usage: npm run evidence -- [options]

Options:
  --root <path>      Repository root
  --scan-dir <path>  Terraform scan directory
  --output <path>    Evidence JSON output
`);
      process.exit(0);
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const facts = await collectEvidenceFacts({
    root: args.root,
    scanDir: args.scanDir,
  });
  const document = buildEvidenceDocument(facts);
  await writeFile(args.output, JSON.stringify(document, null, 2), "utf8");
  console.log(
    `Evidence facts: ${document.summary.total} total, ${document.summary.missing} missing, ${document.summary.warnings} warning(s)`,
  );
  console.log(`Wrote ${args.output}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
```

Modify `package.json` scripts:

```json
"evidence": "tsx src/evidence.ts"
```

Modify `.gitignore`:

```gitignore
evidence-facts.json
```

- [ ] **Step 4: Run evidence CLI**

Run:

```bash
npm run evidence
```

Expected: command writes `evidence-facts.json` and prints a total count.

- [ ] **Step 5: Run evidence tests**

Run:

```bash
node --import tsx --test tests/evidence.test.ts
```

Expected: PASS.

- [ ] **Step 6: Commit Task 3**

Run:

```bash
git add src/evidence.ts tests/evidence.test.ts package.json .gitignore
git commit -m "Add evidence artifact CLI"
```

---

### Task 4: Review Payload and Report Integration

**Files:**
- Modify: `src/lib.ts`
- Modify: `src/review.ts`
- Modify: `src/controlbot.ts`
- Modify: `tests/review-payload.test.ts`

- [ ] **Step 1: Add failing review payload test**

Append to `tests/review-payload.test.ts`:

```ts
import type { EvidenceDocument } from "../src/evidence.js";

const evidenceDocument: EvidenceDocument = {
  schema: "controlbot.evidence-facts.v1",
  generated_at: "2026-05-30T00:00:00.000Z",
  summary: {
    total: 2,
    observed: 1,
    missing: 1,
    warnings: 0,
    not_applicable: 0,
    by_source: {
      codeowners: 1,
      terraform: 1,
    },
    by_control_family: {
      CM: 2,
    },
  },
  facts: [
    {
      id: "codeowners.missing",
      type: "ownership_metadata",
      source: "codeowners",
      path: "CODEOWNERS",
      subject: "CODEOWNERS",
      summary: "No CODEOWNERS file was found.",
      controls: ["CM-3"],
      confidence: "deterministic",
      disposition: "missing",
      metadata: {},
    },
    {
      id: "terraform.provider.aws.region.us-gov-west-1",
      type: "configuration_baseline",
      source: "terraform",
      path: "fixtures/terraform/main.tf",
      subject: "provider.aws",
      summary: "AWS provider region is us-gov-west-1.",
      controls: ["CM-6"],
      confidence: "deterministic",
      disposition: "observed",
      metadata: { region: "us-gov-west-1" },
    },
  ],
};

test("review payload includes evidence summary without changing finding stats", () => {
  const payload = buildReviewPayload(
    [
      finding({
        severity: "LOW",
        nistControls: ["CM-6"],
        nistFamily: "CM",
      }),
    ],
    profile,
    undefined,
    evidenceDocument,
  );

  assert.equal(payload.stats.total, 1);
  assert.equal(payload.stats.blocking, 0);
  assert.equal(payload.evidence?.summary.total, 2);
  assert.equal(payload.evidence?.summary.missing, 1);
  assert.match(payload.body, /### Evidence/);
  assert.match(payload.body, /Missing evidence: 1/);
});
```

- [ ] **Step 2: Run review payload test to verify it fails**

Run:

```bash
node --import tsx --test tests/review-payload.test.ts
```

Expected: FAIL because `buildReviewPayload` does not accept evidence yet.

- [ ] **Step 3: Add evidence loading and rendering helpers**

Modify `src/lib.ts`:

```ts
import type {
  EvidenceDocument,
  EvidenceFact,
} from "./evidence.js";
```

Extend `ReviewPayload`:

```ts
  evidence?: EvidenceDocument;
```

Add helper near `buildCustomComplianceBody`:

```ts
function topEvidenceFamilies(evidence: EvidenceDocument): string {
  return Object.entries(evidence.summary.by_control_family)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)
    .map(([family, count]) => `${family}: ${count}`)
    .join(", ");
}

function buildEvidenceBody(evidence?: EvidenceDocument): string[] {
  if (!evidence || evidence.summary.total === 0) return [];
  const families = topEvidenceFamilies(evidence);
  const warnings = evidence.facts
    .filter((fact) => fact.disposition === "warning")
    .slice(0, 5);
  const missing = evidence.facts
    .filter((fact) => fact.disposition === "missing")
    .slice(0, 5);
  const lines = [
    "### Evidence",
    "",
    `Facts: ${evidence.summary.total} · Observed: ${evidence.summary.observed} · Missing evidence: ${evidence.summary.missing} · Warnings: ${evidence.summary.warnings}`,
    families ? `Control families: ${families}` : "",
  ].filter(Boolean);

  for (const item of [...missing, ...warnings]) {
    lines.push(`- ${item.disposition.toUpperCase()} ${item.subject}: ${item.summary}`);
  }

  lines.push(
    "",
    "_Evidence facts are deterministic repo observations and are not mixed into Checkov findings._",
  );
  return lines;
}
```

Change `buildReviewPayload` signature:

```ts
export function buildReviewPayload(
  findings: EnrichedFinding[],
  profile: ControlBotProfile,
  customCompliance?: CustomComplianceResults,
  evidence?: EvidenceDocument,
): ReviewPayload {
```

Add `...buildEvidenceBody(evidence),` after custom compliance body in the PR body array.

Return `evidence` in the payload object:

```ts
    evidence,
```

Change `buildAgentPrompt` signature to include evidence:

```ts
  evidence?: EvidenceDocument,
```

Add:

```ts
  const evidenceJson = JSON.stringify(evidence?.facts ?? [], null, 2);
```

Add prompt section:

```md
## Evidence facts
${evidence?.facts.length ? evidenceJson : "_No evidence facts extracted._"}
```

Add prompt rule:

```md
- Treat evidence facts as repo observations, not scanner findings.
```

- [ ] **Step 4: Wire evidence into review and controlbot commands**

Modify `src/review.ts` imports:

```ts
import {
  buildEvidenceDocument,
  collectEvidenceFacts,
  type EvidenceDocument,
} from "./evidence.js";
```

Add args:

```ts
    evidencePath: resolve(ROOT, "evidence-facts.json"),
```

Parse:

```ts
    else if (arg === "--evidence" && argv[i + 1])
      args.evidencePath = resolve(argv[++i]);
```

After findings/custom compliance are initialized:

```ts
  const evidence = buildEvidenceDocument(
    await collectEvidenceFacts({ root: ROOT, scanDir: args.scanDir }),
  );
  await writeFile(args.evidencePath, JSON.stringify(evidence, null, 2), "utf8");
```

Change scan-only report signature:

```ts
  evidence: EvidenceDocument,
```

Append scan-only report section:

```ts
  lines.push(
    "",
    "## Evidence Facts",
    "",
    `Facts: **${evidence.summary.total}**`,
    `Observed: **${evidence.summary.observed}**`,
    `Missing: **${evidence.summary.missing}**`,
    `Warnings: **${evidence.summary.warnings}**`,
    "",
    "| Source | Disposition | Subject | Controls | Summary |",
    "| --- | --- | --- | --- | --- |",
  );
  for (const fact of evidence.facts.slice(0, 25)) {
    lines.push(
      `| ${fact.source} | ${fact.disposition} | ${fact.subject} | ${fact.controls.join(", ") || "-"} | ${fact.summary.replace(/\|/g, "\\|")} |`,
    );
  }
```

Pass evidence into `writeScanOnlyReport` and `buildAgentPrompt`.

Modify `src/controlbot.ts` imports:

```ts
import {
  buildEvidenceDocument,
  collectEvidenceFacts,
} from "./evidence.js";
```

Add args:

```ts
    evidencePath: resolve(ROOT, "evidence-facts.json"),
```

Parse:

```ts
    else if (arg === "--evidence" && argv[i + 1])
      args.evidencePath = resolve(argv[++i]);
```

Load evidence:

```ts
  const evidence = buildEvidenceDocument(
    await collectEvidenceFacts({ root: ROOT, scanDir: args.scanDir }),
  );
```

Pass evidence:

```ts
  const payload = buildReviewPayload(findings, profile, customCompliance, evidence);
```

- [ ] **Step 5: Run focused tests**

Run:

```bash
node --import tsx --test tests/review-payload.test.ts tests/evidence.test.ts
```

Expected: PASS.

- [ ] **Step 6: Run local commands**

Run:

```bash
npm run scan
npm run review -- --scan-only
npm run controlbot
```

Expected:

- `npm run review -- --scan-only` writes `evidence-facts.json`.
- `npm run controlbot` writes `review-payload.json` and exits `2` if current fixture blockers remain.
- `review-payload.json` includes `evidence`.

- [ ] **Step 7: Commit Task 4**

Run:

```bash
git add src/lib.ts src/review.ts src/controlbot.ts tests/review-payload.test.ts
git commit -m "Include evidence facts in reports and review payloads"
```

---

### Task 5: CI, Docs, and Final Verification

**Files:**
- Modify: `.github/workflows/controlbot.yml`
- Modify: `README.md`
- Modify: `.gitignore`
- Modify: `package.json`

- [ ] **Step 1: Update GitHub Actions workflow**

Modify `.github/workflows/controlbot.yml`:

Add after `Scan Terraform`:

```yaml
      - name: Extract repo evidence
        env:
          SCAN_DIR: ${{ steps.scan.outputs.dir }}
        run: npm run evidence -- --scan-dir "$SCAN_DIR"
```

Add artifact path:

```yaml
            evidence-facts.json
```

- [ ] **Step 2: Update README**

Add a section after custom compliance:

```md
## Evidence facts

ControlBot also extracts deterministic repo evidence into `evidence-facts.json`.
This is a separate non-blocking lane from Checkov findings and custom
compliance assessments.

Evidence sources:

- Terraform resources, provider regions, public exposure, tags, and visible
  encryption attributes
- GitHub workflow triggers, permissions, test/typecheck steps, and artifact
  uploads
- `package.json` / `package-lock.json` dependency and script evidence
- CODEOWNERS presence or missing ownership evidence
- `.controlbot/*` policy files and Checkov-to-NIST mapping coverage

Evidence facts appear in `review-payload.json` and the Markdown report, but do
not change Checkov finding counts or merge-blocking behavior in v1.
```

Update command table:

```md
| `npm run evidence` | Build `evidence-facts.json` from repo evidence sources |
```

- [ ] **Step 3: Run full verification**

Run:

```bash
npm run typecheck
npm test
npm run evidence
npm run scan
npm run review -- --scan-only
npm run controlbot
```

Expected:

- typecheck exits `0`
- tests exit `0`
- evidence exits `0`
- scan exits `0`
- review scan-only exits `0`
- controlbot exits `2` for current fixture blockers

- [ ] **Step 4: Inspect artifacts**

Run:

```bash
jq '{schema, summary, sources: (.facts | map(.source) | unique)}' evidence-facts.json
jq '{checkov_total: .stats.total, evidence_total: .evidence.summary.total, has_evidence: (.evidence != null)}' review-payload.json
rg -n "Evidence Facts|Evidence" report.md review-payload.json
```

Expected:

- `evidence-facts.json` schema is `controlbot.evidence-facts.v1`
- sources include `terraform`, `github_workflow`, `package_manifest`,
  `codeowners`, and `local_policy`
- `review-payload.json` has evidence summary
- report contains evidence section

- [ ] **Step 5: Commit Task 5**

Run:

```bash
git add .github/workflows/controlbot.yml README.md .gitignore package.json package-lock.json
git commit -m "Document and publish evidence facts artifact"
```

- [ ] **Step 6: Push branch**

Run:

```bash
git push origin controlbot-ci-hardening
```

Expected: branch pushes cleanly.

---

## Self-Review Checklist

- Spec coverage: tasks implement evidence facts from Terraform, GitHub workflows, package manifests, CODEOWNERS, and local policy files.
- Artifact coverage: tasks generate `evidence-facts.json`, include it in CI upload, and include evidence summaries in `report.md` and `review-payload.json`.
- Separation coverage: review payload test verifies Checkov stats remain unchanged when evidence is present.
- Non-goals preserved: no evidence merge blocking, no evidence inline comments, no evidence POA&M seeds.
- Verification coverage: plan ends with typecheck, unit tests, local command verification, artifact inspection, and push.
