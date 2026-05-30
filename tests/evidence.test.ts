import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import {
  buildEvidenceDocument,
  collectEvidenceFacts,
  extractCodeownersEvidence,
  extractLocalPolicyEvidence,
  extractPackageEvidence,
  extractTerraformEvidenceFromText,
  extractWorkflowEvidenceFromText,
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

  assert.deepEqual(
    facts.map((fact) => fact.disposition),
    ["missing"],
  );
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
