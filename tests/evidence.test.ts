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
