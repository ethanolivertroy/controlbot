import test from "node:test";
import assert from "node:assert/strict";
import { buildReviewPayload, type EnrichedFinding } from "../src/lib.js";
import type {
  CustomComplianceAssessment,
  CustomComplianceResults,
} from "../src/custom-compliance.js";
import type { EvidenceDocument } from "../src/evidence.js";
import type { ControlBotProfile } from "../src/profile.js";

const profile: ControlBotProfile = {
  name: "test",
  baseline: "fedramp-moderate",
  scan_paths: ["fixtures/terraform"],
  inherited_controls: [],
  inline_comments: true,
  block_on_severity: ["HIGH", "CRITICAL"],
  block_on_unmapped_count: 5,
  max_inline_comments: 10,
  bot_name: "ControlBot",
};

function finding(overrides: Partial<EnrichedFinding> = {}): EnrichedFinding {
  return {
    checkId: "CKV_AWS_TEST",
    checkName: "Ensure test resource is hardened",
    resource: "aws_s3_bucket.test",
    filePath: "/main.tf",
    repoPath: "fixtures/terraform/main.tf",
    lineRange: [1, 1],
    severity: "HIGH",
    guideline: "https://example.com/policy",
    nistControls: ["SC-7", "AC-4"],
    nistFamily: "SC",
    controlIntent: "Test control intent.",
    mapped: true,
    inherited: false,
    ...overrides,
  };
}

function customFailure(): CustomComplianceResults {
  const assessment: CustomComplianceAssessment = {
    ruleId: "resource-ownership-tags",
    title: "Resource Ownership Tags",
    status: "FAIL",
    summary: "Resource tags are missing.",
    evidence: [
      {
        path: "fixtures/terraform/main.tf",
        line: 16,
        detail: "No tags block is present.",
      },
    ],
    remediation: "Add owner and data_classification tags.",
    controls: ["CM-8"],
    severity: "MEDIUM",
    complianceLabel: true,
    blocking: true,
    source: "cursor-agent",
    ruleSource: "local",
    ruleSourcePath: ".controlbot/checklist.yaml",
    overriddenRuleSource: "org",
    overriddenRuleSourcePath: ".controlbot/org/checklist.yaml",
  };

  return {
    sourcePath: ".controlbot/checklist.yaml",
    sources: [
      {
        kind: "local",
        path: ".controlbot/checklist.yaml",
        configuredRules: 1,
        enabledRules: 1,
      },
    ],
    overrides: [],
    assessedAt: "2026-05-30T00:00:00.000Z",
    assessor: "cursor-agent",
    assessments: [assessment],
    stats: {
      configured: 1,
      org_rules: 0,
      local_rules: 1,
      overrides: 0,
      disabled: 0,
      assessed: 1,
      passed: 0,
      failed: 1,
      not_applicable: 0,
      unknown: 0,
      blocking: 1,
    },
  };
}

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

test("review payload includes managed labels for deterministic and custom compliance findings", () => {
  const payload = buildReviewPayload([finding()], profile, customFailure());
  const labels = payload.labels.map((label) => label.name);

  assert.equal(payload.event, "REQUEST_CHANGES");
  assert.deepEqual(
    labels,
    [
      "controlbot:blocking",
      "controlbot:custom-compliance",
      "controlbot:family-AC",
      "controlbot:family-CM",
      "controlbot:family-SC",
      "effort:4",
    ],
  );
  assert.equal(payload.stats.custom_compliance?.blocking, 1);
  assert.equal(payload.custom_compliance?.assessments[0].ruleSource, "local");
});

test("review payload removes blocking label when only nonblocking findings remain", () => {
  const payload = buildReviewPayload(
    [
      finding({
        severity: "LOW",
        nistControls: ["CM-6"],
        nistFamily: "CM",
      }),
    ],
    profile,
  );
  const labels = payload.labels.map((label) => label.name);

  assert.equal(payload.event, "COMMENT");
  assert.deepEqual(labels, ["controlbot:family-CM", "effort:2"]);
});

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
