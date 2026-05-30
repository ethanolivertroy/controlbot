import test from "node:test";
import assert from "node:assert/strict";
import { buildReviewPayload, type EnrichedFinding } from "../src/lib.js";
import type {
  CustomComplianceAssessment,
  CustomComplianceResults,
} from "../src/custom-compliance.js";
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
