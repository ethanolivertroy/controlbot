import test from "node:test";
import assert from "node:assert/strict";
import type { CustomComplianceResults } from "../src/custom-compliance.js";
import type { EnrichedFinding } from "../src/lib.js";
import { buildPoamSeedDocument, renderPoamMarkdown } from "../src/poam.js";
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

const finding: EnrichedFinding = {
  checkId: "CKV_AWS_TEST",
  checkName: "Ensure test resource is hardened",
  resource: "aws_s3_bucket.test",
  filePath: "/main.tf",
  repoPath: "fixtures/terraform/main.tf",
  lineRange: [16, 20],
  severity: "HIGH",
  guideline: "https://example.com/policy",
  nistControls: ["SC-7", "AC-4"],
  nistFamily: "SC",
  controlIntent: "Test control intent.",
  mapped: true,
  inherited: false,
};

const customCompliance: CustomComplianceResults = {
  sourcePath: ".controlbot/checklist.yaml",
  sources: [],
  overrides: [],
  assessedAt: "2026-05-30T00:00:00.000Z",
  assessor: "cursor-agent",
  assessments: [
    {
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
      controls: ["CM-8", "PL-2"],
      severity: "MEDIUM",
      complianceLabel: true,
      blocking: true,
      source: "cursor-agent",
      ruleSource: "local",
      ruleSourcePath: ".controlbot/checklist.yaml",
      overriddenRuleSource: "org",
      overriddenRuleSourcePath: ".controlbot/org/checklist.yaml",
    },
  ],
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

test("POA&M document preserves deterministic and custom compliance seed fields", () => {
  const generatedAt = new Date("2026-05-30T00:00:00.000Z");
  const document = buildPoamSeedDocument(
    [finding],
    profile,
    customCompliance,
    generatedAt,
  );

  assert.equal(document.schema, "controlbot.poam-seeds.v1");
  assert.deepEqual(document.summary, {
    total: 2,
    checkov: 1,
    custom_compliance: 1,
    merge_blocking: 2,
  });

  const checkovSeed = document.seeds.find((seed) => seed.source === "checkov");
  assert.ok(checkovSeed);
  assert.equal(checkovSeed.control, "SC-7, AC-4");
  assert.equal(checkovSeed.due_date, "2026-06-29");
  assert.equal(checkovSeed.provenance.check_id, "CKV_AWS_TEST");

  const customSeed = document.seeds.find(
    (seed) => seed.source === "custom_compliance",
  );
  assert.ok(customSeed);
  assert.equal(customSeed.recommended_remediation, customCompliance.assessments[0].remediation);
  assert.equal(customSeed.provenance.custom_rule_source, "local");
  assert.equal(customSeed.provenance.overridden_rule_source, "org");
});

test("POA&M markdown renders the JSON seed set", () => {
  const document = buildPoamSeedDocument(
    [finding],
    profile,
    customCompliance,
    new Date("2026-05-30T00:00:00.000Z"),
  );
  const markdown = renderPoamMarkdown(document);

  assert.match(markdown, /ControlBot POA&M Seeds/);
  assert.match(markdown, /custom_compliance/);
  assert.match(markdown, /Resource Ownership Tags/);
});
