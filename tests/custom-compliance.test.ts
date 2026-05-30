import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import {
  buildUnassessedCustomComplianceResults,
  loadCustomComplianceChecklist,
} from "../src/custom-compliance.js";

test("merges org and local checklists with local override and disable provenance", async () => {
  const dir = await mkdtemp(join(tmpdir(), "controlbot-checklist-"));
  const orgPath = join(dir, "org.yaml");
  const localPath = join(dir, "local.yaml");

  try {
    await writeFile(
      orgPath,
      `pr_compliances:
  - id: shared-rule
    title: Org Shared Rule
    compliance_label: true
    objective: Org objective
    success_criteria: Org success
    failure_criteria: Org failure
    controls: [SC-7]
    severity: LOW
  - id: disabled-rule
    title: Disabled Rule
    compliance_label: true
    objective: Disabled objective
    success_criteria: Disabled success
    failure_criteria: Disabled failure
    controls: [CM-3]
    severity: MEDIUM
  - id: org-only-rule
    title: Org Only Rule
    compliance_label: false
    objective: Org only objective
    success_criteria: Org only success
    failure_criteria: Org only failure
    controls: [AC-2]
    severity: LOW
`,
      "utf8",
    );

    await writeFile(
      localPath,
      `pr_compliances:
  - id: shared-rule
    title: Local Shared Rule
    compliance_label: true
    objective: Local objective
    success_criteria: Local success
    failure_criteria: Local failure
    controls: [SC-7, AC-4]
    severity: HIGH
  - id: disabled-rule
    enabled: false
`,
      "utf8",
    );

    const checklist = await loadCustomComplianceChecklist({
      orgPath,
      localPath,
    });
    const results = buildUnassessedCustomComplianceResults(checklist);

    assert.deepEqual(
      checklist.rules.map((rule) => [rule.id, rule.ruleSource, rule.title]),
      [
        ["shared-rule", "local", "Local Shared Rule"],
        ["org-only-rule", "org", "Org Only Rule"],
      ],
    );
    assert.equal(checklist.overrides.length, 2);
    assert.equal(results.sourcePath, "external:local.yaml");
    assert.deepEqual(
      results.sources.map((source) => source.path),
      ["external:org.yaml", "external:local.yaml"],
    );
    assert.equal(
      results.assessments.find((item) => item.ruleId === "shared-rule")
        ?.ruleSourcePath,
      "external:local.yaml",
    );
    assert.equal(
      results.assessments.find((item) => item.ruleId === "shared-rule")
        ?.overriddenRuleSourcePath,
      "external:org.yaml",
    );
    assert.equal(results.stats.org_rules, 1);
    assert.equal(results.stats.local_rules, 1);
    assert.equal(results.stats.overrides, 1);
    assert.equal(results.stats.disabled, 1);
    assert.equal(
      results.assessments.find((item) => item.ruleId === "shared-rule")
        ?.overriddenRuleSource,
      "org",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
