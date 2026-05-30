import { parse as parseYaml } from "yaml";

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

    const families = new Set(item.controls.map(controlFamily));
    for (const family of families) {
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

  for (let i = openBraceIndex; i < text.length; i += 1) {
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
  const blocks: Array<{
    type: string;
    name?: string;
    body: string;
    start: number;
  }> = [];

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
        metadata: {
          resource_type: resource.type,
          resource_name: resource.name,
        },
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

  const testCommandIndex = text.search(/npm\s+run\s+typecheck|npm\s+test/);
  if (testCommandIndex >= 0 || /npm\s+run\s+test/.test(text)) {
    facts.push(
      fact({
        id: `workflow.${slug(workflowName)}.tests`,
        type: "ci_control",
        source: "github_workflow",
        path,
        line: lineFor(text, Math.max(testCommandIndex, 0)),
        subject: workflowName,
        summary: `${workflowName} runs typecheck or tests.`,
        controls: ["CM-3", "SA-10"],
        disposition: "observed",
        metadata: { command_pattern: "npm test/typecheck" },
      }),
    );
  }

  const artifactIndex = text.indexOf("actions/upload-artifact@");
  if (artifactIndex >= 0) {
    facts.push(
      fact({
        id: `workflow.${slug(workflowName)}.artifact-upload`,
        type: "artifact_retention",
        source: "github_workflow",
        path,
        line: lineFor(text, artifactIndex),
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
    ? input.profile.inherited_controls
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

  for (const [key, policyPath] of [
    ["localChecklist", ".controlbot/checklist.yaml"],
    ["orgChecklist", ".controlbot/org/checklist.yaml"],
  ] as const) {
    const checklist = input[key];
    const rules = Array.isArray(checklist?.pr_compliances)
      ? checklist.pr_compliances
      : [];
    facts.push(
      fact({
        id: `local-policy.${slug(policyPath)}`,
        type: "local_policy",
        source: "local_policy",
        path: policyPath,
        subject: policyPath,
        summary: `${policyPath} defines ${rules.length} custom compliance rule(s).`,
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
