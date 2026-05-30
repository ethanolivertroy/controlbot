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
