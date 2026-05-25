import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface ControlBotProfile {
  name: string;
  baseline: string;
  scan_paths: string[];
  inherited_controls: string[];
  inline_comments: boolean;
  block_on_severity: Severity[];
  block_on_unmapped_count: number;
  max_inline_comments: number;
  bot_name: string;
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

const DEFAULT_PROFILE: ControlBotProfile = {
  name: "controlbot",
  baseline: "fedramp-moderate",
  scan_paths: ["fixtures/terraform"],
  inherited_controls: [],
  inline_comments: true,
  block_on_severity: ["HIGH", "CRITICAL"],
  block_on_unmapped_count: 5,
  max_inline_comments: 30,
  bot_name: "ControlBot",
};

export async function loadControlBotProfile(
  path = resolve(ROOT, ".controlbot/profile.yaml"),
): Promise<ControlBotProfile> {
  try {
    const raw = await readFile(path, "utf8");
    const parsed = parseYaml(raw) as Partial<ControlBotProfile>;
    return { ...DEFAULT_PROFILE, ...parsed };
  } catch {
    return DEFAULT_PROFILE;
  }
}

export function isBlockingSeverity(
  severity: string,
  profile: ControlBotProfile,
): boolean {
  return profile.block_on_severity.includes(severity as Severity);
}

export function isFullyInherited(
  controls: string[],
  profile: ControlBotProfile,
): boolean {
  if (controls.length === 0) return false;
  const inherited = new Set(profile.inherited_controls);
  return controls.every((c) => inherited.has(c));
}
