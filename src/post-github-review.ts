import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Octokit } from "@octokit/rest";
import type {
  InlineReviewComment,
  ReviewLabel,
  ReviewPayload,
} from "./lib.js";

const SUMMARY_MARKER = "<!-- controlbot-summary -->";

interface StickySummaryComment {
  id: number;
  body?: string | null;
  user?: {
    login?: string | null;
    type?: string | null;
  } | null;
}

export function isManagedLabel(name: string): boolean {
  return name.startsWith("controlbot:") || name.startsWith("effort:");
}

function isGithubActionsBot(user: StickySummaryComment["user"]): boolean {
  const login = user?.login ?? "";
  return (
    user?.type === "Bot" &&
    (login === "github-actions[bot]" || login === "github-actions")
  );
}

export function selectStickySummaryComment<T extends StickySummaryComment>(
  comments: T[],
): T | undefined {
  return comments.find(
    (comment) =>
      comment.body?.includes(SUMMARY_MARKER) &&
      isGithubActionsBot(comment.user),
  );
}

export function planManagedLabelSync(
  currentLabels: string[],
  labels: ReviewLabel[],
): { add: string[]; remove: string[] } {
  const desired = new Set(labels.map((label) => label.name));
  const current = new Set(currentLabels);

  return {
    add: [...desired].filter((name) => !current.has(name)),
    remove: currentLabels.filter(
      (name) => isManagedLabel(name) && !desired.has(name),
    ),
  };
}

export function parseDiffLines(patch: string | undefined): Set<number> {
  const lines = new Set<number>();
  if (!patch) return lines;

  let newLine = 0;
  for (const raw of patch.split("\n")) {
    if (raw.startsWith("@@")) {
      const match = raw.match(/\+(\d+)/);
      newLine = match ? Number(match[1]) - 1 : newLine;
      continue;
    }
    if (raw.startsWith("+") && !raw.startsWith("+++")) {
      newLine += 1;
      lines.add(newLine);
      continue;
    }
    if (raw.startsWith("-") && !raw.startsWith("---")) {
      continue;
    }
    if (raw.startsWith(" ")) {
      newLine += 1;
      lines.add(newLine);
    }
  }

  return lines;
}

async function loadDiffLines(
  octokit: Octokit,
  owner: string,
  repo: string,
  pullNumber: number,
): Promise<Map<string, Set<number>>> {
  const files = await octokit.paginate(octokit.pulls.listFiles, {
    owner,
    repo,
    pull_number: pullNumber,
    per_page: 100,
  });

  const map = new Map<string, Set<number>>();
  for (const file of files) {
    if (!file.filename.endsWith(".tf")) continue;
    map.set(file.filename, parseDiffLines(file.patch));
  }
  return map;
}

export function isCommentInDiff(
  comment: InlineReviewComment,
  diffLines: Map<string, Set<number>>,
): boolean {
  const lines = diffLines.get(comment.path);
  if (!lines || lines.size === 0) return false;
  return lines.has(comment.line);
}

export function isLabelAlreadyExistsError(err: unknown): boolean {
  if (
    typeof err !== "object" ||
    err === null ||
    !("status" in err) ||
    (err as { status?: number }).status !== 422
  ) {
    return false;
  }

  const errors = (err as { response?: { data?: { errors?: unknown } } })
    .response?.data?.errors;
  if (!Array.isArray(errors)) return false;

  return errors.some((item) => {
    if (typeof item !== "object" || item === null) return false;
    const error = item as { code?: unknown; resource?: unknown };
    return (
      error.code === "already_exists" &&
      (error.resource === undefined || error.resource === "Label")
    );
  });
}

async function ensureLabel(
  octokit: Octokit,
  owner: string,
  repo: string,
  label: ReviewLabel,
) {
  try {
    await octokit.issues.createLabel({
      owner,
      repo,
      name: label.name,
      color: label.color,
      description: label.description,
    });
  } catch (err) {
    if (isLabelAlreadyExistsError(err)) {
      return;
    }
    throw err;
  }
}

async function syncLabels(
  octokit: Octokit,
  owner: string,
  repo: string,
  issueNumber: number,
  labels: ReviewLabel[],
) {
  for (const label of labels) {
    await ensureLabel(octokit, owner, repo, label);
  }

  const issue = await octokit.issues.get({
    owner,
    repo,
    issue_number: issueNumber,
  });
  const current = issue.data.labels
    .map((label) => (typeof label === "string" ? label : label.name))
    .filter((name): name is string => Boolean(name));
  const plan = planManagedLabelSync(current, labels);

  for (const name of plan.remove) {
    await octokit.issues.removeLabel({
      owner,
      repo,
      issue_number: issueNumber,
      name,
    });
  }

  if (plan.add.length > 0) {
    await octokit.issues.addLabels({
      owner,
      repo,
      issue_number: issueNumber,
      labels: plan.add,
    });
  }
}

function buildStickyBody(payload: ReviewPayload, skipped: number): string {
  const labelLine =
    payload.labels.length > 0
      ? `\n\n**Labels:** ${payload.labels.map((label) => `\`${label.name}\``).join(", ")}`
      : "";
  const skippedLine =
    skipped > 0
      ? `\n\n_${skipped} finding(s) on unchanged lines in this diff — see full scan artifact._`
      : "";

  return `${SUMMARY_MARKER}\n${payload.body}${labelLine}${skippedLine}`;
}

async function upsertStickySummary(
  octokit: Octokit,
  owner: string,
  repo: string,
  issueNumber: number,
  body: string,
) {
  const comments = await octokit.paginate(octokit.issues.listComments, {
    owner,
    repo,
    issue_number: issueNumber,
    per_page: 100,
  });
  const existing = selectStickySummaryComment(comments);

  if (existing) {
    try {
      await octokit.issues.updateComment({
        owner,
        repo,
        comment_id: existing.id,
        body,
      });
      return { action: "updated", id: existing.id };
    } catch (err) {
      if (
        typeof err !== "object" ||
        err === null ||
        !("status" in err) ||
        (err as { status?: number }).status !== 403
      ) {
        throw err;
      }
      console.warn(
        `Could not update sticky summary ${existing.id}; creating a new one.`,
      );
    }
  }

  const created = await octokit.issues.createComment({
    owner,
    repo,
    issue_number: issueNumber,
    body,
  });
  return { action: "created", id: created.data.id };
}

async function main() {
  const token = process.env.GITHUB_TOKEN;
  const repoFull = process.env.GITHUB_REPOSITORY;
  const prNumber = process.env.PR_NUMBER;
  const headSha = process.env.HEAD_SHA;
  const payloadPath = process.env.REVIEW_PAYLOAD ?? "review-payload.json";

  if (!token || !repoFull || !prNumber || !headSha) {
    console.error(
      "Required env: GITHUB_TOKEN, GITHUB_REPOSITORY, PR_NUMBER, HEAD_SHA",
    );
    process.exit(1);
  }

  const [owner, repo] = repoFull.split("/");
  const pullNumber = Number(prNumber);
  const raw = await readFile(payloadPath, "utf8");
  const payload = JSON.parse(raw) as ReviewPayload;

  const octokit = new Octokit({ auth: token });
  const diffLines = await loadDiffLines(octokit, owner, repo, pullNumber);

  const inlineCandidates = payload.comments.filter((c) =>
    isCommentInDiff(c, diffLines),
  );
  const skipped = payload.comments.length - inlineCandidates.length;

  const summary = await upsertStickySummary(
    octokit,
    owner,
    repo,
    pullNumber,
    buildStickyBody(payload, skipped),
  );

  try {
    await syncLabels(octokit, owner, repo, pullNumber, payload.labels);
    console.log(`Synced ${payload.labels.length} managed label(s).`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.warn(`Label sync failed: ${message}`);
  }

  let posted = 0;
  const failures: string[] = [];

  for (const comment of inlineCandidates) {
    try {
      await octokit.pulls.createReviewComment({
        owner,
        repo,
        pull_number: pullNumber,
        commit_id: headSha,
        path: comment.path,
        line: comment.line,
        side: comment.side,
        body: comment.body,
      });
      posted += 1;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      failures.push(`${comment.path}:${comment.line} — ${message}`);
    }
  }

  console.log(
    `${summary.action} sticky summary ${summary.id}; ${posted}/${inlineCandidates.length} inline comment(s)`,
  );

  if (failures.length > 0) {
    console.warn("Some inline comments failed:\n" + failures.join("\n"));
  }

  if (posted === 0 && payload.stats.total > 0) {
    console.log("No diff lines matched for inline comments; sticky summary is current.");
  }
}

const isDirectRun =
  process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1]);

if (isDirectRun) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
