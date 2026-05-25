import { readFile } from "node:fs/promises";
import { Octokit } from "@octokit/rest";
import type { InlineReviewComment, ReviewPayload } from "./lib.js";

function parseDiffLines(patch: string | undefined): Set<number> {
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

function isCommentInDiff(
  comment: InlineReviewComment,
  diffLines: Map<string, Set<number>>,
): boolean {
  const lines = diffLines.get(comment.path);
  if (!lines || lines.size === 0) return true;
  return lines.has(comment.line);
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

  // GITHUB_TOKEN cannot submit REQUEST_CHANGES — merge gate is the CI check.
  const summary = await octokit.pulls.createReview({
    owner,
    repo,
    pull_number: pullNumber,
    commit_id: headSha,
    event: "COMMENT",
    body:
      payload.body +
      (skipped > 0
        ? `\n\n_${skipped} finding(s) on unchanged lines in this diff — see full scan artifact._`
        : ""),
  });

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
    `Posted summary review ${summary.data.id}; ${posted}/${inlineCandidates.length} inline comment(s)`,
  );

  if (failures.length > 0) {
    console.warn("Some inline comments failed:\n" + failures.join("\n"));
  }

  if (posted === 0 && payload.stats.total > 0) {
    await octokit.issues.createComment({
      owner,
      repo,
      issue_number: pullNumber,
      body: `## ${payload.stats.total} compliance finding(s)\n\n${payload.body}`,
    });
    console.log("Fell back to issue comment (no diff lines matched).");
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
