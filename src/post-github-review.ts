import { readFile } from "node:fs/promises";
import { Octokit } from "@octokit/rest";
import type { ReviewPayload } from "./lib.js";

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

  // Remove prior bot reviews from this run's context (optional: comment-only updates)
  const review = await octokit.pulls.createReview({
    owner,
    repo,
    pull_number: pullNumber,
    commit_id: headSha,
    event: payload.event,
    body: payload.body,
    comments: payload.comments.map((c) => ({
      path: c.path,
      line: c.line,
      start_line: c.startLine,
      side: c.side,
      body: c.body,
    })),
  });

  console.log(
    `Posted review ${review.data.id} (${payload.event}) with ${payload.comments.length} inline comment(s)`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
