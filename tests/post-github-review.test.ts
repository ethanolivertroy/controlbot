import test from "node:test";
import assert from "node:assert/strict";
import {
  isLabelAlreadyExistsError,
  isCommentInDiff,
  planManagedLabelSync,
  selectStickySummaryComment,
} from "../src/post-github-review.js";
import type { InlineReviewComment, ReviewLabel } from "../src/lib.js";

test("selects only the github-actions sticky summary comment", () => {
  const comments = [
    {
      id: 1,
      body: "<!-- controlbot-summary -->\nspoofed marker",
      user: { login: "ethanolivertroy", type: "User" },
    },
    {
      id: 2,
      body: "<!-- controlbot-summary -->\nreal marker",
      user: { login: "github-actions[bot]", type: "Bot" },
    },
  ];

  assert.equal(selectStickySummaryComment(comments)?.id, 2);
});

test("plans stale managed label removal without touching user labels", () => {
  const desired: ReviewLabel[] = [
    {
      name: "controlbot:blocking",
      color: "b60205",
      description: "Blocking finding.",
    },
    {
      name: "effort:3",
      color: "fbca04",
      description: "Medium remediation effort.",
    },
  ];

  const plan = planManagedLabelSync(
    ["bug", "controlbot:blocking", "controlbot:family-AC", "effort:1"],
    desired,
  );

  assert.deepEqual(plan.add, ["effort:3"]);
  assert.deepEqual(plan.remove, ["controlbot:family-AC", "effort:1"]);
});

test("filters inline comments to lines present in the PR diff", () => {
  const comment = (
    path: string,
    line: number,
  ): InlineReviewComment => ({
    path,
    line,
    side: "RIGHT",
    body: "Review body",
  });
  const diffLines = new Map([
    ["fixtures/terraform/main.tf", new Set([16, 17, 18])],
  ]);

  assert.equal(
    isCommentInDiff(comment("fixtures/terraform/main.tf", 16), diffLines),
    true,
  );
  assert.equal(
    isCommentInDiff(comment("fixtures/terraform/main.tf", 41), diffLines),
    false,
  );
  assert.equal(isCommentInDiff(comment("other.tf", 16), diffLines), false);
});

test("treats only already-existing label errors as recoverable", () => {
  assert.equal(
    isLabelAlreadyExistsError({
      status: 422,
      response: {
        data: {
          errors: [{ resource: "Label", code: "already_exists" }],
        },
      },
    }),
    true,
  );
  assert.equal(
    isLabelAlreadyExistsError({
      status: 422,
      response: {
        data: {
          errors: [{ resource: "Label", code: "invalid" }],
        },
      },
    }),
    false,
  );
  assert.equal(isLabelAlreadyExistsError({ status: 500 }), false);
});
