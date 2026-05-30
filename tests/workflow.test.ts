import { readFile } from "node:fs/promises";
import test from "node:test";
import assert from "node:assert/strict";

test("workflow passes scan paths and changed files through quoted shell variables", async () => {
  const workflow = await readFile(".github/workflows/controlbot.yml", "utf8");

  assert.match(workflow, /SCAN_DIR: \$\{\{ steps\.scan\.outputs\.dir \}\}/);
  assert.match(workflow, /CONTROLBOT_ARGS=\("--scan-dir" "\$SCAN_DIR"\)/);
  assert.match(workflow, /POAM_ARGS=\("--scan-dir" "\$SCAN_DIR"\)/);
  assert.match(workflow, /while IFS= read -r changed_file; do/);
  assert.match(workflow, /npm run controlbot -- "\$\{CONTROLBOT_ARGS\[@\]\}"/);
  assert.match(workflow, /npm run poam -- "\$\{POAM_ARGS\[@\]\}"/);
  assert.doesNotMatch(workflow, /npm run controlbot -- \$ARGS/);
  assert.doesNotMatch(workflow, /npm run poam -- \$ARGS/);
  assert.doesNotMatch(workflow, /for f in \$\{\{ steps\.scan\.outputs\.changed \}\}/);
});
