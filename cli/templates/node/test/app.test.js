// Runs with `node --test` (orch-apps test sets DATA_DIR to a fresh temporary folder).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.DATA_DIR ||= mkdtempSync(join(tmpdir(), "{{slug}}-"));
const { server } = await import("../server.js");

test("health and start page answer", async () => {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.equal((await fetch(`${base}/health`)).status, 200);
    const res = await fetch(`${base}/`);
    assert.equal(res.status, 200);
    assert.match(await res.text(), /<h1>{{name}}<\/h1>/);
  } finally {
    server.close();
  }
});
