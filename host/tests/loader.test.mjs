// The sealed loader's decrypt function against a blob made with WebCrypto here: same format the CLI writes.
// Run: node --test host/tests/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("../orch_apps_host/loader.html", import.meta.url), "utf8");
const src = html.split("/*open*/")[1];
const openSealed = new Function(`${src}; return openSealed;`)();

async function seal(text, shareId) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new TextEncoder().encode("orch-apps:" + shareId) },
    key, new TextEncoder().encode(text)));
  const blob = new Uint8Array(4 + 12 + ct.length);
  blob.set(new TextEncoder().encode("OAS1"), 0);
  blob.set(iv, 4);
  blob.set(ct, 16);
  const k = Buffer.from(raw).toString("base64url");
  return { blob, k };
}

test("opens a sealed page with the key from the fragment", async () => {
  const { blob, k } = await seal("<h1>Grüezi</h1>", "seal01");
  assert.equal(await openSealed(k, blob, "seal01"), "<h1>Grüezi</h1>");
});

test("refuses a blob of another share id", async () => {
  const { blob, k } = await seal("x", "seal01");
  await assert.rejects(openSealed(k, blob, "seal02"));
});

test("refuses a cut-off key", async () => {
  const { blob, k } = await seal("x", "seal01");
  await assert.rejects(openSealed(k.slice(0, 20), blob, "seal01"));
});
