// {{name}}: a mini app on orch-apps (node, store {{store}}).
// The host gives every app PORT, BASE_PATH (/{{slug}}), DATA_DIR (kept across deploys) and APP_ENV.
// Requests arrive without the /{{slug}} prefix; links in pages must start with BASE_PATH or be relative.
import http from "node:http";
import { openStore } from "./store.js";

const PORT = Number(process.env.PORT || 3000);
const BASE = process.env.BASE_PATH || "";
const store = openStore(process.env.DATA_DIR || "./.data");

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const CSS = `body{font:16px/1.5 system-ui,sans-serif;margin:0;padding:24px 16px;background:#f6f7f9;color:#15171a}
main{max-width:40rem;margin:auto}form{display:flex;gap:8px;margin:16px 0}input{flex:1;padding:8px;font:inherit}
button{padding:8px 14px;font:inherit}li{padding:4px 0}
@media (prefers-color-scheme:dark){body{background:#15171a;color:#e6e8eb}}`;

function page(items) {
  const form = store.writable
    ? `<form method="post" action="${BASE}/items"><input name="text" required maxlength="200" aria-label="New entry"><button>Add</button></form>`
    : "";
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{name}}</title><link rel="stylesheet" href="${BASE}/style.css">
<main><h1>{{name}}</h1>${form}<ul>${items.map((i) => `<li>${esc(i.text)}</li>`).join("")}</ul></main></html>`;
}

function readBody(req, limit = 10_000) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > limit) { reject(new Error("too large")); req.destroy(); }
    });
    req.on("end", () => resolve(data));
  });
}

export const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://app");
  try {
    if (url.pathname === "/health") return res.end("ok");
    if (url.pathname === "/style.css") {
      res.setHeader("content-type", "text/css");
      return res.end(CSS);
    }
    if (url.pathname === "/" && req.method === "GET") {
      res.setHeader("content-type", "text/html; charset=utf-8");
      return res.end(page(store.list()));
    }
    if (url.pathname === "/items" && req.method === "POST" && store.writable) {
      const text = new URLSearchParams(await readBody(req)).get("text")?.trim();
      if (text) store.add(text.slice(0, 200));
      res.writeHead(303, { location: `${BASE}/` });
      return res.end();
    }
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
  } catch {
    res.writeHead(400, { "content-type": "text/plain" });
    res.end("bad request");
  }
});

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  server.listen(PORT, "127.0.0.1");
}
