"""{{name}}: a mini app on orch-apps (python, store {{store}}).

The host gives every app PORT, BASE_PATH (/{{slug}}), DATA_DIR (kept across deploys) and APP_ENV. Requests arrive
without the /{{slug}} prefix; links in pages must start with BASE_PATH or be relative.
"""

import html
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from store import open_store

BASE = os.environ.get("BASE_PATH", "")
STORE = open_store(os.environ.get("DATA_DIR", ".data"))

CSS = """body{font:16px/1.5 system-ui,sans-serif;margin:0;padding:24px 16px;background:#f6f7f9;color:#15171a}
main{max-width:40rem;margin:auto}form{display:flex;gap:8px;margin:16px 0}input{flex:1;padding:8px;font:inherit}
button{padding:8px 14px;font:inherit}li{padding:4px 0}
@media (prefers-color-scheme:dark){body{background:#15171a;color:#e6e8eb}}"""


def page(items) -> str:
    form = (f'<form method="post" action="{BASE}/items"><input name="text" required maxlength="200" '
            f'aria-label="New entry"><button>Add</button></form>') if STORE.writable else ""
    rows = "".join(f"<li>{html.escape(i['text'])}</li>" for i in items)
    return (f'<!doctype html><html lang="en"><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1"><title>{{name}}</title>'
            f'<link rel="stylesheet" href="{BASE}/style.css"><main><h1>{{name}}</h1>{form}<ul>{rows}</ul></main></html>')


class App(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, status: int, body: bytes = b"", ctype: str = "text/plain", headers: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/health":
            return self.send(200, b"ok")
        if path == "/style.css":
            return self.send(200, CSS.encode(), "text/css")
        if path == "/":
            return self.send(200, page(STORE.list()).encode(), "text/html; charset=utf-8")
        self.send(404, b"not found")

    def do_POST(self):
        if urllib.parse.urlsplit(self.path).path != "/items" or not STORE.writable:
            return self.send(404, b"not found")
        length = int(self.headers.get("Content-Length") or 0)
        if length > 10_000:
            return self.send(413, b"too large")
        text = urllib.parse.parse_qs(self.rfile.read(length).decode()).get("text", [""])[0].strip()
        if text:
            STORE.add(text[:200])
        self.send(303, headers={"Location": f"{BASE}/"})


def make_server(port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), App)


if __name__ == "__main__":
    make_server(int(os.environ.get("PORT", "8000"))).serve_forever()
