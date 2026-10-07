#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=42"]
# ///
"""orch-apps: publish a ticket's web artifact as a share, or a mini app as a permanent app, on your orch-apps host.

Shares
  orch-apps share <file|folder> --ticket INT-1 --access public|secret|sealed --expires 1d|7d|30d|done
  orch-apps publish <id> [--hold]        upload a staged share; prints the link once (or keeps it for `reveal`)
  orch-apps reveal <id>                  print a held link once, then forget its key or token
  orch-apps staged                       shares staged here and not yet published or revealed
  orch-apps discard <id>                 drop a staged share that is not published
  orch-apps revoke <id> | extend <id> --expires 7d|<ISO>|none
Apps
  orch-apps new <slug> --stack static|python|node --store sqlite|json|markdown|none
  orch-apps test <slug>                  run it the way the host does and check it
  orch-apps deploy <slug> --ticket INT-1 [--access public|secret]
  orch-apps start|stop|restart|delete|logs <slug>
Both
  orch-apps status [--json]              orch-apps setup --ssh orch-apps@host --domain app.example.com

Nothing here holds a server secret: the SSH key comes from your SSH agent or SSH config. Keys and tokens of shares
live only in the stage folder (~/.local/state/orch-apps/stage, mode 0700) until their link has been shown once.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import http.client
import http.server
import json
import mimetypes
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEMPLATES = HERE / "templates"
STATE = Path(os.environ.get("ORCH_APPS_STATE") or Path.home() / ".local" / "state" / "orch-apps")
CONFIG = Path(os.environ.get("ORCH_APPS_CONFIG") or Path.home() / ".config" / "orch-apps" / "config.toml")

SLUG = re.compile(r"[a-z][a-z0-9-]{1,28}")
RESERVED = frozenset({"s", "admin", "api", "health", "static", "assets", "_auth"})
TICKET = re.compile(r"[A-Z][A-Z0-9]{0,9}-\d{1,6}")
SHARE_ID = re.compile(r"[a-z0-9]{6,16}")
STACKS = ("static", "python", "node")
STORES = ("sqlite", "json", "markdown", "none")
STATIC_STORES = ("markdown", "none")
EXPIRES = {"1d": 1, "7d": 7, "30d": 30}
SEALED_WARN = 10_000_000
SEALED_MAX = 50_000_000
SKIP = (".venv", "node_modules", "__pycache__", ".pytest_cache", ".data", ".DS_Store", ".git")
HEALTH_SECONDS = 30

mimetypes.add_type("font/woff2", ".woff2")
mimetypes.add_type("font/woff", ".woff")
mimetypes.add_type("text/markdown", ".md")
mimetypes.add_type("image/svg+xml", ".svg")


class Refused(Exception):
    """Not allowed or not valid. Exit code 2."""


class Failed(Exception):
    """Valid, but did not work. Exit code 1."""


# -- small helpers --------------------------------------------------------------------------------------------------

def check(value: str, pattern: re.Pattern, what: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise Refused(f"invalid {what}: {value!r}")
    return value


def check_slug(slug: str) -> str:
    check(slug, SLUG, "slug (lowercase letters, digits and hyphens, 2 to 29 characters)")
    if slug in RESERVED or slug.endswith("-"):
        raise Refused(f"the slug {slug!r} is reserved or malformed")
    return slug


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def iso(t: dt.datetime) -> str:
    return t.isoformat().replace("+00:00", "Z")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def expiry(value: str) -> str:
    """1d/7d/30d → ISO time; done/none → none (the addon sets the time when the ticket is done); ISO passes."""
    if value in EXPIRES:
        return iso(now() + dt.timedelta(days=EXPIRES[value]))
    if value in ("done", "none"):
        return "none"
    try:
        t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Refused(f"expires must be 1d, 7d, 30d, done or an ISO time, not {value!r}") from None
    if t.tzinfo is None:
        raise Refused("an ISO expiry needs a time zone, for example 2026-10-14T18:00:00Z")
    return iso(t.astimezone(dt.timezone.utc))


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def write_private(path: Path, data: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# -- commands on this machine and the host --------------------------------------------------------------------------

def _run(argv: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, **kw)


runner = _run  # tests replace this


def run(argv: list[str], ok: bool = True, **kw) -> subprocess.CompletedProcess:
    try:
        res = runner(argv, **kw)
    except FileNotFoundError:
        raise Failed(f"{argv[0]} is not installed") from None
    if ok and res.returncode != 0:
        msg = (res.stderr or res.stdout or "").strip()
        raise Failed(msg or f"{argv[0]} exited with {res.returncode}")
    return res


def load_config() -> dict:
    try:
        cfg = tomllib.loads(CONFIG.read_text())
    except FileNotFoundError:
        raise Refused(f"no host set up yet: run `orch-apps setup --ssh orch-apps@<server> --domain <domain>` "
                      f"(writes {CONFIG})") from None
    for key in ("ssh", "domain"):
        if not isinstance(cfg.get(key), str) or not cfg[key]:
            raise Refused(f"{CONFIG} needs {key}")
    return cfg


SSH_OPTIONS = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"]


def ssh_options(cfg: dict) -> list[str]:
    """BatchMode and a pinned host key always; a key file only when the config names one (a path, never a key)."""
    opts = list(SSH_OPTIONS)
    if cfg.get("identity_file"):
        opts += ["-o", "IdentitiesOnly=yes", "-i", str(Path(cfg["identity_file"]).expanduser())]
    return opts


def remote(cfg: dict, *words: str) -> subprocess.CompletedProcess:
    res = run(["ssh", *ssh_options(cfg), cfg["ssh"], *words], ok=False)
    if res.returncode == 2:
        raise Refused((res.stderr or "").strip().removeprefix("refused: ") or "the host refused the request")
    if res.returncode != 0:
        raise Failed((res.stderr or res.stdout or "").strip().removeprefix("failed: ") or "the host command failed")
    return res


def remote_json(cfg: dict, *words: str) -> dict:
    out = remote(cfg, *words).stdout
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        raise Failed(f"the host answered something that is not JSON: {out[:200]}") from None


def rsync(cfg: dict, src: Path, dest: str, stats: bool = False) -> dict:
    argv = ["rsync", "-rt", "--delete", "--chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r"]
    for name in SKIP:
        argv += ["--exclude", name]
    if stats:
        argv.append("--stats")
    argv += ["-e", " ".join(["ssh", *ssh_options(cfg)]), f"{src}/", f"{cfg['ssh']}:{dest}/"]
    res = run(argv)
    # GNU rsync and macOS's openrsync label their --stats differently
    labels = (("files", ("Number of files:",)),
              ("transferred", ("Number of regular files transferred:", "Number of files transferred:")),
              ("bytes_sent", ("Total bytes sent:", "Total sent:")))
    found = {}
    for line in (res.stdout or "").splitlines():
        for key, options in labels:
            for label in options:
                if line.startswith(label):
                    digits = re.match(r"[\d,.']+", line[len(label):].strip())
                    found[key] = int(re.sub(r"\D", "", digits.group(0))) if digits else 0
    return found


# -- packing a page into one file -----------------------------------------------------------------------------------

ATTR = re.compile(r"""([\w:-]+)(?:\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'>]+)))?""")
CSS_URL = re.compile(r"""url\(\s*(['"]?)([^'")]+)\1\s*\)""")
CSS_IMPORT = re.compile(r"""@import\s+(?:url\(\s*)?(['"])([^'"]+)\1\s*\)?\s*;""")


def _attrs(tag: str) -> dict:
    inner = re.sub(r"^<\s*[\w-]+|/?>$", "", tag)
    return {m.group(1).lower(): (m.group(3) or m.group(4) or m.group(5) or "") for m in ATTR.finditer(inner)}


def _set_attr(tag: str, name: str, value: str) -> str:
    pattern = re.compile(rf"""(\s{name}\s*=\s*)("[^"]*"|'[^']*'|[^\s"'>]+)""", re.I)
    return pattern.sub(lambda m: f'{m.group(1)}"{value}"', tag, count=1)


class Packer:
    """Inline every local resource of an HTML page (stylesheets, scripts, images, fonts, media) as data, so the page
    is one file. External resources are listed; links (<a href>) are navigation and stay as they are."""

    def __init__(self, base: Path):
        self.base = base.resolve()
        self.external: list[str] = []
        self.missing: list[str] = []
        self.used: set[Path] = set()

    def local(self, ref: str, rel_to: Path) -> Path | None:
        ref = ref.strip()
        if not ref or ref.startswith(("data:", "#", "mailto:", "tel:", "javascript:", "blob:")):
            return None
        if re.match(r"^([a-z][a-z0-9+.-]*:)?//", ref, re.I):
            self.external.append(ref)
            return None
        path = urllib.parse.unquote(ref.split("#")[0].split("?")[0])
        target = (self.base / path.lstrip("/")) if path.startswith("/") else (rel_to / path)
        target = target.resolve()
        if (self.base not in target.parents and target != self.base) or not target.is_file():
            self.missing.append(ref)
            return None
        self.used.add(target)
        return target

    def data_uri(self, path: Path) -> str:
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        return f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode()}"

    def css(self, text: str, rel_to: Path, depth: int = 0) -> str:
        def imp(m):
            p = self.local(m.group(2), rel_to)
            return self.css(p.read_text(errors="replace"), p.parent, depth + 1) if p and depth < 5 else m.group(0)

        def url(m):
            p = self.local(m.group(2), rel_to)
            return f'url("{self.data_uri(p)}")' if p else m.group(0)
        return CSS_URL.sub(url, CSS_IMPORT.sub(imp, text))

    def page(self, html_path: Path) -> str:
        html = html_path.read_text(errors="replace")
        folder = html_path.parent.resolve()

        def link(m):
            tag = m.group(0)
            a = _attrs(tag)
            rel = a.get("rel", "").lower()
            href = a.get("href", "")
            if "stylesheet" in rel:
                p = self.local(href, folder)
                return f"<style>{self.css(p.read_text(errors='replace'), p.parent)}</style>" if p else tag
            if any(r in rel for r in ("icon", "preload", "manifest")):
                p = self.local(href, folder)
                return _set_attr(tag, "href", self.data_uri(p)) if p else tag
            return tag

        def script(m):
            a = _attrs(m.group(1))
            p = self.local(a.get("src", ""), folder)
            if not p:
                return m.group(0)
            body = p.read_text(errors="replace").replace("</script", "<\\/script")
            keep = re.sub(r"""\s+src\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""", "", m.group(1), flags=re.I)
            return f"<script{keep}>{body}</script>"

        def media(m):
            tag = m.group(0)
            a = _attrs(tag)
            for name in ("src", "poster"):
                if name in a:
                    p = self.local(a[name], folder)
                    if p:
                        tag = _set_attr(tag, name, self.data_uri(p))
            if "srcset" in a:
                parts = []
                for item in a["srcset"].split(","):
                    bits = item.strip().split()
                    p = self.local(bits[0], folder) if bits else None
                    parts.append(" ".join([self.data_uri(p), *bits[1:]]) if p else item.strip())
                tag = _set_attr(tag, "srcset", ", ".join(parts))
            return tag

        for m in re.finditer(r"<a\b[^>]*>", html, flags=re.I):  # links stay links; report the ones that lead nowhere
            ref = _attrs(m.group(0)).get("href", "")
            if ref and not re.match(r"^([a-z][a-z0-9+.-]*:|//|#)", ref, re.I):
                target = (folder / urllib.parse.unquote(ref.split("#")[0].split("?")[0])).resolve()
                if not target.exists():
                    self.missing.append(ref)
        html = re.sub(r"<link\b[^>]*>", link, html, flags=re.I)
        html = re.sub(r"<script\b([^>]*\bsrc\s*=[^>]*)>\s*</script>", script, html, flags=re.I)
        html = re.sub(r"<(?:img|source|audio|video|track|input|embed)\b[^>]*>", media, html, flags=re.I)
        html = re.sub(r"(<style\b[^>]*>)(.*?)(</style>)", lambda m: m.group(1) + self.css(m.group(2), folder) + m.group(3),
                      html, flags=re.I | re.S)
        html = re.sub(r"""(\sstyle\s*=\s*)(["'])(.*?)\2""", lambda m: m.group(1) + m.group(2) + self.css(m.group(3), folder)
                      + m.group(2), html, flags=re.I | re.S)
        return html


def seal(html: str, share_id: str) -> tuple[bytes, str]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    blob = b"OAS1" + nonce + AESGCM(key).encrypt(nonce, html.encode(), f"orch-apps:{share_id}".encode())
    return blob, b64url(key)


def unseal(blob: bytes, key: str, share_id: str) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
    if not blob.startswith(b"OAS1"):
        raise Refused("not an orch-apps sealed blob")
    return AESGCM(raw).decrypt(blob[4:16], blob[16:], f"orch-apps:{share_id}".encode()).decode()


# -- shares ---------------------------------------------------------------------------------------------------------

def stage_root() -> Path:
    return private_dir(STATE / "stage")


def _copy_tree(src: Path, dst: Path) -> tuple[int, int]:
    files = size = 0
    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src)
        if any(part in SKIP or part.startswith(".") for part in rel.parts) or path.is_symlink():
            continue
        if path.is_dir():
            (dst / rel).mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            (dst / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dst / rel)
            files += 1
            size += path.stat().st_size
    return files, size


def cmd_share(args) -> dict:
    check(args.ticket, TICKET, "ticket")
    src = Path(args.path).expanduser()
    if src.is_dir():
        html_path = src / "index.html"
        if not html_path.is_file():
            raise Refused(f"{src} has no index.html at its top")
    elif src.is_file() and src.suffix.lower() in (".html", ".htm"):
        html_path = src
    else:
        raise Refused(f"share an HTML file or a folder with index.html, not {src}")
    host_expires = expiry(args.expires)

    share_id = "".join(secrets.choice("abcdefghijkmnpqrstuvwxyz23456789") for _ in range(10))
    stage = private_dir(stage_root() / share_id)
    payload = stage / "payload"
    payload.mkdir()
    packer = Packer(html_path.parent)
    warnings: list[str] = []
    try:
        if args.access == "sealed":
            html = packer.page(html_path)
            if packer.external and not args.allow_external:
                raise Refused("a sealed page should not load anything from the internet, but this one loads:\n  "
                              + "\n  ".join(sorted(set(packer.external)))
                              + "\nInline them, or pass --allow-external to share it anyway (visitors' browsers "
                                "then fetch them; the page content stays sealed).")
            blob, secret = seal(html, share_id)
            if len(blob) > SEALED_MAX:
                raise Refused(f"the sealed page is {len(blob) // 1_000_000} MB; the limit is 50 MB")
            if len(blob) > SEALED_WARN:
                warnings.append(f"the sealed page is {len(blob) // 1_000_000} MB; it opens slowly on a phone")
            (payload / "sealed.bin").write_bytes(blob)
            files, size = 1, len(blob)
        else:
            if src.is_dir():
                files, size = _copy_tree(src, payload)
            else:  # one HTML file: take it as index.html, with the local files it uses
                packer.page(html_path)
                shutil.copy2(html_path, payload / "index.html")
                files, size = 1, html_path.stat().st_size
                for p in sorted(packer.used):
                    rel = p.relative_to(packer.base)
                    (payload / rel).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(p, payload / rel)
                    files += 1
                    size += p.stat().st_size
            secret = secrets.token_urlsafe(24) if args.access == "secret" else None
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    if packer.missing:
        warnings.append("not found next to the page, left as they are: " + ", ".join(sorted(set(packer.missing))))
    if packer.external and args.access != "sealed":
        warnings.append("loads from the internet: " + ", ".join(sorted(set(packer.external))))
    meta = {"id": share_id, "ticket": args.ticket, "access": args.access, "expires": host_expires,
            "expires_choice": args.expires, "source": str(src.resolve()), "files": files, "size": size,
            "staged": iso(now()), "warnings": warnings, "secret": secret, "published": None}
    write_private(stage / "meta.json", meta)
    return {**_public(meta), "next": f"orch-apps publish {share_id}"}


def _public(meta: dict) -> dict:
    return {k: v for k, v in meta.items() if k != "secret"}


def _stage(share_id: str) -> tuple[Path, dict]:
    check(share_id, SHARE_ID, "share id")
    stage = STATE / "stage" / share_id
    try:
        return stage, json.loads((stage / "meta.json").read_text())
    except FileNotFoundError:
        raise Refused(f"nothing staged as {share_id} (orch-apps staged lists what is)") from None


def _link(cfg: dict, meta: dict) -> str:
    base = f"https://{cfg['domain']}/s/{meta['id']}"
    if meta["access"] == "secret":
        return f"{base}.{meta['secret']}/"
    if meta["access"] == "sealed":
        return f"{base}/#k={meta['secret']}"
    return f"{base}/"


def _forget(stage: Path, meta: dict) -> None:
    """The link has been shown: remember what was published, never the key or token."""
    record = STATE / "published.jsonl"
    with open(record, "a") as f:
        f.write(json.dumps({**_public(meta), "revealed": iso(now())}) + "\n")
    os.chmod(record, 0o600)
    shutil.rmtree(stage)


def cmd_publish(args) -> dict:
    cfg = load_config()
    stage, meta = _stage(args.id)
    if meta.get("published"):
        raise Refused(f"{args.id} is already published; show its link with orch-apps reveal {args.id}")
    rsync(cfg, stage / "payload", f"shares/{meta['id']}")
    words = ["share", "put", meta["id"], "--access", meta["access"], "--ticket", meta["ticket"],
             "--expires", meta["expires"]]
    if meta["access"] == "secret":
        words += ["--token-hash", hashlib.sha256(meta["secret"].encode()).hexdigest()]
    remote(cfg, *words)
    meta["published"] = iso(now())
    shutil.rmtree(stage / "payload")
    if args.hold:
        write_private(stage / "meta.json", meta)
        return {**_public(meta), "url": None, "next": f"orch-apps reveal {meta['id']}"}
    url = _link(cfg, meta)
    _forget(stage, meta)
    return {**_public(meta), "url": url}


def cmd_reveal(args) -> dict:
    cfg = load_config()
    stage, meta = _stage(args.id)
    if not meta.get("published"):
        raise Refused(f"{args.id} is not published yet: orch-apps publish {args.id}")
    url = _link(cfg, meta)
    _forget(stage, meta)
    return {**_public(meta), "url": url}


def cmd_discard(args) -> dict:
    """Drop a staged share that was not published (its key or token goes with it)."""
    stage, meta = _stage(args.id)
    if meta.get("published"):
        raise Refused(f"{args.id} is already published; revoke it with orch-apps revoke {args.id}")
    shutil.rmtree(stage)
    return {**_public(meta), "discarded": iso(now())}


def cmd_staged(args) -> dict:
    root = STATE / "stage"
    items = []
    if root.exists():
        for d in sorted(root.iterdir()):
            try:
                items.append(_public(json.loads((d / "meta.json").read_text())))
            except (FileNotFoundError, json.JSONDecodeError):
                continue
    return {"staged": items}


# -- apps: manifest, templates, test ---------------------------------------------------------------------------------

def apps_dir(args) -> Path:
    if getattr(args, "apps_dir", None):
        return Path(args.apps_dir).expanduser().resolve()
    if os.environ.get("ORCH_APPS_DIR"):
        return Path(os.environ["ORCH_APPS_DIR"]).expanduser().resolve()
    res = _run(["git", "rev-parse", "--show-toplevel"])
    if res.returncode != 0:
        raise Refused("not inside a git repository: pass --apps-dir or set ORCH_APPS_DIR")
    return Path(res.stdout.strip()) / "apps"


def load_manifest(app: Path) -> dict:
    try:
        man = tomllib.loads((app / "app.toml").read_text())
    except FileNotFoundError:
        raise Refused(f"{app}/app.toml is missing") from None
    except tomllib.TOMLDecodeError as e:
        raise Refused(f"app.toml: {e}") from None
    for key in ("name", "stack", "store"):
        if not isinstance(man.get(key), str) or not man[key].strip():
            raise Refused(f"app.toml needs {key}")
    if man["stack"] not in STACKS:
        raise Refused(f"app.toml: stack must be one of {', '.join(STACKS)}, not {man['stack']!r}")
    if man["store"] not in STORES:
        raise Refused(f"app.toml: store must be one of {', '.join(STORES)}, not {man['store']!r}")
    if man["stack"] == "static" and man["store"] not in STATIC_STORES:
        raise Refused("a static app can only use store markdown or none")
    if man["stack"] != "static" and (not isinstance(man.get("start"), str) or not man["start"].strip()):
        raise Refused("app.toml needs start, the command that runs the app")
    man.setdefault("health", "/health")
    if man["stack"] == "static" and not (app / "index.html").is_file():
        raise Refused("a static app needs index.html")
    return man


def cmd_new(args) -> dict:
    slug = check_slug(args.slug)
    if args.stack not in STACKS or args.store not in STORES:
        raise Refused(f"stack is one of {', '.join(STACKS)}; store one of {', '.join(STORES)}")
    if args.stack == "static" and args.store not in STATIC_STORES:
        raise Refused("a static app can only use store markdown or none; pick python or node for sqlite or json")
    dest = apps_dir(args) / slug
    if dest.exists():
        raise Refused(f"{dest} already exists")
    name = args.name or slug.replace("-", " ").title()
    words = {"{{slug}}": slug, "{{name}}": name, "{{store}}": args.store,
             "{{about}}": (args.about or f"{name}, a mini app").replace('"', "'")}

    def fill(src: Path, rel: Path):
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        text = src.read_text()
        for k, v in words.items():
            text = text.replace(k, v)
        target.write_text(text)

    for src in sorted((TEMPLATES / args.stack).rglob("*")):
        if src.is_file():
            fill(src, src.relative_to(TEMPLATES / args.stack))
    if args.stack == "static":
        if args.store == "markdown":
            for src in sorted((TEMPLATES / "static-markdown").rglob("*")):
                if src.is_file():
                    fill(src, src.relative_to(TEMPLATES / "static-markdown"))
            fill(TEMPLATES / "content" / "welcome.md", Path("content/welcome.md"))
    else:
        ext = "js" if args.stack == "node" else "py"
        fill(TEMPLATES / f"{args.stack}-stores" / f"{args.store}.{ext}", Path(f"store.{ext}"))
        if args.store == "markdown":
            fill(TEMPLATES / "content" / "welcome.md", Path("content/welcome.md"))
    if args.stack == "python":
        run(["uv", "lock", "--quiet"], cwd=dest)
    return {"slug": slug, "path": str(dest), "stack": args.stack, "store": args.store,
            "next": f"orch-apps test {slug}"}


class _Front(http.server.ThreadingHTTPServer):
    daemon_threads = True


def _front(app: Path, slug: str, man: dict, port: int) -> _Front:
    """What Caddy does on the host: /<slug> redirects, /<slug>/... loses its prefix and goes to the app (or, for a
    static app, to its files); everything else is 404."""
    prefix = f"/{slug}/"

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _answer(self):
            path = urllib.parse.urlsplit(self.path).path
            if path == f"/{slug}":
                self.send_response(308)
                self.send_header("Location", prefix)
                self.end_headers()
                return
            if not path.startswith(prefix):
                self.send_error(404)
                return
            rest = "/" + self.path[len(prefix):]
            if man["stack"] == "static":
                return self._file(urllib.parse.unquote(urllib.parse.urlsplit(rest).path))
            body = None
            if self.headers.get("Content-Length"):
                body = self.rfile.read(int(self.headers["Content-Length"]))
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                conn.request(self.command, rest, body=body,
                             headers={k: v for k, v in self.headers.items() if k.lower() != "host"})
                res = conn.getresponse()
                data = res.read()
            except OSError:
                self.send_error(502)
                return
            self.send_response(res.status)
            for k, v in res.getheaders():
                if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _file(self, rest: str):
            target = (app / rest.lstrip("/")).resolve()
            if app.resolve() not in target.parents and target != app.resolve():
                return self.send_error(404)
            if target.is_dir():
                target = target / "index.html"
            if not target.is_file():
                return self.send_error(404)
            data = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(target.name)[0] or "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = _answer

    return _Front(("127.0.0.1", free_port()), H)


def _get(port: int, path: str) -> tuple[int, str, str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path)
        res = conn.getresponse()
        return res.status, res.getheader("Content-Type") or "", res.read().decode(errors="replace")
    except OSError:
        return 0, "", ""
    finally:
        conn.close()


def _env(app: Path, port: int, data_dir: Path, slug: str) -> dict:
    path = f"{app}/.venv/bin:{app}/node_modules/.bin:{os.environ.get('PATH', '/usr/bin:/bin')}"
    return {**os.environ, "PORT": str(port), "BASE_PATH": f"/{slug}", "DATA_DIR": str(data_dir),
            "APP_ENV": "local", "PATH": path, "VIRTUAL_ENV": str(app / ".venv")}


def _install_local(app: Path, man: dict) -> None:
    if man["stack"] == "node" and (app / "package.json").exists():
        if not (app / "package-lock.json").exists():
            raise Refused("package.json needs a package-lock.json (run npm install once)")
        if not (app / "node_modules").exists() or \
                (app / "package-lock.json").stat().st_mtime > (app / "node_modules").stat().st_mtime:
            run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--silent"], cwd=app)
    if man["stack"] == "python" and (app / "pyproject.toml").exists():
        if not (app / "uv.lock").exists():
            raise Refused("pyproject.toml needs a uv.lock (run uv lock)")
        run(["uv", "sync", "--frozen", "--quiet", "--no-install-project"], cwd=app)


LINK = re.compile(r"""\b(href|src|action)\s*=\s*(["'])(.*?)\2""", re.I)


def run_checks(app: Path, slug: str, say=print) -> dict:
    man = load_manifest(app)
    say(f"ok   manifest: {man['name']} ({man['stack']}, {man['store']})")
    _install_local(app, man)
    results = {"slug": slug, "stack": man["stack"], "checks": []}
    app_port = free_port()
    with tempfile.TemporaryDirectory(prefix=f"orch-apps-{slug}-") as tmp:
        env = _env(app, app_port, Path(tmp), slug)
        if man.get("test"):
            res = subprocess.run(["/bin/sh", "-c", man["test"]], cwd=app, env=env, capture_output=True, text=True,
                                 timeout=300)
            if res.returncode != 0:
                tail = "\n".join((res.stdout + res.stderr).strip().splitlines()[-15:])
                raise Failed(f"unit tests failed ({man['test']}):\n{tail}")
            say(f"ok   unit tests: {man['test']}")
            results["checks"].append("unit tests")
        proc = None
        log = Path(tmp) / "app.log"
        if man["stack"] != "static":
            with open(log, "w") as out:
                proc = subprocess.Popen(["/bin/sh", "-c", f"exec {man['start']}"], cwd=app, env=env,
                                        stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
        front = _front(app, slug, man, app_port)
        threading.Thread(target=front.serve_forever, daemon=True).start()
        fport = front.server_address[1]
        try:
            if proc:
                deadline = time.monotonic() + HEALTH_SECONDS
                while True:
                    if proc.poll() is not None:
                        raise Failed(f"the app stopped right away (exit {proc.returncode}):\n"
                                     + "\n".join(log.read_text().strip().splitlines()[-10:]))
                    st, _, _ = _get(app_port, man["health"])
                    if st == 200:
                        break
                    if time.monotonic() > deadline:
                        raise Failed(f"{man['health']} did not answer 200 within {HEALTH_SECONDS} s "
                                     f"(last answer: {st or 'no connection'}); every app needs a health route")
                    time.sleep(0.3)
                say(f"ok   {man['health']} answers 200")
                st, _, _ = _get(fport, f"/{slug}{man['health']}")
                if st != 200:
                    raise Failed(f"/{slug}{man['health']} through the base path answered {st}")
            st, ctype, body = _get(fport, f"/{slug}/")
            if st != 200 or "html" not in ctype:
                raise Failed(f"the start page /{slug}/ answered {st} ({ctype or 'no content type'})")
            say(f"ok   start page /{slug}/ answers 200")
            outside, broken, checked = [], [], 0
            for attr, _, ref in LINK.findall(body):
                if not ref or ref.startswith(("#", "data:", "mailto:", "tel:", "javascript:")) or \
                        re.match(r"^([a-z]+:)?//", ref, re.I):
                    continue
                url = urllib.parse.urljoin(f"/{slug}/", ref)
                if not url.startswith(f"/{slug}/") and url != f"/{slug}":
                    outside.append(ref)
                    continue
                if attr.lower() == "action":
                    continue  # a form target is checked for its base path, not fetched
                checked += 1
                if _get(fport, url)[0] >= 400:
                    broken.append(ref)
            if outside:
                raise Failed("the start page links outside its base path /" + slug + "/: " + ", ".join(outside)
                             + "\n     build links from BASE_PATH or keep them relative")
            if broken:
                raise Failed("links on the start page do not load: " + ", ".join(broken))
            say(f"ok   {checked} link(s) on the start page load under /{slug}/")
            results["checks"] += ["health", "start page", "links"]
        finally:
            front.shutdown()
            front.server_close()
            if proc and proc.poll() is None:
                os.killpg(proc.pid, 15)
                try:
                    proc.wait(5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, 9)
    return results


def cmd_test(args) -> dict:
    slug = check_slug(args.slug)
    app = apps_dir(args) / slug
    if not app.is_dir():
        raise Refused(f"no app at {app} (orch-apps new {slug} --stack … --store …)")
    say = (lambda *_: None) if args.json else (lambda *a: print(*a, flush=True))
    res = run_checks(app, slug, say)
    return {**res, "result": "passed"}


# -- deploy and the pass-through commands ---------------------------------------------------------------------------

def _app_token_file(slug: str) -> Path:
    return private_dir(STATE / "apps") / f"{slug}.json"


def cmd_deploy(args) -> dict:
    cfg = load_config()
    slug = check_slug(args.slug)
    check(args.ticket, TICKET, "ticket")
    app = apps_dir(args) / slug
    if not app.is_dir():
        raise Refused(f"no app at {app}")
    say = (lambda *_: None) if args.json else (lambda *a: print(*a, flush=True))
    try:
        run_checks(app, slug, say)
    except (Refused, Failed) as e:
        raise Refused(f"orch-apps test {slug} failed, so nothing was deployed:\n{e}") from None
    stats = rsync(cfg, app, f"apps/{slug}", stats=True)
    say(f"ok   upload: {stats.get('transferred', '?')} of {stats.get('files', '?')} files sent")
    words = ["app", "deploy", slug, "--ticket", args.ticket, "--access", args.access]
    token = None
    if args.access == "secret":
        tf = _app_token_file(slug)
        known = json.loads(tf.read_text()) if tf.exists() else {}
        if args.new_token or not known.get("token_hash"):
            token = secrets.token_urlsafe(24)
            known = {"token_hash": hashlib.sha256(token.encode()).hexdigest()}
        words += ["--token-hash", known["token_hash"]]
    res = remote_json(cfg, *words)
    if token:
        write_private(_app_token_file(slug), known)
    url = f"https://{cfg['domain']}/{slug}/"
    out = {**res, "upload": stats, "url": url}
    if token:
        out["secret_url"] = f"https://{cfg['domain']}/{slug}.{token}/"
        out["note"] = "shown once: the secret link opens the app and sets its cookie; orch-apps keeps only its hash"
    return out


def cmd_passthrough(args) -> dict | str:
    cfg = load_config()
    if args.cmd in ("revoke", "extend"):
        check(args.id, SHARE_ID, "share id")
        words = ["share", args.cmd, args.id]
        if args.cmd == "extend":
            words += ["--expires", expiry(args.expires)]
        return remote_json(cfg, *words)
    slug = check_slug(args.slug)
    if args.cmd == "logs":
        return remote(cfg, "app", "logs", slug, "--lines", str(args.lines)).stdout
    return remote_json(cfg, "app", args.cmd, slug)


def cmd_status(args) -> dict:
    cfg = load_config()
    return {**remote_json(cfg, "status", "--json"), "domain": cfg["domain"]}


def cmd_setup(args) -> dict:
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*@[A-Za-z0-9.-]+", args.ssh):
        raise Refused("--ssh is user@host, for example orch-apps@tix.severin.io")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", args.domain):
        raise Refused("--domain is a host name, for example app.severin.io")
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    key_line = ""
    if args.identity_file:
        key = Path(args.identity_file).expanduser()
        if not key.is_file() or " " in str(key):
            raise Refused(f"--identity-file must be an existing key file without spaces in its path: {key}")
        key_line = f'identity_file = "{key}"\n'
    CONFIG.write_text(f'# orch-apps: where shares and apps go. No secrets here: the SSH key comes from your agent,\n'
                      f'# or from identity_file (a path to a key file, never the key itself).\n'
                      f'ssh = "{args.ssh}"\ndomain = "{args.domain}"\n{key_line}')
    return {"config": str(CONFIG), "ssh": args.ssh, "domain": args.domain, "identity_file": args.identity_file}


# -- output ---------------------------------------------------------------------------------------------------------

def human(cmd: str, res) -> str:
    if isinstance(res, str):
        return res.rstrip("\n")
    if cmd == "share":
        lines = [f"staged {res['id']}: {res['access']}, {res['files']} file(s), {res['size']:,} bytes, "
                 f"expires {res['expires_choice']}. Nothing is uploaded yet."]
        lines += [f"note: {w}" for w in res["warnings"]]
        lines.append(f"publish it with: {res['next']}")
        return "\n".join(lines)
    if cmd in ("publish", "reveal"):
        if not res.get("url"):
            return f"published {res['id']}. Show its link once with: {res['next']}"
        tail = "" if res["access"] == "public" else "\nThis link is shown once; orch-apps does not keep its key or token."
        return f"{res['url']}{tail}"
    if cmd == "discard":
        return f"discarded {res['id']}; nothing was uploaded"
    if cmd == "staged":
        if not res["staged"]:
            return "nothing staged"
        return "\n".join(f"{s['id']}  {s['access']:<7} {s['ticket']:<10} "
                         f"{'published, link not shown yet' if s['published'] else 'staged'}" for s in res["staged"])
    if cmd == "new":
        return f"created {res['path']} ({res['stack']}, {res['store']}). Next: {res['next']}"
    if cmd == "test":
        return f"passed: {res['slug']} works like it will on the host"
    if cmd == "deploy":
        health = ("health check on the host passed, running" if res.get("status") == "running"
                  else "unchanged, still running" if res.get("result") == "unchanged" else res.get("status", ""))
        lines = [f"{res.get('result')} {res['slug']} {res.get('version', '')}: {health}", f"open {res['url']}"]
        if res.get("secret_url"):
            lines.append(f"secret link (shown once): {res['secret_url']}")
        return "\n".join(lines)
    if cmd == "status":
        lines = [f"{res['host']} at {res['at']}"]
        for a in res["apps"]:
            mem = f"{a['memory_bytes'] // 1_000_000} MB" if a.get("memory_bytes") else "-"
            lines.append(f"app   {a['slug']:<20} {a['status']:<8} {a.get('stack', ''):<7} {mem:>7}  {a.get('ticket', '')}")
        for s in res["shares"]:
            lines.append(f"share {s['id']:<20} {s['state']:<8} {s['access']:<7} {s['views']:>5} views  {s['ticket']}"
                         f"  ends {s.get('expires') or 'when its ticket is done'}")
        return "\n".join(lines)
    return json.dumps(res, indent=2, sort_keys=True)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="orch-apps", description=__doc__.split("\n")[0], allow_abbrev=False,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("share", help="stage a page or folder as a share (uploads nothing)", allow_abbrev=False)
    s.add_argument("path")
    s.add_argument("--ticket", required=True)
    s.add_argument("--access", required=True, choices=("public", "secret", "sealed"))
    s.add_argument("--expires", default="7d", help="1d, 7d, 30d or done (7 days after the ticket is done)")
    s.add_argument("--allow-external", action="store_true", help="sealed: allow resources from the internet")
    pub = sub.add_parser("publish", help="upload a staged share", allow_abbrev=False)
    pub.add_argument("id")
    pub.add_argument("--hold", action="store_true", help="do not print the link now; show it once with reveal")
    sub.add_parser("reveal", help="print a published share's link once", allow_abbrev=False).add_argument("id")
    sub.add_parser("staged", help="list staged shares", allow_abbrev=False)
    sub.add_parser("discard", help="drop a staged share that is not published", allow_abbrev=False).add_argument("id")
    sub.add_parser("revoke", help="end a share now", allow_abbrev=False).add_argument("id")
    ext = sub.add_parser("extend", help="change when a share ends", allow_abbrev=False)
    ext.add_argument("id")
    ext.add_argument("--expires", required=True, help="1d, 7d, 30d, none or an ISO time")

    for name, helptext in (("new", "scaffold apps/<slug>/"), ("test", "check an app like the host runs it"),
                           ("deploy", "test, upload and deploy an app")):
        a = sub.add_parser(name, help=helptext, allow_abbrev=False)
        a.add_argument("slug")
        a.add_argument("--apps-dir", help="default: apps/ at the top of this git repository")
        if name == "new":
            a.add_argument("--stack", required=True, choices=STACKS)
            a.add_argument("--store", required=True, choices=STORES)
            a.add_argument("--name")
            a.add_argument("--about")
        if name == "deploy":
            a.add_argument("--ticket", required=True)
            a.add_argument("--access", default="public", choices=("public", "secret"))
            a.add_argument("--new-token", action="store_true", help="secret: make a new secret link")
    for name in ("start", "stop", "restart", "delete"):
        sub.add_parser(name, help=f"{name} an app on the host", allow_abbrev=False).add_argument("slug")
    lg = sub.add_parser("logs", help="recent log lines of an app", allow_abbrev=False)
    lg.add_argument("slug")
    lg.add_argument("--lines", type=int, default=100)
    sub.add_parser("status", help="apps and shares on the host", allow_abbrev=False)
    st = sub.add_parser("setup", help="set the host this machine publishes to", allow_abbrev=False)
    st.add_argument("--ssh", required=True)
    st.add_argument("--domain", required=True)
    st.add_argument("--identity-file", help="SSH key file to use instead of the agent (a path only)")
    for sp in sub.choices.values():
        sp.add_argument("--json", action="store_true", help="machine-readable output")
    return p


COMMANDS = {"share": cmd_share, "publish": cmd_publish, "reveal": cmd_reveal, "staged": cmd_staged, "discard": cmd_discard,
            "new": cmd_new, "test": cmd_test, "deploy": cmd_deploy, "status": cmd_status, "setup": cmd_setup}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    fn = COMMANDS.get(args.cmd, cmd_passthrough)
    try:
        res = fn(args)
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    except Failed as e:
        print(f"failed: {e}", file=sys.stderr)
        return 1
    if args.json:
        print(res if isinstance(res, str) else json.dumps(res, indent=2, sort_keys=True))
    else:
        print(human(args.cmd, res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
