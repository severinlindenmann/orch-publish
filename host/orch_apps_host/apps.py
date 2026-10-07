"""Permanent apps: releases, dependencies, one systemd service each, health check and rollback.

Layout per app under /srv/orch-apps/apps/<slug>/:
  releases/<version>/   the uploaded code, world-readable, version = hash of the files
  current -> releases/<version>
  run.sh, env           generated; the systemd unit orch-app@<slug> runs run.sh with env
Dependencies live in /srv/orch-apps/deps/<slug>/<lockfile hash>/ and are linked into the release, so a deploy that
does not change the lockfile installs nothing.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import time
import tomllib
from pathlib import Path

from . import caddy, util
from .util import Failed, Refused

STACKS = ("static", "python", "node")
STORES = ("sqlite", "json", "markdown", "none")
ACCESS = ("public", "secret")
MAX_APP_BYTES = 50_000_000
FIRST_PORT = 4201
HEALTH_SECONDS = 30
KEEP_RELEASES = 2


# -- state ------------------------------------------------------------------------------------------------------

def load_state() -> dict:
    return util.read_json(util.P.apps_file, {"apps": {}})


def save_state(st: dict) -> None:
    # The share server reads token hashes from here to let secret-link visitors in.
    util.write_json(util.P.apps_file, st, group=util.P.web_group)


def _need(st: dict, slug: str) -> dict:
    app = st["apps"].get(util.check_slug(slug))
    if not app:
        raise Refused(f"no app {slug}")
    return app


def _port(st: dict) -> int:
    used = {a["port"] for a in st["apps"].values() if a.get("port")}
    p = FIRST_PORT
    while p in used:
        p += 1
    return p


# -- manifest ---------------------------------------------------------------------------------------------------

def load_manifest(top: Path, upload: bool = True) -> dict:
    try:
        man = tomllib.loads((top / "app.toml").read_text())
    except FileNotFoundError:
        raise Refused("app.toml is missing") from None
    except tomllib.TOMLDecodeError as e:
        raise Refused(f"app.toml: {e}") from None
    for key in ("name", "stack", "store"):
        if not isinstance(man.get(key), str) or not man[key].strip():
            raise Refused(f"app.toml needs {key}")
    if man["stack"] not in STACKS:
        raise Refused(f"app.toml: stack must be one of {', '.join(STACKS)}")
    if man["store"] not in STORES:
        raise Refused(f"app.toml: store must be one of {', '.join(STORES)}")
    if man["stack"] != "static":
        start = man.get("start")
        if not isinstance(start, str) or not start.strip() or "\n" in start or "\0" in start:
            raise Refused("app.toml needs start, one line")
    health = man.get("health", "/health")
    if not isinstance(health, str) or not health.startswith("/") or any(c in health for c in " \n\0"):
        raise Refused("app.toml: health must be a path like /health")
    man["health"] = health
    if man["stack"] == "static" and not (top / "index.html").is_file():
        raise Refused("a static app needs index.html")
    for forbidden in ("node_modules", ".venv") if upload else ():
        if (top / forbidden).exists() or (top / forbidden).is_symlink():
            raise Refused(f"do not upload {forbidden}; the host installs dependencies")
    return man


# -- dependencies -----------------------------------------------------------------------------------------------

def _lock_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def install_deps(slug: str, man: dict, rel: Path) -> str | None:
    """Install dependencies for this lockfile once; link them into the release. No package code runs: npm with
    --ignore-scripts, uv with --no-build (wheels only)."""
    if man["stack"] == "node" and (rel / "package.json").exists():
        lock = rel / "package-lock.json"
        if not lock.exists():
            raise Refused("a node app with package.json needs package-lock.json")
        h = _lock_hash(lock)
        d = util.P.deps / slug / h
        if not (d / "node_modules").exists():
            shutil.rmtree(d, ignore_errors=True)
            d.mkdir(parents=True)
            shutil.copy(rel / "package.json", d)
            shutil.copy(lock, d)
            util.run(["npm", "ci", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=d,
                     env={**_base_env(), "npm_config_cache": str(util.P.cache / "npm")}, timeout=300)
            util.tree_perms(d, 0o755, 0o644)
        (rel / "node_modules").symlink_to(d / "node_modules")
        return h
    if man["stack"] == "python" and (rel / "pyproject.toml").exists():
        lock = rel / "uv.lock"
        if not lock.exists():
            raise Refused("a python app with pyproject.toml needs uv.lock")
        h = _lock_hash(lock)
        d = util.P.deps / slug / h
        if not (d / "venv").exists():
            shutil.rmtree(d, ignore_errors=True)
            d.mkdir(parents=True)
            util.run(["uv", "sync", "--frozen", "--no-dev", "--no-build", "--no-install-project"], cwd=rel,
                     env={**_base_env(), "UV_PROJECT_ENVIRONMENT": str(d / "venv"),
                          "UV_CACHE_DIR": str(util.P.cache / "uv"), "UV_PYTHON_DOWNLOADS": "never",
                          "UV_PYTHON": "/usr/bin/python3"}, timeout=300)
            util.tree_perms(d, 0o755, 0o644)
        (rel / ".venv").symlink_to(d / "venv")
        return h
    return None


def _base_env() -> dict:
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(util.P.cache), "LANG": "C.UTF-8"}


# -- runtime files ----------------------------------------------------------------------------------------------

def _write_runtime(slug: str, man: dict, port: int) -> None:
    base = util.P.apps / slug
    cur = base / "current"
    (base / "env").write_text(
        f"PORT={port}\nBASE_PATH=/{slug}\nDATA_DIR=/var/lib/orch-apps-data/{slug}\nAPP_ENV=prod\n"
        f"HOME=/tmp\nLANG=C.UTF-8\n")
    if man["stack"] != "static":
        (base / "run.sh").write_text(
            "#!/bin/sh\n# generated by orch-apps-host from app.toml\n"
            f"cd {cur} || exit 1\n"
            f'export PATH="{cur}/.venv/bin:{cur}/node_modules/.bin:/usr/local/bin:/usr/bin:/bin"\n'
            f"exec {man['start']}\n")
        os.chmod(base / "run.sh", 0o755)
    os.chmod(base / "env", 0o644)


def _healthy(slug: str, man: dict, port: int) -> bool:
    if man["stack"] == "static":
        return (util.P.apps / slug / "current" / "index.html").is_file()
    deadline = time.monotonic() + HEALTH_SECONDS
    while time.monotonic() < deadline:
        if util.http_ok(f"http://127.0.0.1:{port}{man['health']}"):
            return True
        time.sleep(0.5)
    return False


def _unit(slug: str) -> str:
    return f"orch-app@{slug}.service"


# -- commands ---------------------------------------------------------------------------------------------------

def deploy(slug: str, ticket: str, access: str, token_hash: str | None = None) -> dict:
    util.check_slug(slug)
    util.check(ticket, util.TICKET, "ticket")
    if access not in ACCESS:
        raise Refused(f"invalid access: {access!r}")
    if access == "secret":
        util.check(token_hash or "", util.TOKEN_HASH, "token hash")
    elif token_hash:
        raise Refused("a token hash is only for secret apps")

    src = util.P.incoming / "apps" / slug
    if not src.is_dir():
        raise Refused(f"upload not found: apps/{slug}")
    man = load_manifest(src)
    version = util.tree_hash(src)[:12]

    st = load_state()
    app = st["apps"].get(slug) or {"slug": slug, "status": "new"}
    if not app.get("port") and man["stack"] != "static":
        app["port"] = _port(st)
    unchanged = (app.get("version") == version and app.get("status") == "running"
                 and app.get("access") == access and app.get("token_hash") == token_hash)
    if unchanged:
        return {"slug": slug, "result": "unchanged", "version": version}

    base = util.P.apps / slug
    rel = base / "releases" / version
    if not rel.exists():
        tmp = base / "releases" / f".{version}.new"
        shutil.rmtree(tmp, ignore_errors=True)
        (base / "releases").mkdir(parents=True, exist_ok=True)
        try:
            util.copy_tree_safe(src, tmp, MAX_APP_BYTES)
            util.tree_perms(tmp, 0o755, 0o644)
            install_deps(slug, man, tmp)
            tmp.rename(rel)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
    os.chmod(base, 0o755)
    os.chmod(base / "releases", 0o755)

    cur = base / "current"
    previous = os.readlink(cur) if cur.is_symlink() else None
    prev_app = dict(app)
    util.swap_symlink(cur, rel)
    _write_runtime(slug, man, app.get("port", 0))
    app.update({"name": man["name"], "stack": man["stack"], "store": man["store"], "access": access,
                "ticket": ticket, "health": man["health"], "held": False})
    if token_hash:
        app["token_hash"] = token_hash
    else:
        app.pop("token_hash", None)

    try:
        caddy.apply(slug, caddy.snippet(slug, app))
    except Failed:
        if previous:
            util.swap_symlink(cur, Path(previous))
        raise
    if man["stack"] != "static":
        util.run(["systemctl", "enable", _unit(slug)])
        util.run(["systemctl", "restart", _unit(slug)])

    if _healthy(slug, man, app.get("port", 0)):
        app.update({"status": "running", "version": version, "deployed_at": util.iso(util.now()), "message": None})
        st["apps"][slug] = app
        save_state(st)
        _prune(slug, rel)
        return {"slug": slug, "result": "deployed", "version": version, "status": "running"}

    # roll back to the release that served before
    failed = f"health {man['health']} did not answer 2xx within {HEALTH_SECONDS} s"
    if previous and prev_app.get("version"):
        util.swap_symlink(cur, Path(previous))
        prev_man = load_manifest(Path(previous), upload=False)
        _write_runtime(slug, prev_man, prev_app.get("port", 0))
        caddy.apply(slug, caddy.snippet(slug, {**prev_app, "held": False}))
        if prev_man["stack"] != "static":
            util.run(["systemctl", "restart", _unit(slug)], ok=False)
        back = _healthy(slug, prev_man, prev_app.get("port", 0))
        app = {**prev_app, "status": "failed" if not back else "running",
               "message": f"deploy of {version} failed ({failed}); "
                          + (f"{prev_app['version']} is serving again" if back else "rollback also unhealthy"),
               "failed_version": version}
    else:
        if man["stack"] != "static":
            util.run(["systemctl", "stop", _unit(slug)], ok=False)
        app.update({"status": "failed", "message": f"first deploy of {version} failed ({failed})",
                    "failed_version": version})
    st["apps"][slug] = app
    save_state(st)
    raise Failed(f"{slug}: {app['message']}")


def _prune(slug: str, keep: Path) -> None:
    rels = util.P.apps / slug / "releases"
    others = sorted((p for p in rels.iterdir() if p.is_dir() and not p.name.startswith(".") and p != keep),
                    key=lambda p: p.stat().st_mtime, reverse=True)
    used_deps = set()
    for old in others[KEEP_RELEASES - 1:]:
        shutil.rmtree(old)
    for r in [keep, *others[:KEEP_RELEASES - 1]]:
        for link in (r / "node_modules", r / ".venv"):
            if link.is_symlink():
                used_deps.add(Path(os.readlink(link)).parent)
    deps = util.P.deps / slug
    if deps.exists():
        for d in deps.iterdir():
            if d not in used_deps:
                shutil.rmtree(d)


def start(slug: str) -> dict:
    st = load_state()
    app = _need(st, slug)
    app["held"] = False
    caddy.apply(slug, caddy.snippet(slug, app))
    if app["stack"] != "static":
        util.run(["systemctl", "enable", _unit(slug)])
        util.run(["systemctl", "start", _unit(slug)])
    app["status"] = "running"
    save_state(st)
    return {"slug": slug, "status": "running"}


def stop(slug: str) -> dict:
    st = load_state()
    app = _need(st, slug)
    app["held"] = True
    if app["stack"] != "static":
        util.run(["systemctl", "disable", "--now", _unit(slug)])
    caddy.apply(slug, caddy.snippet(slug, app))
    app["status"] = "stopped"
    save_state(st)
    return {"slug": slug, "status": "stopped"}


def restart(slug: str) -> dict:
    st = load_state()
    app = _need(st, slug)
    if app["stack"] == "static":
        raise Refused("a static app has no process to restart")
    if app.get("held"):
        raise Refused(f"{slug} is stopped; start it instead")
    util.run(["systemctl", "restart", _unit(slug)])
    return {"slug": slug, "status": "restarted"}


def delete(slug: str) -> dict:
    st = load_state()
    app = _need(st, slug)
    if app["stack"] != "static":
        util.run(["systemctl", "disable", "--now", _unit(slug)], ok=False)
    caddy.apply(slug, None)
    stamp = util.now().strftime("%Y%m%d-%H%M%S")
    data = util.P.data / slug
    util.P.archive.mkdir(parents=True, exist_ok=True)
    archived = None
    if data.exists():
        archived = util.P.archive / f"{slug}-data-{stamp}"
        shutil.move(str(data), archived)
    shutil.rmtree(util.P.apps / slug, ignore_errors=True)
    shutil.rmtree(util.P.deps / slug, ignore_errors=True)
    del st["apps"][slug]
    save_state(st)
    return {"slug": slug, "result": "deleted", "data_archived": str(archived) if archived else None}


def logs(slug: str, lines: int) -> str:
    _need(load_state(), slug)
    if not 1 <= lines <= 500:
        raise Refused("lines must be between 1 and 500")
    res = util.run(["journalctl", "-u", _unit(slug), "-n", str(lines), "--no-pager", "-o", "short-iso"], ok=False)
    return res.stdout


def _show(slug: str) -> dict:
    res = util.run(["systemctl", "show", _unit(slug), "--property=ActiveState,MemoryCurrent,ActiveEnterTimestamp"],
                   ok=False)
    props = dict(line.split("=", 1) for line in res.stdout.splitlines() if "=" in line)
    mem = props.get("MemoryCurrent", "")
    return {"active": props.get("ActiveState"), "memory_bytes": int(mem) if mem.isdigit() else None,
            "active_since": props.get("ActiveEnterTimestamp") or None}


def listing() -> list[dict]:
    out = []
    for slug, app in sorted(load_state()["apps"].items()):
        row = {k: v for k, v in app.items() if k != "token_hash"}
        if app.get("stack") != "static":
            row.update(_show(slug))
        row["data_bytes"] = util.dir_size(util.P.data / slug)
        out.append(row)
    return out
