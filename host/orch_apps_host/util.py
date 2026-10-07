"""Paths, validation, atomic JSON files, safe tree copies and the command runner, shared by every part of the host."""

from __future__ import annotations

import datetime as dt
import grp
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path


class Refused(Exception):
    """The request is not allowed or not valid. Exit code 2."""


class Failed(Exception):
    """The request was valid but did not work. Exit code 1."""


@dataclass(frozen=True)
class Paths:
    root: Path
    data: Path        # systemd StateDirectory of the apps (DynamicUser keeps it under /var/lib/private)
    web_state: Path   # the share server's own state (views, cookie secret)
    caddy: Path       # generated per-app snippets
    backups: Path
    web_group: str
    share_port: int

    @property
    def incoming(self) -> Path: return self.root / "incoming"
    @property
    def shares(self) -> Path: return self.root / "shares"
    @property
    def apps(self) -> Path: return self.root / "apps"
    @property
    def deps(self) -> Path: return self.root / "deps"
    @property
    def state(self) -> Path: return self.root / "state"
    @property
    def archive(self) -> Path: return self.root / "archive"
    @property
    def cache(self) -> Path: return self.root / "cache"
    @property
    def apps_file(self) -> Path: return self.state / "apps.json"


def paths_from_env() -> Paths:
    e = os.environ.get
    return Paths(
        root=Path(e("ORCH_APPS_ROOT", "/srv/orch-apps")),
        data=Path(e("ORCH_APPS_DATA", "/var/lib/private/orch-apps-data")),
        web_state=Path(e("ORCH_APPS_WEB_STATE", "/var/lib/orch-apps-web")),
        caddy=Path(e("ORCH_APPS_CADDY", "/etc/caddy/orch-apps")),
        backups=Path(e("ORCH_APPS_BACKUPS", "/var/backups/orch-apps")),
        web_group=e("ORCH_APPS_WEB_GROUP", "orch-apps-web"),
        share_port=int(e("ORCH_APPS_SHARE_PORT", "8790")),
    )


P = paths_from_env()


def configure(paths: Paths) -> None:
    """Tests point the host at temporary folders."""
    global P
    P = paths


# -- validation -------------------------------------------------------------------------------------------------

SLUG = re.compile(r"[a-z][a-z0-9-]{1,28}")  # at most 29, so the app's user oa-<slug> fits 32 characters
RESERVED = frozenset({"s", "admin", "api", "health", "static", "assets", "_auth"})
SHARE_ID = re.compile(r"[a-z0-9]{6,16}")
TOKEN = re.compile(r"[A-Za-z0-9_-]{16,64}")
TOKEN_HASH = re.compile(r"[0-9a-f]{64}")
TICKET = re.compile(r"[A-Z][A-Z0-9]{0,9}-\d{1,6}")


def check(value: str, pattern: re.Pattern, what: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise Refused(f"invalid {what}: {value!r}")
    return value


def check_slug(value: str) -> str:
    check(value, SLUG, "slug")
    if value in RESERVED or value.endswith("-"):
        raise Refused(f"slug {value!r} is reserved or malformed")
    return value


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def iso(t: dt.datetime | None) -> str | None:
    return t.isoformat().replace("+00:00", "Z") if t else None


def parse_time(value: str) -> dt.datetime:
    try:
        t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Refused(f"invalid time: {value!r}") from None
    if t.tzinfo is None:
        raise Refused(f"time needs a zone: {value!r}")
    return t.astimezone(dt.timezone.utc)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# -- files ------------------------------------------------------------------------------------------------------

def read_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default


def write_json(path: Path, data, mode: int = 0o640, group: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        os.chmod(tmp, mode)
        if group:
            set_group(Path(tmp), group)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def set_group(path: Path, group: str) -> None:
    """chgrp when the group exists (it does on the VPS; tests on a laptop skip it)."""
    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError:
        return
    os.chown(path, -1, gid, follow_symlinks=False)


def tree_perms(top: Path, dir_mode: int, file_mode: int, group: str | None = None) -> None:
    for dirpath, dirnames, filenames in os.walk(top):
        d = Path(dirpath)
        os.chmod(d, dir_mode)
        if group:
            set_group(d, group)
        for name in filenames:
            f = d / name
            executable = os.lstat(f).st_mode & 0o100
            os.chmod(f, file_mode | (dir_mode & 0o111 if executable else 0))
            if group:
                set_group(f, group)


def copy_tree_safe(src: Path, dst: Path, max_bytes: int) -> tuple[int, int]:
    """Copy regular files and folders only. The upload folder is writable by the deploy user, so a symlink, a hard
    link or a device there could make root copy something it should not: all of those are refused."""
    if not src.is_dir() or src.is_symlink():
        raise Refused(f"upload not found: {src.name}")
    files = total = 0
    dst.mkdir(parents=True)
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        rel = Path(dirpath).relative_to(src)
        for name in dirnames:
            if (Path(dirpath) / name).is_symlink():
                raise Refused(f"symlink not allowed: {rel / name}")
            (dst / rel / name).mkdir()
        for name in filenames:
            path = Path(dirpath) / name
            st = os.lstat(path)
            if not stat.S_ISREG(st.st_mode):
                raise Refused(f"only regular files are allowed: {rel / name}")
            if st.st_nlink > 1:
                raise Refused(f"hard links are not allowed: {rel / name}")
            total += st.st_size
            files += 1
            if total > max_bytes:
                raise Refused(f"upload is larger than {max_bytes // 1_000_000} MB")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as fin, open(dst / rel / name, "xb") as fout:
                shutil.copyfileobj(fin, fout)
            if st.st_mode & 0o100:
                os.chmod(dst / rel / name, 0o755)
    return files, total


def tree_hash(top: Path, skip: frozenset[str] = frozenset()) -> str:
    h = hashlib.sha256()
    for path in sorted(p for p in top.rglob("*") if p.is_file() and not p.is_symlink()):
        rel = path.relative_to(top).as_posix()
        if rel.split("/")[0] in skip:
            continue
        h.update(rel.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    return h.hexdigest()


def dir_size(top: Path) -> int:
    if not top.exists():
        return 0
    return sum(p.lstat().st_size for p in top.rglob("*") if p.is_file() and not p.is_symlink())


def swap_symlink(link: Path, target: Path) -> None:
    tmp = link.with_name(f".{link.name}.new")
    tmp.unlink(missing_ok=True)
    tmp.symlink_to(target)
    os.replace(tmp, link)


# -- commands ---------------------------------------------------------------------------------------------------

def _subprocess_run(argv: list[str], *, cwd: Path | None = None, env: dict | None = None,
                    timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=cwd, env=env, timeout=timeout, capture_output=True, text=True)


runner = _subprocess_run  # tests replace this with a recorder


def run(argv: list[str], *, cwd: Path | None = None, env: dict | None = None, timeout: int = 120,
        ok: bool = True) -> subprocess.CompletedProcess:
    try:
        res = runner(argv, cwd=cwd, env=env, timeout=timeout)
    except FileNotFoundError:
        raise Failed(f"{argv[0]} is not installed") from None
    except subprocess.TimeoutExpired:
        raise Failed(f"{' '.join(argv[:3])} took longer than {timeout} s") from None
    if ok and res.returncode != 0:
        tail = (res.stderr or res.stdout or "").strip().splitlines()[-5:]
        raise Failed(f"{' '.join(argv[:3])} failed: " + " | ".join(tail))
    return res


def _http_ok(url: str, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


http_ok = _http_ok  # tests replace this
