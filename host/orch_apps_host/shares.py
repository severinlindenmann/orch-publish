"""Shares: static files or one sealed blob under /srv/orch-apps/shares/<id>/, with a meta.json the share server reads.

An expired or revoked share keeps its meta.json as a tombstone, so the share server answers 410 instead of 404;
its files are removed by the next sweep (revoke removes them at once).
"""

from __future__ import annotations

import shutil

from . import util
from .util import Refused

MAX_SHARE_BYTES = 50_000_000
SEALED_MAGIC = b"OAS1"
ACCESS = ("public", "secret", "sealed")
TOMBSTONE_DAYS = 30


def _dir(share_id: str):
    return util.P.shares / util.check(share_id, util.SHARE_ID, "share id")


def read_meta(share_id: str) -> dict | None:
    return util.read_json(_dir(share_id) / "meta.json", None)


def state_of(meta: dict) -> str:
    if meta.get("revoked"):
        return "revoked"
    exp = meta.get("expires")
    if exp and util.parse_time(exp) <= util.now():
        return "expired"
    return "live"


def put(share_id: str, access: str, ticket: str, expires: str | None, token_hash: str | None = None) -> dict:
    util.check(ticket, util.TICKET, "ticket")
    if access not in ACCESS:
        raise Refused(f"invalid access: {access!r}")
    if access == "secret":
        util.check(token_hash or "", util.TOKEN_HASH, "token hash")
    elif token_hash:
        raise Refused("a token hash is only for secret shares")
    exp = _expiry(expires)
    if exp and util.parse_time(exp) <= util.now():
        raise Refused("expiry is in the past")

    dst = _dir(share_id)
    old = read_meta(share_id)
    if old and state_of(old) == "live":
        raise Refused(f"share {share_id} already exists")
    src = util.P.incoming / "shares" / share_id
    tmp = util.P.shares / f".{share_id}.new"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    try:
        files, size = util.copy_tree_safe(src, tmp / "files", MAX_SHARE_BYTES)
        _check_content(tmp / "files", access)
        meta = {
            "id": share_id, "access": access, "ticket": ticket, "created": util.iso(util.now()),
            "expires": exp, "revoked": None, "files": files, "size": size,
        }
        if token_hash:
            meta["token_hash"] = token_hash
        util.write_json(tmp / "meta.json", meta, group=util.P.web_group)
        util.tree_perms(tmp, 0o750, 0o640, util.P.web_group)
        if dst.exists():
            shutil.rmtree(dst)
        tmp.rename(dst)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    shutil.rmtree(src, ignore_errors=True)
    return public_meta(meta)


def _check_content(files, access: str) -> None:
    names = sorted(p.relative_to(files).as_posix() for p in files.rglob("*") if p.is_file())
    if access == "sealed":
        if names != ["sealed.bin"]:
            raise Refused("a sealed share is exactly one file, sealed.bin")
        blob = (files / "sealed.bin").read_bytes()
        if not blob.startswith(SEALED_MAGIC) or len(blob) < len(SEALED_MAGIC) + 12 + 16:
            raise Refused("sealed.bin is not an orch-apps sealed blob")
    elif "index.html" not in names:
        raise Refused("a share needs an index.html at its top")


def _expiry(value: str | None) -> str | None:
    return None if value in (None, "", "none") else util.iso(util.parse_time(value))


def revoke(share_id: str) -> dict:
    meta = _need(share_id)
    if not meta.get("revoked"):
        meta["revoked"] = util.iso(util.now())
        util.write_json(_dir(share_id) / "meta.json", meta, group=util.P.web_group)
    shutil.rmtree(_dir(share_id) / "files", ignore_errors=True)
    return public_meta(meta)


def extend(share_id: str, expires: str | None) -> dict:
    meta = _need(share_id)
    if state_of(meta) == "revoked":
        raise Refused(f"share {share_id} is revoked")
    if not (_dir(share_id) / "files").exists():
        raise Refused(f"share {share_id} has expired and its files are gone")
    meta["expires"] = _expiry(expires)
    util.write_json(_dir(share_id) / "meta.json", meta, group=util.P.web_group)
    return public_meta(meta)


def _need(share_id: str) -> dict:
    meta = read_meta(share_id)
    if not meta:
        raise Refused(f"no share {share_id}")
    return meta


def sweep() -> list[str]:
    """Delete the files of expired or revoked shares, and tombstones older than 30 days."""
    done = []
    if not util.P.shares.exists():
        return done
    for d in sorted(util.P.shares.iterdir()):
        if d.name.startswith(".") or not util.SHARE_ID.fullmatch(d.name):
            continue
        meta = util.read_json(d / "meta.json", None)
        if not meta:
            continue
        st = state_of(meta)
        if st == "live":
            continue
        if (d / "files").exists():
            shutil.rmtree(d / "files")
            done.append(f"{d.name}: files removed ({st})")
        ended = util.parse_time(meta.get("revoked") or meta.get("expires"))
        if (util.now() - ended).days >= TOMBSTONE_DAYS:
            shutil.rmtree(d)
            done.append(f"{d.name}: tombstone removed")
    return done


def views() -> dict:
    return util.read_json(util.P.web_state / "views.json", {})


def public_meta(meta: dict) -> dict:
    """What status shows: never the token hash."""
    return {k: v for k, v in meta.items() if k != "token_hash"}


def listing() -> list[dict]:
    out = []
    if not util.P.shares.exists():
        return out
    seen = views()
    for d in sorted(util.P.shares.iterdir()):
        if d.name.startswith(".") or not util.SHARE_ID.fullmatch(d.name):
            continue
        meta = util.read_json(d / "meta.json", None)
        if meta:
            row = public_meta(meta)
            row["state"] = state_of(meta)
            row["views"] = int(seen.get(d.name, 0))
            out.append(row)
    return out
