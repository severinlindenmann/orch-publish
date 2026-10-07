"""orch-apps-host: the only program that changes the server. Called with root rights through one sudoers line, by the
forced SSH command (bin/orch-apps-gate) and by the two timers. Every argument is validated here.

Exit codes: 0 ok, 1 failed (valid request that did not work), 2 refused (not allowed or not valid).
"""

from __future__ import annotations

import argparse
import json
import platform
import sys

from . import apps, backup, shares, util


def _expires(value: str) -> str | None:
    return None if value == "none" else value


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="orch-apps-host", allow_abbrev=False)
    sub = p.add_subparsers(dest="area", required=True)

    s = sub.add_parser("share", allow_abbrev=False).add_subparsers(dest="cmd", required=True)
    put = s.add_parser("put", allow_abbrev=False)
    put.add_argument("id")
    put.add_argument("--access", required=True, choices=shares.ACCESS)
    put.add_argument("--ticket", required=True)
    put.add_argument("--expires", required=True, help="ISO time or none")
    put.add_argument("--token-hash")
    for name in ("revoke",):
        s.add_parser(name, allow_abbrev=False).add_argument("id")
    ext = s.add_parser("extend", allow_abbrev=False)
    ext.add_argument("id")
    ext.add_argument("--expires", required=True, help="ISO time or none")

    a = sub.add_parser("app", allow_abbrev=False).add_subparsers(dest="cmd", required=True)
    dep = a.add_parser("deploy", allow_abbrev=False)
    dep.add_argument("slug")
    dep.add_argument("--ticket", required=True)
    dep.add_argument("--access", required=True, choices=apps.ACCESS)
    dep.add_argument("--token-hash")
    for name in ("start", "stop", "restart", "delete"):
        a.add_parser(name, allow_abbrev=False).add_argument("slug")
    lg = a.add_parser("logs", allow_abbrev=False)
    lg.add_argument("slug")
    lg.add_argument("--lines", type=int, default=100)

    st = sub.add_parser("status", allow_abbrev=False)
    st.add_argument("--json", action="store_true", help="always JSON; accepted for symmetry with the CLI")
    sub.add_parser("backup", allow_abbrev=False)
    sub.add_parser("sweep", allow_abbrev=False)
    return p


def _runtimes() -> dict:
    out = {"python": platform.python_version()}
    for name, argv in (("node", ["node", "-v"]), ("uv", ["uv", "--version"]), ("caddy", ["caddy", "version"])):
        try:
            res = util.run(argv, ok=False, timeout=10)
            out[name] = (res.stdout or "").split()[0 if name != "uv" else 1].lstrip("v") if res.stdout else None
        except (util.Failed, IndexError):
            out[name] = None
    return out


def status() -> dict:
    return {"host": platform.node(), "at": util.iso(util.now()), "shares": shares.listing(), "apps": apps.listing(),
            "backup": backup.latest(), "runtimes": _runtimes()}


def dispatch(args) -> object:
    if args.area == "share":
        if args.cmd == "put":
            return shares.put(args.id, args.access, args.ticket, _expires(args.expires), args.token_hash)
        if args.cmd == "revoke":
            return shares.revoke(args.id)
        if args.cmd == "extend":
            return shares.extend(args.id, _expires(args.expires))
    if args.area == "app":
        if args.cmd == "deploy":
            return apps.deploy(args.slug, args.ticket, args.access, args.token_hash)
        if args.cmd == "logs":
            return apps.logs(args.slug, args.lines)
        return getattr(apps, args.cmd)(args.slug)
    if args.area == "status":
        return status()
    if args.area == "backup":
        return backup.run_backup()
    if args.area == "sweep":
        return {"swept": shares.sweep()}
    raise util.Refused("unknown command")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    try:
        result = dispatch(args)
    except util.Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    except util.Failed as e:
        print(f"failed: {e}", file=sys.stderr)
        return 1
    if isinstance(result, str):
        sys.stdout.write(result)
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
