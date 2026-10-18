"""orch-publish: `serve` (loopback only) and `admin` (owner allowlist, block)."""

import argparse
import re
import sys
import time

from . import db

_ID = re.compile(r"[0-9a-f]{32}")
LOOPBACK = {"127.0.0.1", "[::1]", "localhost"}


def _id(value):
    if not _ID.fullmatch(value):
        raise argparse.ArgumentTypeError("expected 32 lower-case hex characters")
    return value


def _now():
    return int(time.time() * 1000)


def admin(args, out=None):
    out = out or sys.stdout
    path = db.prepare_dir(args.data)
    db.init(path)
    conn = db.connect(path)
    try:
        if args.group == "owners":
            if args.action == "add":
                conn.execute(
                    "INSERT OR IGNORE INTO owners(person_id, added_ms) VALUES (?,?)",
                    (args.id, _now()),
                )
                print(f"owner {args.id} allowed", file=out)
            elif args.action == "remove":
                n = conn.execute("DELETE FROM owners WHERE person_id=?", (args.id,)).rowcount
                print(
                    f"owner {args.id} removed" if n else f"owner {args.id} was not listed", file=out
                )
            else:
                for r in conn.execute("SELECT person_id, added_ms FROM owners ORDER BY added_ms"):
                    print(f"{r['person_id']} added_ms={r['added_ms']}", file=out)
        else:
            if args.action == "list":
                for r in conn.execute(
                    "SELECT workspace_id, owner_person_id, card_seq, status FROM workspaces"
                    " ORDER BY created_ms"
                ):
                    print(
                        f"{r['workspace_id']} owner={r['owner_person_id']} seq={r['card_seq']}"
                        f" {r['status']}",
                        file=out,
                    )
                return 0
            status = "blocked" if args.action == "block" else "active"
            n = conn.execute(
                "UPDATE workspaces SET status=?, updated_ms=? WHERE workspace_id=?",
                (status, _now(), args.id),
            ).rowcount
            if not n:
                print(f"unknown workspace {args.id}", file=sys.stderr)
                return 1
            print(f"workspace {args.id} {status}", file=out)
    finally:
        conn.close()
    return 0


def serve(args):
    import uvicorn

    from .app import create_app

    host, _, port = args.api_host.rpartition(":")
    if host not in LOOPBACK or not port.isdigit():
        print("serve binds loopback only: --api-host must be 127.0.0.1:PORT", file=sys.stderr)
        return 2
    app = create_app(args.data, args.api_host)
    # no access log: request lines carry ids, and the no-logging policy applies (design I15)
    uvicorn.run(
        app,
        host="127.0.0.1" if host == "localhost" else host.strip("[]"),
        port=int(port),
        access_log=False,
        log_level="warning",
    )
    return 0


def _loopback_port(value, what):
    host, _, port = value.rpartition(":")
    if host not in LOOPBACK or not port.isdigit():
        raise ValueError(f"{what} must be 127.0.0.1:PORT (loopback only)")
    return ("127.0.0.1" if host == "localhost" else host.strip("[]")), int(port)


def _uvicorn_server(app, host, port):
    import uvicorn

    class Quiet(uvicorn.Server):
        def install_signal_handlers(self):  # the main thread owns Ctrl-C
            pass

    # no access log: request lines carry ids, and the no-logging policy applies (design I15)
    return Quiet(uvicorn.Config(app, host=host, port=port, access_log=False, log_level="warning"))


def share(args):
    from .serve import create_share_app

    try:
        host, port = _loopback_port(args.share_host, "--share-host")
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2
    _uvicorn_server(create_share_app(args.data), host, port).run()
    return 0


def dev(args, ready=None):
    """Both processes' servers on loopback, plain HTTP, for local testing (design section 4)."""
    import threading

    from .app import create_app
    from .serve import create_share_app

    try:
        a_host, a_port = _loopback_port(args.api, "--api")
        s_host, s_port = _loopback_port(args.share, "--share")
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2
    if (a_host, a_port) == (s_host, s_port):
        print("--api and --share need different ports (separate origins)", file=sys.stderr)
        return 2
    path = db.prepare_dir(args.data)
    db.init(path)
    conn = db.connect(path)
    try:
        for person in args.owner or []:
            conn.execute(
                "INSERT OR IGNORE INTO owners(person_id, added_ms) VALUES (?,?)",
                (person, _now()),
            )
    finally:
        conn.close()
    api = _uvicorn_server(create_app(args.data, args.api), a_host, a_port)
    web = _uvicorn_server(create_share_app(args.data), s_host, s_port)
    t = threading.Thread(target=web.run, daemon=True)
    t.start()
    print(f"orch-publish dev: api http://{args.api}  share http://{args.share}", flush=True)
    try:
        api.run()
    except KeyboardInterrupt:
        pass
    finally:
        web.should_exit = True
        t.join(timeout=5)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="orch-publish")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the API on loopback")
    s.add_argument("--data", required=True)
    s.add_argument("--api-host", default="127.0.0.1:8103", help="host:port clients sign and reach")
    w2 = sub.add_parser("share", help="run the share server (public origin) on loopback")
    w2.add_argument("--data", required=True)
    w2.add_argument("--share-host", default="127.0.0.1:8104")
    d = sub.add_parser("dev", help="run API and share server on loopback for local testing")
    d.add_argument("--data", required=True)
    d.add_argument("--api", default="127.0.0.1:8103")
    d.add_argument("--share", default="127.0.0.1:8104")
    d.add_argument("--owner", action="append", type=_id, help="person id to allow (repeatable)")
    a = sub.add_parser("admin", help="owner allowlist and blocking")
    a.add_argument("--data", required=True)
    g = a.add_subparsers(dest="group", required=True)
    o = g.add_parser("owners").add_subparsers(dest="action", required=True)
    for name in ("add", "remove"):
        o.add_parser(name).add_argument("id", type=_id)
    o.add_parser("list")
    w = g.add_parser("ws").add_subparsers(dest="action", required=True)
    for name in ("block", "unblock"):
        w.add_parser(name).add_argument("id", type=_id)
    w.add_parser("list")
    args = p.parse_args(argv)
    run = {"serve": serve, "share": share, "dev": dev}.get(args.cmd, admin)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
