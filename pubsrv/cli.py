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
        if args.group == "sweep":
            from . import sweep

            counts = sweep.run(path, args.data, _now())
            print(" ".join(f"{k}={v}" for k, v in counts.items()), file=out)
        elif args.group == "owners":
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
                    "SELECT workspace_id, owner_person_id, status FROM workspaces"
                    " ORDER BY created_ms"
                ):
                    print(
                        f"{r['workspace_id']} owner={r['owner_person_id']} {r['status']}",
                        file=out,
                    )
                return 0
            if args.action == "allow":
                conn.execute(
                    "INSERT OR REPLACE INTO prebinds(workspace_id, person_id, added_ms) VALUES (?,?,?)",
                    (args.id, args.person, _now()),
                )
                print(f"workspace {args.id} may register for owner {args.person}", file=out)
                return 0
            if args.action == "unbind":
                return _unbind(conn, args.id, out)
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


def _unbind(conn, ws, out):
    """Forget a workspace: drop its binding and pre-binding and revoke (tombstone) its shares, in one
    transaction. Files are removed by the share lifecycle (P2); the tombstone rows stay."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        n = conn.execute("DELETE FROM workspaces WHERE workspace_id=?", (ws,)).rowcount
        conn.execute("DELETE FROM prebinds WHERE workspace_id=?", (ws,))
        # nonces are left to expire on their own: a replay after unbind + re-register stays refused.
        # Every share row (tombstones included) is re-keyed to a value no workspace id can equal, so
        # a later registration of the same id inherits nothing and owned_share(ws, id) never matches.
        k = conn.execute(
            "UPDATE shares SET state='revoked', owner_ws='unbound:'||owner_ws||':'||?,"
            " ended_ms=?, token_hash=? WHERE owner_ws=?",
            (_now(), _now(), "0" * 64, ws),
        ).rowcount
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    print(
        f"workspace {ws} unbound ({k} shares revoked)" if n else f"workspace {ws} was not bound",
        file=out,
    )
    return 0


def serve(args):
    import uvicorn

    from .app import create_app

    try:
        host, port = _loopback_port(args.bind, "--bind")
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2
    # --api-host is what clients sign (it may be a public name when a proxy sits in front); it
    # defaults to the bind address
    app = create_app(args.data, args.api_host or args.bind, dev_mode=args.dev_mode)
    # no access log: request lines carry ids, and the no-logging policy applies (design I15)
    uvicorn.run(
        app,
        host=host,
        port=port,
        access_log=False,
        log_level="warning",
    )
    return 0


def combined_app(data_dir, api_host, dev_mode=False):
    """No-domain mode: one ASGI app on one port. `/s/...` is the share server (path-based links), every other path
    is the signed API. With a domain the two stay on separate origins (`serve` + `share`)."""
    from .app import create_app
    from .serve import create_share_app

    api = create_app(data_dir, api_host, dev_mode=dev_mode)
    share = create_share_app(data_dir)

    async def app(scope, receive, send):
        if scope["type"] == "http" and (scope.get("path") or "").startswith("/s/"):
            return await share(scope, receive, send)
        return await api(scope, receive, send)

    app.state = api.state
    return app


def run_cmd(args):
    """One address, one port, api and share together: `orch-publish run --data D --listen IP:PORT`."""
    from urllib.parse import urlsplit

    host, _, port = args.listen.rpartition(":")
    if not host or not port.isdigit():
        print("--listen must be ADDRESS:PORT", file=sys.stderr)
        return 2
    origin = args.public_origin or f"http://{args.listen}"
    u = urlsplit(origin)
    if u.scheme not in ("http", "https") or not u.netloc or u.path not in ("", "/"):
        print("--public-origin must be http(s)://HOST[:PORT] with no path", file=sys.stderr)
        return 2
    try:
        app = combined_app(args.data, u.netloc.lower(), dev_mode=args.dev_mode)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2
    print(f"orch-publish: listening on {args.listen}; links open at {origin}/s/<id>", flush=True)
    _uvicorn_server(app, host.strip("[]"), int(port)).run()
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
    return Quiet(
        uvicorn.Config(
            app,
            host=host,
            port=port,
            access_log=False,
            log_level="warning",
            server_header=False,
            workers=1,
        )
    )


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
    pre = []
    for item in args.workspace or []:
        ws, _, person = item.partition("=")
        if not (_ID.fullmatch(ws) and _ID.fullmatch(person)):
            print("--workspace must be WS=PERSON (32 lower-case hex each)", file=sys.stderr)
            return 2
        pre.append((ws, person))
    path = db.prepare_dir(args.data)
    db.init(path)
    conn = db.connect(path)
    try:
        for ws, person in pre:
            conn.execute(
                "INSERT OR REPLACE INTO prebinds(workspace_id, person_id, added_ms) VALUES (?,?,?)",
                (ws, person, _now()),
            )
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
    s.add_argument("--bind", default="127.0.0.1:8103", help="loopback host:port to listen on")
    s.add_argument("--api-host", default=None, help="host[:port] clients sign (default: --bind)")
    s.add_argument(
        "--dev-mode",
        action="store_true",
        help="dev instance: accepts only dev hub objects (dev: true) and refuses real ones",
    )
    r = sub.add_parser("run", help="no domain: API and share links on ONE address and port")
    r.add_argument("--data", required=True)
    r.add_argument("--listen", required=True, help="ADDRESS:PORT to bind, e.g. 100.64.0.5:8102")
    r.add_argument("--public-origin", default=None, help="http(s)://HOST[:PORT] clients use (default: http://LISTEN)")
    r.add_argument("--dev-mode", action="store_true", help="dev instance: accepts only dev hub objects")
    w2 = sub.add_parser("share", help="run the share server (public origin) on loopback")
    w2.add_argument("--data", required=True)
    w2.add_argument("--share-host", default="127.0.0.1:8104")
    d = sub.add_parser("dev", help="run API and share server on loopback for local testing")
    d.add_argument("--data", required=True)
    d.add_argument("--api", default="127.0.0.1:8103")
    d.add_argument("--share", default="127.0.0.1:8104")
    d.add_argument("--owner", action="append", type=_id, help="person id to allow (repeatable)")
    d.add_argument(
        "--workspace",
        action="append",
        metavar="WS=PERSON",
        help="pre-bind a workspace id to an owner (repeatable; same as admin ws allow)",
    )
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
    g.add_parser("sweep", help="expire shares, drop stale uploads and old tombstones")
    al = w.add_parser("allow", help="pre-bind a workspace id to an owner so it may register")
    al.add_argument("id", type=_id)
    al.add_argument("person", type=_id)
    w.add_parser("unbind", help="forget a workspace and revoke its shares").add_argument(
        "id", type=_id
    )
    args = p.parse_args(argv)
    run = {"serve": serve, "share": share, "dev": dev, "run": run_cmd}.get(args.cmd, admin)
    try:
        return run(args)
    except db.SchemaError as e:
        print(e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
