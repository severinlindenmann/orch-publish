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
            "UPDATE shares SET state='revoked', owner_ws='unbound:'||owner_ws||':'||? WHERE owner_ws=?",
            (_now(), ws),
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

    host, _, port = args.bind.rpartition(":")
    if host not in LOOPBACK or not port.isdigit():
        print("serve binds loopback only: --bind must be 127.0.0.1:PORT", file=sys.stderr)
        return 2
    # --api-host is what clients sign (it may be a public name when a proxy sits in front); it
    # defaults to the bind address
    app = create_app(args.data, args.api_host or args.bind)
    # no access log: request lines carry ids, and the no-logging policy applies (design I15)
    uvicorn.run(
        app,
        host="127.0.0.1" if host == "localhost" else host.strip("[]"),
        port=int(port),
        access_log=False,
        log_level="warning",
    )
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="orch-publish")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the API on loopback")
    s.add_argument("--data", required=True)
    s.add_argument("--bind", default="127.0.0.1:8103", help="loopback host:port to listen on")
    s.add_argument("--api-host", default=None, help="host[:port] clients sign (default: --bind)")
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
    al = w.add_parser("allow", help="pre-bind a workspace id to an owner so it may register")
    al.add_argument("id", type=_id)
    al.add_argument("person", type=_id)
    w.add_parser("unbind", help="forget a workspace and revoke its shares").add_argument(
        "id", type=_id
    )
    args = p.parse_args(argv)
    return serve(args) if args.cmd == "serve" else admin(args)


if __name__ == "__main__":
    sys.exit(main())
