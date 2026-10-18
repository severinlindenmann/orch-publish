"""Workspace admission (design 2.6b): the self-presented delegation, the owner allowlist, block."""

import sqlite3

from . import relay_proto as proto
from .auth import Refusal

ID32 = r"[0-9a-f]{32}"


def parse_register_body(raw):
    """Strict body: exactly {delegation, owner_pk}. Returns (delegation, owner_pk_bytes)."""
    try:
        body = proto.parse_json(raw)
        if (
            not isinstance(body, dict)
            or set(body) != {"delegation", "owner_pk"}
            or not isinstance(body["delegation"], dict)
        ):
            raise ValueError("shape")
        pk = proto.unb64u(body["owner_pk"], 65)
        if not proto.SUITE.pub_ok(pk):
            raise ValueError("pk")
    except (ValueError, TypeError):
        raise Refusal(400, "malformed") from None
    return body["delegation"], pk


def check_delegation(delegation, pk, ws_hex, path_ws=None):
    """Design 2.6b steps 1-2: the owner PK signed this delegation, it names this owner, and it is
    for exactly this workspace (the signed Orch-Workspace and, when given, the path). Returns the
    signed object `o`."""
    res = proto.verify_delegation(delegation, pk)
    if "refuse" in res:
        raise Refusal(400, "delegation_refused", reason=res["refuse"])
    o = res["ok"]
    if o["workspace_id"] != ws_hex or (path_ws is not None and path_ws != ws_hex):
        raise Refusal(400, "other_workspace")
    return o


def delegation_key(delegation, pk, ws_hex, path_ws):
    """For an unknown workspace: the wsk_pub the request signature must verify under (step 3)."""
    return check_delegation(delegation, pk, ws_hex, path_ws)["wsk_pub"]


def require_prebound(conn, ws_hex, person_id):
    """An unknown workspace may register only if the admin pre-bound it to this owner (M2) and the
    owner is on the allowlist. Every failure is the same 401, whatever the reason (L3)."""
    ok = (
        conn.execute(
            "SELECT 1 FROM prebinds p JOIN owners o ON o.person_id = p.person_id"
            " WHERE p.workspace_id=? AND p.person_id=?",
            (ws_hex, person_id),
        ).fetchone()
        is not None
    )
    if not ok:
        raise Refusal(401, "unknown_workspace")


def get_workspace(conn, ws_hex):
    return conn.execute("SELECT * FROM workspaces WHERE workspace_id=?", (ws_hex,)).fetchone()


def require_binding(conn, ws_hex, wsk_pub):
    """Re-check, on freshly read state, that this workspace is still bound to this key and still
    admitted. Call it inside any write transaction (P2 handlers) and in the middleware after the body
    is read: an unbind, re-register or block that happened since the request was admitted refuses it.
    Returns the fresh row."""
    row = get_workspace(conn, ws_hex)
    if row is None or row["wsk_pub"] != wsk_pub:
        raise Refusal(401, "unknown_workspace")
    check_admitted(conn, row)
    return row


def check_admitted(conn, row):
    """Policy for an authenticated, known workspace; evaluated on every request from the DB row,
    with no cache in front, so a block or an allowlist removal bites on the very next request."""
    if row["status"] != "active":
        raise Refusal(403, "workspace_blocked")
    if (
        conn.execute("SELECT 1 FROM owners WHERE person_id=?", (row["owner_person_id"],)).fetchone()
        is None
    ):
        raise Refusal(403, "owner_not_allowed")


def register(conn, ws_hex, delegation, pk, now_ms):
    """Bind a workspace to its genesis delegation (design 2.6b). Everything is decided inside one
    BEGIN IMMEDIATE transaction on freshly read state. The binding is permanent: a byte-identical
    delegation is "unchanged", any other one is 409 delegation_changed; only an admin unbind
    releases it. Returns "registered" | "unchanged"."""
    o = check_delegation(delegation, pk, ws_hex, ws_hex)
    blob = proto.cj(delegation).decode()
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = get_workspace(conn, ws_hex)
        if row is None:
            # checked on freshly read state, inside the lock (M2)
            require_prebound(conn, ws_hex, o["owner_person_id"])
            if (
                conn.execute(
                    "SELECT 1 FROM owners WHERE person_id=?", (o["owner_person_id"],)
                ).fetchone()
                is None
            ):
                raise Refusal(401, "unknown_workspace")
            conn.execute(
                "INSERT INTO workspaces(workspace_id, wsk_pub, owner_person_id, owner_pk,"
                " delegation_json, status, created_ms, updated_ms)"
                " VALUES (?,?,?,?,?,'active',?,?)",
                (ws_hex, o["wsk_pub"], o["owner_person_id"], proto.b64u(pk), blob, now_ms, now_ms),
            )
            outcome = "registered"
        else:
            check_admitted(conn, row)
            if row["delegation_json"] != blob:
                raise Refusal(409, "delegation_changed")
            outcome = "unchanged"
        conn.execute("COMMIT")
        return outcome
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
