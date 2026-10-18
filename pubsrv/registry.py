"""Workspace admission (design section 2.6): the self-presented card, the owner allowlist, block."""

import json
import sqlite3

from . import relay_proto as proto
from .auth import Refusal

ID32 = r"[0-9a-f]{32}"

# card refusal -> HTTP status; anything unlisted is 400
_CARD_STATUS = {
    "stale_card": 409,
    "wsk_changed": 409,
    "delegation_changed": 409,
    "other_workspace": 409,
    "bad_wxk_version": 409,
    "wxk_changed_without_version": 409,
}


def parse_register_body(raw):
    """Strict body: exactly {card, owner_pk}. Returns (card, owner_pk_bytes)."""
    try:
        body = proto.parse_json(raw)
        if (
            not isinstance(body, dict)
            or set(body) != {"card", "owner_pk"}
            or not isinstance(body["card"], dict)
        ):
            raise ValueError("shape")
        pk = proto.unb64u(body["owner_pk"], 65)
        if not proto.SUITE.pub_ok(pk):
            raise ValueError("pk")
    except (ValueError, TypeError):
        raise Refusal(400, "malformed") from None
    return body["card"], pk


def card_key(card, pk, ws_hex):
    """For an unknown workspace: the wsk_pub the request signature must verify under. Only a card
    that verifies end to end (delegation by the owner PK, card by the WSK) is trusted for that."""
    res = proto.verify_card(card, pk)
    if "refuse" in res:
        raise Refusal(400, "card_refused", reason=res["refuse"])
    if res["ok"]["workspace_id"] != ws_hex:
        raise Refusal(400, "card_refused", reason="other_workspace")
    return res["ok"]["wsk_pub"]


def get_workspace(conn, ws_hex):
    return conn.execute("SELECT * FROM workspaces WHERE workspace_id=?", (ws_hex,)).fetchone()


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


def register(conn, ws_hex, card, pk, now_ms):
    """Bind or update a workspace. Everything is decided inside one BEGIN IMMEDIATE transaction on
    freshly read state. Returns "registered" | "updated" | "unchanged"."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = get_workspace(conn, ws_hex)
        if row is not None:
            check_admitted(conn, row)
            old = json.loads(row["card_json"])
            stored = {"o": old["o"], "delegation": old["delegation"]["o"]}
        else:
            stored = None
        res = proto.relay_accept_card(stored, card, pk)
        if "refuse" in res:
            raise Refusal(
                _CARD_STATUS.get(res["refuse"], 400), "card_refused", reason=res["refuse"]
            )
        o = res["ok"]
        if o["workspace_id"] != ws_hex:
            raise Refusal(400, "card_refused", reason="other_workspace")
        if (
            conn.execute(
                "SELECT 1 FROM owners WHERE person_id=?", (o["owner_person_id"],)
            ).fetchone()
            is None
        ):
            raise Refusal(403, "owner_not_allowed")
        blob = json.dumps(card, sort_keys=True, separators=(",", ":"))
        if row is None:
            conn.execute(
                "INSERT INTO workspaces(workspace_id, wsk_pub, owner_person_id, owner_pk, card_seq,"
                " card_json, status, created_ms, updated_ms) VALUES (?,?,?,?,?,?,'active',?,?)",
                (
                    ws_hex,
                    o["wsk_pub"],
                    o["owner_person_id"],
                    proto.b64u(pk),
                    o["card_seq"],
                    blob,
                    now_ms,
                    now_ms,
                ),
            )
            outcome = "registered"
        elif o == stored["o"]:
            outcome = "unchanged"
        else:
            conn.execute(
                "UPDATE workspaces SET card_seq=?, card_json=?, updated_ms=? WHERE workspace_id=?",
                (o["card_seq"], blob, now_ms, ws_hex),
            )
            outcome = "updated"
        conn.execute("COMMIT")
        return outcome, o["card_seq"]
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
