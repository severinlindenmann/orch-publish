"""Admin read model for the hub console (orch-core #900): release metadata per workspace.

Query and serialization only; the route and the hub transport signature are a separate step (auth proposal
pending). Releases are the `shares` rows of a workspace. Only metadata leaves here: never file content, paths,
the ticket, the token hash or any link that grants access (a secret/once share is reachable only by its token).
No share is public today (hub_path.PUBLIC_ROUTES is empty), so `public_url` is always None until a public kind exists.
"""

from . import hub_path as H
from . import relay_proto as proto

FIELDS = (
    "workspace_id",
    "release_id",
    "kind",
    "state",
    "created_ms",
    "expires_ms",
    "revoked",
    "bytes",
    "public_url",
)


def _item(row, now_ms):
    state = row["state"]
    if state == "live" and row["expires_ms"] <= now_ms:
        state = "expired"
    return {
        "workspace_id": row["owner_ws"],
        "release_id": row["id"],
        "kind": row["kind"],
        "state": state,
        "created_ms": row["created_ms"],
        "expires_ms": row["expires_ms"],
        "revoked": state == "revoked",
        "bytes": row["bytes"],
        "public_url": None,
    }


def bound_workspaces(conn, hub_hex):
    """Workspace ids with a CURRENT binding to this hub: the stored card exists, the binding is `bound`, names this
    hub, and was signed by the card's current WSK (a binding under a rotated key does not count)."""
    rows = conn.execute(
        "SELECT w.workspace_id, w.wsk_pub, b.binding_json FROM hub_bindings b"
        " JOIN workspaces w ON w.workspace_id=b.workspace_id"
        " WHERE b.status='bound' AND b.hub_id=? ORDER BY w.workspace_id",
        (hub_hex,),
    ).fetchall()
    out = []
    for r in rows:
        if r["binding_json"] is None:
            continue
        b = proto.parse_json(r["binding_json"].encode())
        if b["wsk_pub"] == r["wsk_pub"]:
            out.append(r["workspace_id"])
    return out


def list_releases(conn, hub_hex, now_ms, workspace=None):
    """Release metadata for the workspaces bound to `hub_hex`, or only `workspace`. A workspace not bound to this
    hub yields `H.Refused("not_bound")` (never an empty list, so the hub cannot probe other hubs' workspaces
    apart from the single code). Oldest first."""
    scope = bound_workspaces(conn, hub_hex)
    if workspace is not None:
        if workspace not in scope:
            raise H.Refused("not_bound")
        scope = [workspace]
    items = []
    for ws in scope:
        for r in conn.execute(
            "SELECT id, owner_ws, kind, state, created_ms, expires_ms, bytes FROM shares"
            " WHERE owner_ws=? AND state!='staged' ORDER BY created_ms, id",
            (ws,),
        ):
            items.append(_item(r, now_ms))
    return {"releases": items}
