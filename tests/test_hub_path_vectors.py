"""The shared hub-contract vectors (tests/vectors/vectors_hub.json, copied from orch-hub, V3-D8) against
pubsrv.hub_path: every case of the checks orch-publish implements must give the vector's result."""

import json
import pathlib

import pytest

from pubsrv import auth
from pubsrv import hub_admin_read as R
from pubsrv import hub_path as H
from pubsrv import relay_proto as proto

VEC = json.loads((pathlib.Path(__file__).parent / "vectors/vectors_hub.json").read_text())
CHECKS = (
    "binding_store", "publish", "card", "card_text", "op_cert", "op_revoked",
    "admin_read", "admin_read_rows", "admin_read_row", "card_reader",
)  # fmt: skip
CASES = [c for c in VEC["cases"] if c["check"] in CHECKS]


def _held(a):
    pinned = proto.unb64u(a["pinned_root"], 65) if a.get("pinned_root") else None
    rev = frozenset(a.get("revoked_op_certs", []))
    dev = a.get("dev_mode", True)
    prior = None
    if a.get("held_card"):
        prior = H.verify_card(a["held_card"], a["now_ms"], dev, pinned, rev)
    return H.verify_card(a["card"], a["now_ms"], dev, pinned, rev, prior)


def _apply_store(steps, ws, wsk, now, dev):
    state = None
    for st in steps:
        if "binding" in st:
            state = H.apply_binding(state, H.verify_binding(st["binding"], ws, wsk, now, dev))
        else:
            state = H.apply_unbound(state, H.verify_unbound(st["unbound"], ws, wsk, dev))
    return state


def run(check, a):
    dev, now = a.get("dev_mode", True), a.get("now_ms", 0)
    if check == "op_cert":
        o = H.verify_op_cert(
            a["signed"],
            proto.unb64u(a["hk_root_pub"], 65),
            now,
            dev,
            frozenset(a.get("revoked_op_certs", [])),
        )
        return {"cert_id": o["cert_id"]}
    if check == "op_revoked":
        return {
            "cert_id": H.verify_op_revoked(a["signed"], proto.unb64u(a["hk_root_pub"], 65))[
                "cert_id"
            ]
        }
    if check == "card":
        h = _held(a)
        return {"hub_id": h["card"]["hub_id"], "op_cert_id": h["op_cert"]["cert_id"]}
    if check == "card_reader":
        return {"reader": _held(a)["card"]["reader"]}
    if check == "card_text":
        return run("card", {**a, "card": H._bad(proto.parse_json, bytes.fromhex(a["text_hex"]))})
    if check == "admin_read":
        pinned = frozenset(a.get("revoked_op_certs", []))
        st = {
            "cards": a["cards"],
            "bindings": {
                w: _apply_store(steps, w, proto.unb64u(a["cards"][w]["wsk_pub"], 65), now, dev)
                for w, steps in a.get("bindings", {}).items()
            },
            "held": lambda h: (
                H.verify_card(a["hub_card"], now, dev, revoked_op_certs=pinned)
                if h == a["hub_id"]
                else None
            ),
        }
        r = R.check_admin_read(a["request"], st, now)
        return {"hub": r["hub"], "workspaces": r["workspaces"]}
    if check == "admin_read_rows":
        return {"rows": len(R.check_rows(a["rows"], a["scope"]))}
    if check == "admin_read_row":
        R.check_row(a["row"])
        return {"row": True}
    if check == "binding_store":
        s = _apply_store(a["steps"], a["workspace_id"], proto.unb64u(a["wsk_pub"], 65), now, dev)
        return {"binding_seq": s["binding_seq"], "status": s["status"]}
    assert check == "publish"
    held = _held({**a, "card": a["hub_card"]})
    bindings = {
        w: _apply_store(steps, w, proto.unb64u(a["cards"][w]["wsk_pub"], 65), now, dev)
        for w, steps in a.get("bindings", {}).items()
    }
    st = H.State(
        a["cards"], bindings, lambda h: held if h == held["card"]["hub_id"] else None,
        frozenset(a.get("revoked_devices", [])),
    )  # fmt: skip
    r = a["request"]
    req = {
        "method": r["method"],
        "host": r["host"],
        "target": r["target"],
        "headers": {k.lower(): v for k, v in r["headers"].items()},
        "body": bytes.fromhex(r["body_hex"]),
        "access": r.get("access"),
    }
    nonces = auth.MemoryNonces({k: dict(v) for k, v in a.get("nonces", {}).items()})
    return H.check_hub_publish(req, st, nonces, now, dev)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_vector(case):
    if case["args"].get("path") == "direct":
        pytest.skip(
            "V3-D36: there is no direct path any more; tests/test_hub_path_http.py covers hub_required"
        )
    try:
        got = {"ok": run(case["check"], case["args"])}
    except H.Refused as r:
        got = {"error": r.code}
    assert got == case["expect"]


def test_every_relevant_case_is_run():
    # Every card-bearing check the hub vectors define must be replayed here (a new card field once broke publish
    # silently): all card, card_text, card_reader and ws_card_admission cases are in CASES / CARD_CASES.
    for check in CHECKS + ("ws_card_admission",):
        assert any(c["check"] == check for c in VEC["cases"]), check
    assert len(CASES) == sum(c["check"] in CHECKS for c in VEC["cases"])
    assert len([c for c in CASES if c["check"] == "card_reader"]) == 11


def test_labels_match_the_contract():
    for k, v in H.LABELS.items():
        assert VEC["labels"][k].encode() == v


CARD_CASES = [c for c in VEC["cases"] if c["check"] == "ws_card_admission"]


@pytest.mark.parametrize("case", CARD_CASES, ids=lambda c: c["name"])
def test_card_admission_vector_over_the_real_route(tmp_path, case):
    """protocol 11.2 "Admission through the hub": the same cases, through `PUT /v2/hub/cards/{ws}`."""
    from tests.test_publish_api_auth import Env

    a = case["args"]
    e = Env(tmp_path)
    e.now = a["now_ms"]
    card_owner = a["card"]["delegation"]["o"]["owner_person_id"]
    e.sql("INSERT OR IGNORE INTO owners VALUES (?,?)", card_owner, e.now)
    if a["prebound"]:
        e.sql(
            "INSERT OR REPLACE INTO prebinds VALUES (?,?,?)", a["workspace_id"], card_owner, e.now
        )
    if a.get("floor") is not None:
        e.sql("INSERT INTO card_floor VALUES (?,?)", a["workspace_id"], a["floor"])
    r = e.c.put(
        f"/v2/hub/cards/{a['workspace_id']}",
        content=json.dumps({"card": a["card"], "pk_pub": a["pk_pub"]}).encode(),
    )
    if "ok" in case["expect"]:
        assert (r.status_code, r.json()) == (200, {"ok": True})
    else:
        assert r.json() == case["expect"], r.text


def _reader_card_case(name):
    return next(c for c in VEC["cases"] if c["name"] == name)["args"]


def test_reader_bearing_card_is_admitted():
    a = _reader_card_case("card_reader_level_1")
    assert H.verify_card(a["card"], a["now_ms"], a.get("dev_mode", True))["card"]["reader"] == 1


def test_unknown_extra_field_is_still_refused():
    a = _reader_card_case("card_reader_level_1")
    card = json.loads(json.dumps(a["card"]))
    card["o"]["extra"] = 1  # signature check comes first, so assert on the field-set step directly
    with pytest.raises(H.Refused) as r:
        H._fields(card["o"], "hub.card")
    assert r.value.code == "malformed"
