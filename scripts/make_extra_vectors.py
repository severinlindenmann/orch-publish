"""Generate tests/vectors/publish_v2_extra.json (edge vectors for the nonce retention boundary, L1).

Run from the repo root with `uv run python scripts/make_extra_vectors.py`. Fake keys only.
"""

import json
import pathlib
import sys

sys.path[:0] = ["tests", "."]
import test_publish_api_auth as t

base_case = t.VEC["publish"]["cases"][0]
n = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
t0 = 1790000000000
ws = t.WS_A
host, target, body = "pub.dev.severin.io", "/v1/apps/invoices?x=1", base_case["body"]
hdr = t.sign_headers(
    t._priv("wsk_a.sig"), ws, "PUT", host, target, bytes.fromhex(body), ts=t0 + 120000, nonce=n
)
base = {"headers": hdr, "method": "PUT", "host": host, "target": target, "body": body}
cases = [
    {
        "name": "replay_at_exactly_nonce_retention_end",
        "nonces": {ws: {n.hex(): t0 + 240000}},
        "now_ms": t0 + 240000,
        "expect": {"status": 401, "error": "replay"},
        **base,
    },
    {
        "name": "expired_nonce_is_purged_one_ms_later",
        "nonces": {ws: {n.hex(): t0 + 240000}},
        "now_ms": t0 + 240001,
        "expect": {"status": 401, "error": "stale_timestamp", "server_ms": t0 + 240001},
        **base,
    },
    {
        "name": "first_use_with_ts_at_the_future_edge",
        "nonces": {},
        "now_ms": t0,
        "expect": {"status": 200, "workspace": ws},
        **base,
    },
]
out = {
    "comment": "EXTRA edge vectors for orch-publish pubsrv (L1), same shape as publish.cases in"
    " publish_v2.json; not in the relay vector file (propose to orch-relay). Suite 2, fake keys.",
    "suite": 2,
    "cases": cases,
}
pathlib.Path("tests/vectors/publish_v2_extra.json").write_text(
    json.dumps(out, indent=1, sort_keys=True)
)
