"""Builders shared by the publish tests: a hub with its card, a workspace's binding, and the hub-path request the host
builds and the hub forwards (protocol 11.1). Fake keys only. Every request to pubsrv is of this kind (V3-D36)."""

import json
import os
import pathlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pubsrv import hub_path as H
from pubsrv import relay_proto as proto

ROOT = pathlib.Path(__file__).resolve().parent.parent
VEC = json.loads((ROOT / "tests/vectors/publish_v2.json").read_text())
HOST = "127.0.0.1:8103"
NOW = 1_790_000_000_000
WS_A = VEC["ids"]["workspace_a"]
PUBLIC_PATH = f"/v1/ws/{WS_A}/status"


def pub(priv):
    return priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def sign(priv, msg):
    r, s = decode_dss_signature(priv.sign(msg, ec.ECDSA(hashes.SHA256())))
    return proto.b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def signed(priv, label, o, **extra):
    return {"o": o, **extra, "sig": sign(priv, label + proto.cj(o))}


def newkey():
    return ec.generate_private_key(ec.SECP256R1())


class Hub:
    def __init__(self, dev=True, cert_seq=1):
        self.root, self.op = newkey(), newkey()
        self.id = H.hub_id(pub(self.root))
        hdr = {"v": 2, "suite": 2, "hv": 0}
        op_cert = signed(
            self.root,
            H.LABELS["sig_hub_op_cert"],
            {
                **hdr, "kind": "hub.op_cert", "hub_id": self.id, "cert_id": os.urandom(16).hex(),
                "op_seq": cert_seq, "hk_op_pub": proto.b64u(pub(self.op)), "issued_ms": NOW - 1000,
                "expires_ms": NOW + 10**11, "dev": dev,
            },
        )  # fmt: skip
        self.card = signed(
            self.op,
            H.LABELS["sig_hub_card"],
            {
                **hdr, "kind": "hub.card", "hub_id": self.id, "hk_root_pub": proto.b64u(pub(self.root)),
                "hxk_pub": proto.b64u(pub(newkey())), "relay_url": None,
                "tls_spki_sha256": proto.b64u(os.urandom(32)), "card_seq": 1, "reader": 1, "issued_ms": NOW - 1000, "dev": dev,
            },
            op_cert=op_cert,
        )  # fmt: skip


def binding(wsk, hub, ws=WS_A, seq=1, dev=True, wsk_pub=None, **over):
    o = {
        "v": 2, "suite": 2, "hv": 0, "kind": "hub.binding", "workspace_id": ws,
        "wsk_pub": proto.b64u(wsk_pub or pub(wsk)), "hub_id": hub.id,
        "hk_root_pub": proto.b64u(pub(hub.root)), "mode": "selective", "binding_seq": seq,
        "valid_from_ms": NOW - 1000, "dev": dev,
    }  # fmt: skip
    o.update(over)
    return signed(wsk, H.LABELS["sig_hub_binding"], o)


def unbound(wsk, hub, ws=WS_A, seq=1, dev=True):
    o = {
        "v": 2, "suite": 2, "hv": 0, "kind": "hub.unbound", "workspace_id": ws, "hub_id": hub.id,
        "binding_seq": seq, "unbound_ms": NOW, "dev": dev,
    }  # fmt: skip
    return signed(wsk, H.LABELS["sig_hub_unbound"], o)


def build(
    hub,
    wsk,
    method="GET",
    target=PUBLIC_PATH,
    body=b"",
    ts=NOW,
    nonce=None,
    approval=None,
    hub_op=None,
    ws=WS_A,
    host=HOST,
):
    """The headers the host builds and the hub forwards (11.1)."""
    nonce = nonce or os.urandom(16)
    pb = H.hub_path_signed_bytes(
        bytes.fromhex(ws), ts, nonce, method, host, target, body, hub.id, approval
    )
    h = {
        "Orch-Workspace": ws, "Orch-Ts": str(ts), "Orch-Nonce": nonce.hex(), "Orch-Signature": None,
        "Orch-Hub": hub.id,
    }  # fmt: skip
    r, s = decode_dss_signature(wsk.sign(pb, ec.ECDSA(hashes.SHA256())))
    h["Orch-Signature"] = proto.b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    r, s = decode_dss_signature(
        (hub_op or hub.op).sign(H.hub_publish_bytes(hub.id, pb), ec.ECDSA(hashes.SHA256()))
    )
    h["Orch-Hub-Signature"] = proto.b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    if approval is not None:
        h["Orch-Owner-Approval"] = proto.b64u(proto.cj(approval))
    return h, {
        "hub": hub,
        "ts": ts,
        "nonce": nonce,
        "method": method,
        "target": target,
        "body": body,
    }
