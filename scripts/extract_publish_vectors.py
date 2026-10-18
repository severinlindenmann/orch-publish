"""Extract tests/vectors/publish_v2.json (suite 2) from orch-relay's tests/vectors_v2.json.

Usage: python scripts/extract_publish_vectors.py PATH/TO/orch-relay/tests/vectors_v2.json
"""

import hashlib
import json
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_bytes()
src = json.loads(raw)
v = src["suites"]["2"]
out = {
    "comment": "orch v2 publish-request + card vectors, suite 2 (P-256). Extracted verbatim from orch-relay"
    " tests/vectors_v2.json (protocol-v2 sections 7.1, 12.1). All keys are FAKE. orch-core's publish"
    " client (P4) checks parity against THIS file. Regenerate: scripts/extract_publish_vectors.py.",
    "source": {
        "repo": "orch-relay",
        "path": "tests/vectors_v2.json",
        "sha256": hashlib.sha256(raw).hexdigest(),
    },
    "suite": 2,
    "ids": v["ids"],
    "keys": {k: v["keys"][k] for k in ("person_alice.sig", "wsk_a.sig", "wsk_b.sig")},
    "publish": v["publish"],
    "card": {
        "card": v["card"]["card"],
        "card_seq_2": v["card"]["card_seq_2"],
        "cases": v["card"]["cases"],
    },
}
pathlib.Path("tests/vectors/publish_v2.json").write_text(json.dumps(out, indent=1, sort_keys=True))
