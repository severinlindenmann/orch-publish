# Vendored code

`relay_proto.py` is a byte-identical copy of `src/orch_relay/proto/__init__.py` from
orch-relay (severinlindenmann/orch-relay), branch `develop`, commit `4a9f95474bdac8dc3ffae8be4099a9b4b2e6cdcc`
(git blob `a6c5b26324c00f49719ef7fcb9c4aa849af39c8c`), licensed PolyForm Noncommercial 1.0.0 like this repo.

It provides `verify_delegation` and `verify_card`, both used by the hub card route (`PUT /v2/hub/cards/{ws}`, V3-D36: the card is how a workspace is admitted). `relay_accept_card` stays vendored but is unused; the card vectors still run against it to pin the file. Never edit it here: change it in
orch-relay, copy it again and update the pinned sha256 in `tests/test_publish_api_auth.py`
(`VENDORED_SHA256`). That test fails when the file differs from the pin, and also compares it with a
local orch-relay checkout when `ORCH_RELAY_SRC` points at one.

Pinned sha256: `4b7cd9aa524b5d808859b9cff54ea3c025dab5791c13966683e9f88657b9c1b0`
