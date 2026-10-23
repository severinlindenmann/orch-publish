# vectors_hub.json

Copied unchanged (V3-D8; regenerated for R5: card admission cases added, direct-path case deleted) from
`orch-hub/vectors/vectors_hub.json` (severinlindenmann/orch-hub, `develop` once PR #72 is merged), contract `orch.hub/0`,
`hv` 0. sha256 `2c8baa2f058a9c2eaf5231927a785030fa7349c5493f0900ecbd6f966a016da5`. FAKE keys, test only.
orch-publish runs the cases of `binding_store`, `publish`, `ws_card_admission` (through `PUT /v2/hub/cards/{ws}`), `card`, `card_text`, `op_cert`, `op_revoked` and (F3)
`admin_read`, `admin_read_rows`, `admin_read_row` (`tests/test_hub_path_vectors.py`; the `admin_read` cases whose path
is the route also run through the real HTTP route in `tests/test_hub_admin_read.py`). Never edit the file here:
regenerate it in orch-hub and copy it again.
