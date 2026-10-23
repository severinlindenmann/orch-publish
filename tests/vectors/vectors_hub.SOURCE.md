# vectors_hub.json

Copied unchanged (V3-D8) from `orch-hub/vectors/vectors_hub.json` (severinlindenmann/orch-hub, branch
`v3-d8-spaces-contract` = PR #13, protocol.md 10.6 hub admin read, route `/v2/hub/releases`; the file moves to
`develop` when #13 merges), last changed in commit `0249b0965aa76e29fe301043f560aacd721c567b`, contract `orch.hub/0`,
`hv` 0. sha256 `45d56fb07530bb5794d758f3d7cc456e4bbe7af67cfccf1b92cfad010e9104ed`. FAKE keys, test only.
orch-publish runs the cases of `binding_store`, `publish`, `card`, `card_text`, `op_cert`, `op_revoked` and (F3)
`admin_read`, `admin_read_rows`, `admin_read_row` (`tests/test_hub_path_vectors.py`; the `admin_read` cases whose path
is the route also run through the real HTTP route in `tests/test_hub_admin_read.py`). Never edit the file here:
regenerate it in orch-hub and copy it again.
