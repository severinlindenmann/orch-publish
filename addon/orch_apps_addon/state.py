"""Small files of the addon's own.

local.json in the state folder (this machine only, never committed): links already shown, share names, decisions
put off. records/shares.json (committed with the tickets): which share belongs to which ticket and when it was
published - ids and dates only, never a token, key or link.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def local(state_dir: Path) -> dict:
    data = _read(Path(state_dir) / "local.json")
    data.setdefault("revealed", [])
    data.setdefault("names", {})
    data.setdefault("put_off", {})
    return data


def save_local(state_dir: Path, data: dict) -> None:
    _write(Path(state_dir) / "local.json", data)


def record_share(records_dir: Path, share_id: str, ticket: str, at: str) -> None:
    path = Path(records_dir) / "shares.json"
    data = _read(path)
    data[share_id] = {"ticket": ticket, "published": at}
    _write(path, data)


def records(records_dir: Path) -> dict:
    return _read(Path(records_dir) / "shares.json")
