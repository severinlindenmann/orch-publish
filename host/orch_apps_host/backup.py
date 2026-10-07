"""Nightly backup of every app's data folder into one tarball; SQLite files through SQLite's own backup API so a
running app never leaves a half-written copy. The newest 7 backups are kept."""

from __future__ import annotations

import shutil
import sqlite3
import tarfile
import tempfile
from pathlib import Path

from . import util

KEEP = 7
SQLITE_SUFFIXES = (".db", ".sqlite", ".sqlite3")


def run_backup() -> dict:
    util.P.backups.mkdir(parents=True, exist_ok=True)
    stamp = util.now().strftime("%Y%m%d-%H%M%S")
    target = util.P.backups / f"bak-{stamp}.tar.gz"
    count = 0
    with tempfile.TemporaryDirectory(dir=util.P.backups) as tmp:
        stage = Path(tmp) / f"bak-{stamp}"
        stage.mkdir()
        if util.P.apps_file.exists():
            shutil.copy(util.P.apps_file, stage / "apps.json")
        if util.P.data.exists():
            for app_dir in sorted(p for p in util.P.data.iterdir() if p.is_dir()):
                for src in sorted(app_dir.rglob("*")):
                    if src.is_symlink() or not src.is_file() or src.name.endswith(("-wal", "-shm", "-journal")):
                        continue
                    dst = stage / "data" / src.relative_to(util.P.data)
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    if src.suffix in SQLITE_SUFFIXES:
                        _sqlite_copy(src, dst)
                    else:
                        shutil.copy2(src, dst)
                    count += 1
        with tarfile.open(target, "w:gz") as tar:
            tar.add(stage, arcname=stage.name)
    target.chmod(0o600)
    olds = sorted(util.P.backups.glob("bak-*.tar.gz"))
    for old in olds[:-KEEP]:
        old.unlink()
    return {"backup": target.name, "files": count, "kept": min(len(olds), KEEP)}


def _sqlite_copy(src: Path, dst: Path) -> None:
    source = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    try:
        dest = sqlite3.connect(dst)
        with dest:
            source.backup(dest)
        dest.close()
    finally:
        source.close()


def latest() -> dict:
    olds = sorted(util.P.backups.glob("bak-*.tar.gz")) if util.P.backups.exists() else []
    return {"last": olds[-1].name if olds else None, "kept": len(olds)}
