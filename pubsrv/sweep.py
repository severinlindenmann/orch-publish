"""Housekeeping: expire shares, drop abandoned uploads, delete old tombstones and orphan directories.
Serving checks expiry on every request (design I13); the sweep only reclaims space."""

import os
import shutil

from . import db

STAGED_MAX_AGE_MS = 6 * 3600 * 1000
TOMBSTONE_KEEP_MS = 30 * 86400 * 1000


def _rm(path):
    """Remove one entry; a symlink or plain file is unlinked, a directory is removed in full."""
    if os.path.islink(path) or not os.path.isdir(path):
        try:
            os.unlink(path)
        except OSError:
            pass
    else:
        shutil.rmtree(path, ignore_errors=True)


def run(db_path, data_dir, now_ms):
    counts = {"expired": 0, "stale_staged": 0, "tombstones_dropped": 0, "orphans": 0}
    conn = db.connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            counts["expired"] = conn.execute(
                "UPDATE shares SET state='expired', ended_ms=? WHERE state='live' AND expires_ms<=?",
                (now_ms, now_ms),
            ).rowcount
            stale = [
                r["id"]
                for r in conn.execute(
                    "SELECT id FROM shares WHERE state='staged' AND created_ms<=?",
                    (now_ms - STAGED_MAX_AGE_MS,),
                )
            ]
            for sid in stale:
                conn.execute(
                    "UPDATE shares SET state='expired', ended_ms=? WHERE id=?", (now_ms, sid)
                )
            counts["stale_staged"] = len(stale)
            old = [
                r["id"]
                for r in conn.execute(
                    "SELECT id FROM shares WHERE state IN ('revoked','expired') AND ended_ms<=?",
                    (now_ms - TOMBSTONE_KEEP_MS,),
                )
            ]
            for sid in old:
                conn.execute("DELETE FROM share_files WHERE share_id=?", (sid,))
                conn.execute("DELETE FROM views WHERE share_id=?", (sid,))
                conn.execute("DELETE FROM shares WHERE id=?", (sid,))
            counts["tombstones_dropped"] = len(old)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        # files: only live shares keep shares/<id>, only staged ones keep incoming/<id>
        keep = {
            "shares": {r["id"] for r in conn.execute("SELECT id FROM shares WHERE state='live'")},
            "incoming": {
                r["id"] for r in conn.execute("SELECT id FROM shares WHERE state='staged'")
            },
        }
    finally:
        conn.close()
    for sub, ok in keep.items():
        base = os.path.join(data_dir, sub)
        try:
            names = os.listdir(base)
        except FileNotFoundError:
            continue
        for name in names:
            if name not in ok:
                _rm(os.path.join(base, name))
                counts["orphans"] += 1
    return counts
