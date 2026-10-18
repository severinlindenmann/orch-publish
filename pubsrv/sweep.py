"""Housekeeping: expire shares, drop abandoned uploads, trim old tombstones, remove orphan directories.
Serving checks expiry on every request (design I13); the sweep only reclaims space.

A share id is never freed: the `shares` row stays forever (as a tombstone with a zeroed token hash).
Otherwise someone holding an old link could re-create the id in another workspace with their own
token and have the old link serve the new files."""

import os
import shutil

from . import db

STAGED_MAX_AGE_MS = 6 * 3600 * 1000
TOMBSTONE_KEEP_MS = 30 * 86400 * 1000
MIN_AGE_MS = (
    10 * 60 * 1000
)  # a directory younger than this is never removed (races with commit/PUT)
ZERO = "0" * 64


def _rm(path):
    """Remove one entry; a symlink or plain file is unlinked, a directory is removed in full."""
    if os.path.islink(path) or not os.path.isdir(path):
        try:
            os.unlink(path)
        except OSError:
            pass
    else:
        shutil.rmtree(path, ignore_errors=True)


def _list(base):
    """(name, mtime_ms) for every entry of base, taken BEFORE the database is read."""
    out = []
    try:
        names = os.listdir(base)
    except FileNotFoundError:
        return out
    for name in names:
        try:
            out.append((name, os.lstat(os.path.join(base, name)).st_mtime * 1000))
        except OSError:
            pass
    return out


def _wanted(conn, sub, name):
    state = "live" if sub == "shares" else "staged"
    return (
        conn.execute("SELECT 1 FROM shares WHERE id=? AND state=?", (name, state)).fetchone()
        is not None
    )


def run(db_path, data_dir, now_ms):
    counts = {"expired": 0, "stale_staged": 0, "tombstones_dropped": 0, "orphans": 0}
    # 1. list the directories first: anything created after this point is not a candidate
    listed = {sub: _list(os.path.join(data_dir, sub)) for sub in ("shares", "incoming")}
    conn = db.connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            counts["expired"] = conn.execute(
                "UPDATE shares SET state='expired', ended_ms=?, token_hash=?"
                " WHERE state='live' AND expires_ms<=?",
                (now_ms, ZERO, now_ms),
            ).rowcount
            counts["stale_staged"] = conn.execute(
                "UPDATE shares SET state='expired', ended_ms=?, token_hash=?"
                " WHERE state='staged' AND created_ms<=?",
                (now_ms, ZERO, now_ms - STAGED_MAX_AGE_MS),
            ).rowcount
            # trim only the file list and view sessions; the row itself stays (id is never reused)
            old = [
                r["id"]
                for r in conn.execute(
                    "SELECT id FROM shares WHERE state IN ('revoked','expired') AND ended_ms<=?",
                    (now_ms - TOMBSTONE_KEEP_MS,),
                )
            ]
            for sid in old:
                if conn.execute("DELETE FROM share_files WHERE share_id=?", (sid,)).rowcount:
                    counts["tombstones_dropped"] += 1  # trimmed (files list gone); row is kept
                conn.execute("DELETE FROM views WHERE share_id=?", (sid,))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        # 2. remove only listed, old-enough entries that the database (re-read per entry) no longer wants
        for sub, entries in listed.items():
            for name, mtime_ms in entries:
                if now_ms - mtime_ms < MIN_AGE_MS or _wanted(conn, sub, name):
                    continue
                _rm(os.path.join(data_dir, sub, name))
                counts["orphans"] += 1
    finally:
        conn.close()
    return counts
