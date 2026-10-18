"""Upload path rules (design invariant I8). A path is accepted only if it is already in normal form:
nothing is rewritten, so there is no second interpretation to disagree with the first."""

import re
import unicodedata

MAX_DEPTH = 8
MAX_PART = 100
MAX_PATH = 400
MAX_FILES = 500
_PART = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._ -]*")  # ASCII only; no leading dot


class BadPath(ValueError):
    pass


def check(path):
    """Return path if it is a valid relative upload path, else raise BadPath."""
    if not isinstance(path, str) or not path or len(path) > MAX_PATH:
        raise BadPath("length")
    if unicodedata.normalize("NFC", path) != path:
        raise BadPath("not normalized")
    parts = path.split("/")
    if len(parts) > MAX_DEPTH:
        raise BadPath("depth")
    for p in parts:
        # empty part = leading/trailing/double slash; "." and ".." start with a dot; a trailing dot or
        # space is dropped by some filesystems, so it is refused too
        if not p or len(p) > MAX_PART or not _PART.fullmatch(p) or p[-1] in ". ":
            raise BadPath("part")
    return path


def fold(path):
    return path.lower()


def check_set(paths):
    """No duplicates or case collisions, and no file that is also another file's directory."""
    seen = set()
    for p in paths:
        f = fold(p)
        if f in seen:
            raise BadPath("collision")
        seen.add(f)
    for f in seen:
        parts = f.split("/")
        for i in range(1, len(parts)):
            if "/".join(parts[:i]) in seen:
                raise BadPath("file and directory")
