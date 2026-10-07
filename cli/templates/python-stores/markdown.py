"""store markdown: the content lives in content/*.md in the repository and is read-only at run time."""

from pathlib import Path

CONTENT = Path(__file__).resolve().parent / "content"


class Store:
    writable = False

    def list(self):
        return [{"text": p.read_text().split("\n")[0].lstrip("# ").strip()} for p in sorted(CONTENT.glob("*.md"))]


def open_store(folder: str) -> Store:
    return Store()
