"""store json: one JSON file in DATA_DIR, written to a temporary file first and then renamed, so a crash never
leaves half a file."""

import datetime as dt
import json
import threading
from pathlib import Path


class Store:
    writable = True

    def __init__(self, folder: str):
        Path(folder).mkdir(parents=True, exist_ok=True)
        self.file = Path(folder) / "items.json"
        self.lock = threading.Lock()

    def _read(self):
        try:
            return json.loads(self.file.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def list(self):
        return self._read()[-100:][::-1]

    def add(self, text: str):
        with self.lock:
            items = self._read()
            items.append({"text": text, "at": dt.datetime.now(dt.timezone.utc).isoformat()})
            tmp = self.file.with_suffix(".tmp")
            tmp.write_text(json.dumps(items))
            tmp.replace(self.file)


def open_store(folder: str) -> Store:
    return Store(folder)
