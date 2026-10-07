"""store sqlite: one database file in DATA_DIR, with Python's built-in sqlite3."""

import datetime as dt
import sqlite3
import threading
from pathlib import Path


class Store:
    writable = True

    def __init__(self, folder: str):
        Path(folder).mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.db = sqlite3.connect(Path(folder) / "app.db", check_same_thread=False)
        self.db.execute("create table if not exists items (id integer primary key, text text not null, at text not null)")
        self.db.commit()

    def list(self):
        with self.lock:
            rows = self.db.execute("select text, at from items order by id desc limit 100").fetchall()
        return [{"text": t, "at": a} for t, a in rows]

    def add(self, text: str):
        with self.lock:
            self.db.execute("insert into items (text, at) values (?, ?)",
                            (text, dt.datetime.now(dt.timezone.utc).isoformat()))
            self.db.commit()


def open_store(folder: str) -> Store:
    return Store(folder)
