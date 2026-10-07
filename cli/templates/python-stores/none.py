"""store none: kept in memory only, gone after a restart or deploy."""

import datetime as dt


class Store:
    writable = True

    def __init__(self):
        self.items = []

    def list(self):
        return self.items[-100:][::-1]

    def add(self, text: str):
        self.items.append({"text": text, "at": dt.datetime.now(dt.timezone.utc).isoformat()})


def open_store(folder: str) -> Store:
    return Store()
