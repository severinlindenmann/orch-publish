"""Runs with `python -m unittest discover -s tests` (orch-apps test sets DATA_DIR to a fresh temporary folder)."""

import os
import sys
import tempfile
import threading
import unittest
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="{{slug}}-"))

import main  # noqa: E402


class AppTest(unittest.TestCase):
    def test_health_and_start_page(self):
        server = main.make_server(0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            self.assertEqual(urllib.request.urlopen(f"{base}/health").status, 200)
            body = urllib.request.urlopen(f"{base}/").read().decode()
            self.assertIn("<h1>{{name}}</h1>", body)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
