"""Host tests on a laptop: temporary folders, a recorded fake for systemctl/caddy/npm/uv, a real share server.

Run: python3 -m unittest discover -s host/tests -t host
"""

from __future__ import annotations

import datetime as dt
import http.client
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from orch_apps_host import apps, backup, caddy, cli, server, shares, util

TOKEN = "Vd8xQ2kP7rT4nW1zAb3c"


class Fake:
    """Stands in for util.runner: records argv, answers like the real tools."""

    def __init__(self):
        self.calls: list[list[str]] = []
        self.caddy_ok = True

    def __call__(self, argv, cwd=None, env=None, timeout=None):
        self.calls.append(list(argv))
        rc, out = 0, ""
        if argv[0] == "caddy" and argv[1] == "validate":
            # mimic Caddy refusing a snippet with an unknown directive
            bad = any("bogus_directive" in p.read_text() for p in util.P.caddy.glob("*.caddy"))
            rc = 0 if (self.caddy_ok and not bad) else 1
        if argv[0] == "npm":
            (Path(cwd) / "node_modules" / "left-pad").mkdir(parents=True)
        if argv[0] == "uv" and argv[1] == "sync":
            (Path(env["UV_PROJECT_ENVIRONMENT"]) / "bin").mkdir(parents=True)
        if argv[0] == "systemctl" and argv[1] == "show":
            out = "ActiveState=active\nMemoryCurrent=48234496\nActiveEnterTimestamp=Wed 2026-10-07 18:00:00 CEST\n"
        return subprocess.CompletedProcess(argv, rc, out, "")

    def did(self, *prefix) -> int:
        return sum(1 for c in self.calls if c[:len(prefix)] == list(prefix))


class HostCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="orch-apps-test-"))
        util.configure(util.Paths(root=self.tmp / "srv", data=self.tmp / "data", web_state=self.tmp / "web",
                                  caddy=self.tmp / "caddy", backups=self.tmp / "backups",
                                  web_group="orch-apps-web-test-none", share_port=8790))
        self.fake = Fake()
        util.runner = self.fake
        self.health = {"ok": True}
        util.http_ok = lambda url, timeout=2.0: self.health["ok"]
        apps.HEALTH_SECONDS = 0.6

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # helpers
    def upload_share(self, share_id: str, files: dict[str, bytes]) -> None:
        d = util.P.incoming / "shares" / share_id
        for name, data in files.items():
            (d / name).parent.mkdir(parents=True, exist_ok=True)
            (d / name).write_bytes(data)

    def upload_app(self, slug: str, files: dict[str, str]) -> None:
        d = util.P.incoming / "apps" / slug
        shutil.rmtree(d, ignore_errors=True)
        for name, text in files.items():
            (d / name).parent.mkdir(parents=True, exist_ok=True)
            (d / name).write_text(text)


NODE_APP = {
    "app.toml": 'name = "Hello"\nstack = "node"\nstore = "sqlite"\nstart = "node server.js"\n',
    "server.js": "// v1\n",
    "package.json": '{"name":"hello"}',
    "package-lock.json": '{"lockfileVersion":3}',
}


class ShareTests(HostCase):
    def test_put_public_and_listing_has_no_token(self):
        self.upload_share("abc123", {"index.html": b"<h1>hi</h1>", "img/a.png": b"\x89PNG"})
        meta = shares.put("abc123", "public", "INT-0001", "2099-01-01T00:00:00Z")
        self.assertEqual(meta["files"], 2)
        self.assertFalse((util.P.incoming / "shares" / "abc123").exists())

        self.upload_share("sec456", {"index.html": b"x"})
        shares.put("sec456", "secret", "INT-0001", "none", util.token_hash(TOKEN))
        dump = json.dumps(cli.status())
        self.assertNotIn(util.token_hash(TOKEN), dump)
        self.assertNotIn(TOKEN, dump)

    def test_refusals(self):
        self.upload_share("abc123", {"page.html": b"x"})
        with self.assertRaisesRegex(util.Refused, "index.html"):
            shares.put("abc123", "public", "INT-0001", "none")
        with self.assertRaisesRegex(util.Refused, "share id"):
            shares.put("../etc", "public", "INT-0001", "none")
        with self.assertRaisesRegex(util.Refused, "token hash"):
            shares.put("abc123", "secret", "INT-0001", "none")
        with self.assertRaisesRegex(util.Refused, "ticket"):
            shares.put("abc123", "public", "rm -rf", "none")
        with self.assertRaisesRegex(util.Refused, "past"):
            shares.put("abc123", "public", "INT-0001", "2001-01-01T00:00:00Z")

    def test_symlink_and_hardlink_in_upload_are_refused(self):
        self.upload_share("lnk001", {"index.html": b"x"})
        (util.P.incoming / "shares" / "lnk001" / "passwd").symlink_to("/etc/passwd")
        with self.assertRaisesRegex(util.Refused, "regular files"):
            shares.put("lnk001", "public", "INT-0001", "none")
        self.upload_share("lnk002", {"index.html": b"x"})
        outside = self.tmp / "outside.txt"
        outside.write_text("secret")
        os.link(outside, util.P.incoming / "shares" / "lnk002" / "copy.txt")
        with self.assertRaisesRegex(util.Refused, "hard links"):
            shares.put("lnk002", "public", "INT-0001", "none")

    def test_sealed_needs_one_blob(self):
        self.upload_share("seal01", {"index.html": b"plain"})
        with self.assertRaisesRegex(util.Refused, "sealed.bin"):
            shares.put("seal01", "sealed", "INT-0001", "none")
        self.upload_share("seal02", {"sealed.bin": b"OAS1" + b"n" * 12 + b"c" * 40})
        self.assertEqual(shares.put("seal02", "sealed", "INT-0001", "none")["access"], "sealed")

    def test_revoke_extend_sweep(self):
        self.upload_share("abc123", {"index.html": b"x"})
        shares.put("abc123", "public", "INT-0001", "2099-01-01T00:00:00Z")
        shares.extend("abc123", "2099-02-01T00:00:00Z")
        self.assertEqual(shares.read_meta("abc123")["expires"], "2099-02-01T00:00:00Z")
        shares.revoke("abc123")
        self.assertFalse((util.P.shares / "abc123" / "files").exists())
        self.assertEqual(shares.state_of(shares.read_meta("abc123")), "revoked")
        with self.assertRaisesRegex(util.Refused, "revoked"):
            shares.extend("abc123", "none")

        self.upload_share("old001", {"index.html": b"x"})
        shares.put("old001", "public", "INT-0001", "2099-01-01T00:00:00Z")
        meta = shares.read_meta("old001")
        meta["expires"] = "2020-01-01T00:00:00Z"
        util.write_json(util.P.shares / "old001" / "meta.json", meta)
        done = shares.sweep()
        self.assertTrue(any("old001" in d for d in done))
        self.assertFalse((util.P.shares / "old001").exists())  # older than 30 days: tombstone gone too


class AppTests(HostCase):
    def test_node_deploy_unchanged_and_deps_reused(self):
        self.upload_app("hello", NODE_APP)
        r = apps.deploy("hello", "INT-0027", "public")
        self.assertEqual(r["result"], "deployed")
        self.assertEqual(self.fake.did("npm", "ci"), 1)
        self.assertEqual(self.fake.did("systemctl", "restart", "orch-app@hello.service"), 1)
        snippet = (util.P.caddy / "hello.caddy").read_text()
        self.assertIn("handle_path /hello/*", snippet)
        self.assertIn("reverse_proxy 127.0.0.1:4201", snippet)
        run_sh = (util.P.apps / "hello" / "run.sh").read_text()
        self.assertIn("exec node server.js", run_sh)
        env = (util.P.apps / "hello" / "env").read_text()
        self.assertIn("BASE_PATH=/hello", env)
        self.assertIn("DATA_DIR=/var/lib/orch-apps-data/hello", env)

        self.upload_app("hello", NODE_APP)
        self.assertEqual(apps.deploy("hello", "INT-0027", "public")["result"], "unchanged")

        self.upload_app("hello", {**NODE_APP, "server.js": "// v2\n"})
        self.assertEqual(apps.deploy("hello", "INT-0027", "public")["result"], "deployed")
        self.assertEqual(self.fake.did("npm", "ci"), 1, "same lockfile: no second install")

    def test_only_the_changed_app_restarts(self):
        self.upload_app("hello", NODE_APP)
        apps.deploy("hello", "INT-0027", "public")
        self.upload_app("hello-py", {
            "app.toml": 'name = "Hello Py"\nstack = "python"\nstore = "json"\nstart = "python3 main.py"\n',
            "main.py": "print(1)\n", "pyproject.toml": "[project]\nname='x'\n", "uv.lock": "version = 1\n"})
        apps.deploy("hello-py", "INT-0027", "public")
        self.assertEqual(self.fake.did("systemctl", "restart", "orch-app@hello.service"), 1)
        self.assertEqual(self.fake.did("systemctl", "restart", "orch-app@hello-py.service"), 1)
        self.assertEqual(apps.load_state()["apps"]["hello-py"]["port"], 4202)

    def test_failed_deploy_rolls_back(self):
        self.upload_app("hello", NODE_APP)
        v1 = apps.deploy("hello", "INT-0027", "public")["version"]
        self.health["ok"] = False
        calls = {"n": 0}

        def flaky(url, timeout=2.0):  # the new release never answers, the old one does after the switch back
            calls["n"] += 1
            return os.readlink(util.P.apps / "hello" / "current").endswith(v1)
        util.http_ok = flaky
        self.upload_app("hello", {**NODE_APP, "server.js": "// broken\n"})
        with self.assertRaisesRegex(util.Failed, "serving again"):
            apps.deploy("hello", "INT-0027", "public")
        app = apps.load_state()["apps"]["hello"]
        self.assertEqual(app["version"], v1)
        self.assertEqual(app["status"], "running")
        self.assertTrue(os.readlink(util.P.apps / "hello" / "current").endswith(v1))

    def test_invalid_caddy_is_never_applied(self):
        self.upload_app("hello", NODE_APP)
        apps.deploy("hello", "INT-0027", "public")
        good = (util.P.caddy / "hello.caddy").read_text()
        reloads = self.fake.did("systemctl", "reload", "caddy")
        with self.assertRaisesRegex(util.Failed, "Caddy refused"):
            caddy.apply("hello", good + "bogus_directive\n")
        self.assertEqual((util.P.caddy / "hello.caddy").read_text(), good)
        self.assertEqual(self.fake.did("systemctl", "reload", "caddy"), reloads)

    def test_secret_static_stop_start_delete(self):
        self.upload_app("notes", {"app.toml": 'name = "Notes"\nstack = "static"\nstore = "markdown"\n',
                                  "index.html": "<h1>notes</h1>"})
        apps.deploy("notes", "INT-0027", "secret", util.token_hash(TOKEN))
        snippet = (util.P.caddy / "notes.caddy").read_text()
        self.assertIn("forward_auth 127.0.0.1:8790", snippet)
        self.assertIn("file_server", snippet)
        apps.stop("notes")
        self.assertIn("This app is stopped", (util.P.caddy / "notes.caddy").read_text())
        apps.start("notes")
        self.assertNotIn("stopped", (util.P.caddy / "notes.caddy").read_text())
        (util.P.data / "notes").mkdir(parents=True)
        (util.P.data / "notes" / "x.json").write_text("{}")
        r = apps.delete("notes")
        self.assertFalse((util.P.caddy / "notes.caddy").exists())
        self.assertTrue(Path(r["data_archived"]).exists())
        self.assertNotIn("notes", apps.load_state()["apps"])

    def test_manifest_refusals(self):
        for files, msg in (
            ({"server.js": ""}, "app.toml is missing"),
            ({"app.toml": 'name="x"\nstack="ruby"\nstore="none"\n'}, "stack"),
            ({"app.toml": 'name="x"\nstack="node"\nstore="mongo"\nstart="x"\n'}, "store"),
            ({"app.toml": 'name="x"\nstack="node"\nstore="none"\n'}, "start"),
            ({"app.toml": 'name="x"\nstack="node"\nstore="none"\nstart="a"\n', "node_modules/x.js": ""},
             "node_modules"),
        ):
            self.upload_app("bad-app", files)
            with self.assertRaisesRegex(util.Refused, msg):
                apps.deploy("bad-app", "INT-0027", "public")
        for slug in ("admin", "s", "Bad", "a", "x/y"):
            with self.assertRaises(util.Refused):
                apps.deploy(slug, "INT-0027", "public")


class CliTests(HostCase):
    def test_exit_codes(self):
        self.assertEqual(cli.main(["share", "revoke", "nothere1"]), 2)
        self.assertEqual(cli.main(["share", "rm", "x"]), 2)
        self.assertEqual(cli.main(["status", "--json"]), 0)
        self.assertEqual(cli.main(["app", "logs", "../../etc", "--lines", "5"]), 2)
        self.assertEqual(cli.main(["sweep"]), 0)

    def test_backup_keeps_seven(self):
        import sqlite3
        (util.P.data / "hello").mkdir(parents=True)
        db = sqlite3.connect(util.P.data / "hello" / "app.db")
        db.execute("create table t(x)")
        db.execute("insert into t values (42)")
        db.commit()
        db.close()
        for i in range(9):
            (util.P.backups).mkdir(parents=True, exist_ok=True)
            (util.P.backups / f"bak-2026010{i}-000000.tar.gz").write_bytes(b"old")
        r = backup.run_backup()
        self.assertEqual(r["files"], 1)
        self.assertEqual(len(list(util.P.backups.glob("bak-*.tar.gz"))), 7)


class ServerTests(HostCase):
    def setUp(self):
        super().setUp()
        self.srv = server.make_server(port=0)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        super().tearDown()

    def get(self, path, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", path, headers={"Cookie": cookie} if cookie else {})
        r = c.getresponse()
        body = r.read()
        return r.status, dict(r.getheaders()), body

    def test_public_share(self):
        self.upload_share("pub001", {"index.html": b"<h1>hi</h1>", "app.js": b"1"})
        shares.put("pub001", "public", "INT-0001", "none")
        st, h, body = self.get("/s/pub001/")
        self.assertEqual((st, body), (200, b"<h1>hi</h1>"))
        self.assertTrue(h["Content-Security-Policy"].startswith("sandbox"))
        self.assertEqual(self.get("/s/pub001")[0], 303)
        self.assertEqual(self.get("/s/pub001/app.js")[0], 200)
        self.assertEqual(self.get("/s/pub001/../../meta.json")[0], 404)
        self.assertEqual(self.get("/s/pub001/%2e%2e/meta.json")[0], 404)
        self.assertEqual(self.get("/s/nothere/")[0], 404)
        self.assertEqual(shares.listing()[0]["views"], 1)

    def test_secret_share_token_then_cookie(self):
        self.upload_share("sec001", {"index.html": b"secret page"})
        shares.put("sec001", "secret", "INT-0001", "none", util.token_hash(TOKEN))
        self.assertEqual(self.get("/s/sec001/")[0], 404)
        self.assertEqual(self.get("/s/sec001.WrongTokenWrongToken/")[0], 404)
        st, h, _ = self.get(f"/s/sec001.{TOKEN}/")
        self.assertEqual((st, h["Location"]), (303, "/s/sec001/"))
        cookie = h["Set-Cookie"].split(";")[0]
        self.assertIn("Path=/s/sec001/", h["Set-Cookie"])
        self.assertEqual(self.get("/s/sec001/", cookie)[:3:2], (200, b"secret page"))
        self.assertEqual(self.get("/s/sec001/", cookie.replace("=", "=0"))[0], 404)

    def test_sealed_share_serves_loader_and_blob_only(self):
        blob = b"OAS1" + b"n" * 12 + b"c" * 40
        self.upload_share("seal01", {"sealed.bin": blob})
        shares.put("seal01", "sealed", "INT-0001", "none")
        st, h, body = self.get("/s/seal01/")
        self.assertEqual(st, 200)
        self.assertIn(b'const SHARE_ID = "seal01"', body)
        self.assertEqual(self.get("/s/seal01/blob")[2], blob)
        self.assertEqual(self.get("/s/seal01/sealed.bin")[0], 404)

    def test_expired_and_revoked_answer_410(self):
        self.upload_share("gone01", {"index.html": b"x"})
        shares.put("gone01", "public", "INT-0001", "none")
        shares.revoke("gone01")
        self.assertEqual(self.get("/s/gone01/")[0], 410)
        self.upload_share("gone02", {"index.html": b"x"})
        shares.put("gone02", "public", "INT-0001", "none")
        meta = shares.read_meta("gone02")
        meta["expires"] = util.iso(util.now() - dt.timedelta(minutes=1))
        util.write_json(util.P.shares / "gone02" / "meta.json", meta)
        self.assertEqual(self.get("/s/gone02/")[0], 410)

    def test_secret_app_token_cookie_and_forward_auth(self):
        self.upload_app("notes", {"app.toml": 'name = "Notes"\nstack = "static"\nstore = "none"\n',
                                  "index.html": "x"})
        apps.deploy("notes", "INT-0027", "secret", util.token_hash(TOKEN))
        self.assertEqual(self.get("/_auth/app/notes")[0], 404)
        st, h, _ = self.get(f"/notes.{TOKEN}/")
        self.assertEqual((st, h["Location"]), (303, "/notes/"))
        cookie = h["Set-Cookie"].split(";")[0]
        self.assertEqual(self.get("/_auth/app/notes", cookie)[0], 200)
        self.assertEqual(self.get("/notes.WrongTokenWrongToken/")[0], 404)


if __name__ == "__main__":
    unittest.main()
