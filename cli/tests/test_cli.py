"""CLI tests. Run: cd cli && uv run --with cryptography python -m unittest discover -s tests -t ."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import orch_apps as oa  # noqa: E402

PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")
LOADER = Path(__file__).resolve().parents[2] / "host" / "orch_apps_host" / "loader.html"


class Fake:
    """Stands in for ssh and rsync: records argv and answers like the host."""

    def __init__(self):
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        if argv[0] == "ssh":
            words = argv[argv.index("orch-apps@host.test") + 1:]
            if words[:2] == ["share", "put"]:
                return subprocess.CompletedProcess(argv, 0, json.dumps({"id": words[2], "access": words[4]}), "")
            if words[:2] == ["app", "deploy"]:
                return subprocess.CompletedProcess(argv, 0, json.dumps(
                    {"slug": words[2], "result": "deployed", "version": "abc123", "status": "running"}), "")
            return subprocess.CompletedProcess(argv, 0, "{}", "")
        if argv[0] == "rsync":
            return subprocess.CompletedProcess(argv, 0, "Number of files: 4 (reg: 3, dir: 1)\n"
                                               "Number of regular files transferred: 1\nTotal bytes sent: 512\n", "")
        return oa._run(argv, **kw)


class CliCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="orch-apps-cli-"))
        oa.STATE = self.tmp / "state"
        oa.CONFIG = self.tmp / "config.toml"
        oa.CONFIG.write_text('ssh = "orch-apps@host.test"\ndomain = "app.test"\n')
        os.environ["ORCH_APPS_DIR"] = str(self.tmp / "apps")
        self.fake = Fake()
        oa.runner = self.fake

    def tearDown(self):
        oa.runner = oa._run
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cli(self, *argv) -> tuple[int, str]:
        from io import StringIO
        from contextlib import redirect_stderr, redirect_stdout
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = oa.main(list(argv))
        return code, out.getvalue() + err.getvalue()

    def page(self, extra_head: str = "") -> Path:
        site = self.tmp / "site"
        (site / "img").mkdir(parents=True)
        (site / "img" / "dot.png").write_bytes(PNG)
        (site / "style.css").write_text("body{background:url(img/dot.png)}")
        (site / "app.js").write_text("document.title='ok'</script>")
        (site / "index.html").write_text(
            f'<!doctype html><head>{extra_head}<link rel="stylesheet" href="style.css"></head>'
            '<img src="img/dot.png" alt="dot"><a href="other.html">nav</a><script src="app.js"></script>')
        return site


class ShareTests(CliCase):
    def test_sealed_inlines_everything_and_opens_with_the_key(self):
        site = self.page()
        code, out = self.cli("share", str(site / "index.html"), "--ticket", "INT-0028", "--access", "sealed", "--json")
        self.assertEqual(code, 0, out)
        res = json.loads(out)
        self.assertNotIn("secret", res)
        stage = oa.STATE / "stage" / res["id"]
        self.assertEqual(oct(stage.stat().st_mode & 0o777), "0o700")
        meta = json.loads((stage / "meta.json").read_text())
        html = oa.unseal((stage / "payload" / "sealed.bin").read_bytes(), meta["secret"], res["id"])
        self.assertEqual(html.count("data:image/png;base64,"), 2)  # the <img> and the CSS background
        self.assertNotIn('src="app.js"', html)
        self.assertIn("<\\/script>", html)  # a closing tag inside the script cannot end it early
        self.assertIn('href="other.html"', html)  # navigation stays
        self.assertEqual(sorted(p.name for p in (stage / "payload").iterdir()), ["sealed.bin"])

    def test_sealed_refuses_external_resources_unless_allowed(self):
        site = self.page('<link rel="stylesheet" href="https://fonts.example/css">')
        code, out = self.cli("share", str(site), "--ticket", "INT-0028", "--access", "sealed")
        self.assertEqual(code, 2)
        self.assertIn("https://fonts.example/css", out)
        self.assertFalse(list((oa.STATE / "stage").iterdir()), "a refused share leaves no stage behind")
        code, out = self.cli("share", str(site), "--ticket", "INT-0028", "--access", "sealed", "--allow-external")
        self.assertEqual(code, 0, out)

    def test_public_file_takes_the_files_it_uses(self):
        site = self.page()
        (site / "unrelated.bin").write_bytes(b"x" * 10)
        code, out = self.cli("share", str(site / "index.html"), "--ticket", "INT-0028", "--access", "public", "--json")
        payload = oa.STATE / "stage" / json.loads(out)["id"] / "payload"
        names = sorted(p.relative_to(payload).as_posix() for p in payload.rglob("*") if p.is_file())
        self.assertEqual(names, ["app.js", "img/dot.png", "index.html", "style.css"])
        self.assertIn("other.html", out)  # reported as not found next to the page

    def test_publish_prints_once_and_forgets_the_secret(self):
        site = self.page()
        _, out = self.cli("share", str(site), "--ticket", "INT-0028", "--access", "secret", "--json")
        sid = json.loads(out)["id"]
        code, out = self.cli("publish", sid, "--json")
        self.assertEqual(code, 0, out)
        url = json.loads(out)["url"]
        self.assertRegex(url, rf"^https://app.test/s/{sid}\.[A-Za-z0-9_-]{{32}}/$")
        token = url.split(".", 2)[-1].strip("/").split(".")[-1]
        put = next(c for c in self.fake.calls if "put" in c)
        self.assertIn("--token-hash", put)
        self.assertNotIn(token, " ".join(put))
        self.assertFalse((oa.STATE / "stage" / sid).exists())
        self.assertNotIn(token, (oa.STATE / "published.jsonl").read_text())
        self.assertEqual(self.cli("reveal", sid)[0], 2)

    def test_hold_then_reveal_once(self):
        site = self.page()
        _, out = self.cli("share", str(site), "--ticket", "INT-0028", "--access", "sealed", "--json")
        sid = json.loads(out)["id"]
        code, out = self.cli("publish", sid, "--hold", "--json")
        self.assertIsNone(json.loads(out)["url"])
        self.assertIn('"published"', self.cli("staged", "--json")[1])
        code, out = self.cli("reveal", sid, "--json")
        self.assertIn("#k=", json.loads(out)["url"])
        self.assertEqual(self.cli("reveal", sid)[0], 2, "the second reveal finds nothing")

    def test_discard_drops_an_unpublished_stage_only(self):
        site = self.page()
        sid = json.loads(self.cli("share", str(site), "--ticket", "INT-0029", "--access", "sealed", "--json")[1])["id"]
        self.assertEqual(self.cli("discard", sid)[0], 0)
        self.assertFalse((oa.STATE / "stage" / sid).exists())
        sid = json.loads(self.cli("share", str(site), "--ticket", "INT-0029", "--access", "public", "--json")[1])["id"]
        self.cli("publish", sid, "--hold")
        code, out = self.cli("discard", sid)
        self.assertEqual(code, 2)
        self.assertIn("already published", out)

    def test_expiry_values(self):
        self.assertEqual(oa.expiry("done"), "none")
        self.assertTrue(oa.expiry("7d").endswith("Z"))
        with self.assertRaises(oa.Refused):
            oa.expiry("next week")

    def test_missing_config_is_a_clear_refusal(self):
        oa.CONFIG.unlink()
        code, out = self.cli("status")
        self.assertEqual(code, 2)
        self.assertIn("orch-apps setup", out)


class AppTests(CliCase):
    def new(self, slug, stack, store):
        code, out = self.cli("new", slug, "--stack", stack, "--store", store)
        self.assertEqual(code, 0, out)
        return Path(os.environ["ORCH_APPS_DIR"]) / slug

    def test_refusals(self):
        self.assertIn("invalid slug", self.cli("new", "Bad_Slug", "--stack", "node", "--store", "none")[1])
        self.assertIn("reserved", self.cli("new", "admin", "--stack", "node", "--store", "none")[1])
        self.assertIn("static app can only", self.cli("new", "x-static", "--stack", "static", "--store", "sqlite")[1])
        app = self.new("odd-app", "node", "none")
        (app / "app.toml").write_text('name="x"\nstack="ruby"\nstore="none"\nstart="x"\n')
        code, out = self.cli("test", "odd-app")
        self.assertEqual(code, 2)
        self.assertIn("stack must be one of", out)
        (app / "app.toml").write_text('name="x"\nstack="node"\nstore="mongo"\nstart="x"\n')
        self.assertIn("store must be one of", self.cli("test", "odd-app")[1])

    def test_app_without_health_fails(self):
        app = self.new("no-health", "node", "none")
        (app / "server.js").write_text(
            'import http from "node:http";\n'
            'http.createServer((q, r) => { r.statusCode = q.url === "/" ? 200 : 404; r.end("<h1>x</h1>"); })'
            '.listen(Number(process.env.PORT), "127.0.0.1");\n')
        shutil.rmtree(app / "test")
        (app / "app.toml").write_text('name="x"\nstack="node"\nstore="none"\nstart="node server.js"\n')
        oa.HEALTH_SECONDS = 2
        code, out = self.cli("test", "no-health")
        oa.HEALTH_SECONDS = 30
        self.assertEqual(code, 1)
        self.assertIn("/health did not answer 200", out)

    def test_app_that_ignores_base_path_fails(self):
        app = self.new("no-base", "node", "none")
        js = (app / "server.js").read_text().replace("${BASE}/style.css", "/style.css")
        (app / "server.js").write_text(js)
        code, out = self.cli("test", "no-base")
        self.assertEqual(code, 1)
        self.assertIn("links outside its base path", out)
        self.assertIn("/style.css", out)

    def test_deploy_refuses_when_test_fails_and_reports_upload(self):
        app = self.new("deploy-me", "node", "json")
        (app / "server.js").write_text("process.exit(3)\n")
        code, out = self.cli("deploy", "deploy-me", "--ticket", "INT-0028")
        self.assertEqual(code, 2)
        self.assertIn("nothing was deployed", out)
        self.assertFalse(any(c[0] == "rsync" for c in self.fake.calls))

    def test_deploy_secret_keeps_only_the_hash(self):
        self.new("secret-app", "static", "none")
        code, out = self.cli("deploy", "secret-app", "--ticket", "INT-0028", "--access", "secret", "--json")
        self.assertEqual(code, 0, out)
        res = json.loads(out)
        token = res["secret_url"].split("secret-app.")[1].strip("/")
        stored = (oa.STATE / "apps" / "secret-app.json").read_text()
        self.assertNotIn(token, stored)
        self.assertEqual(res["upload"]["transferred"], 1)
        rs = next(c for c in self.fake.calls if c[0] == "rsync")
        self.assertIn(".venv", rs)  # local dependency folders are never uploaded
        code, out = self.cli("deploy", "secret-app", "--ticket", "INT-0028", "--access", "secret", "--json")
        self.assertNotIn("secret_url", json.loads(out), "a redeploy keeps the same secret link")


class LoaderCompat(CliCase):
    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_host_loader_opens_a_cli_blob(self):
        blob, key = oa.seal("<h1>Grüezi</h1>", "abc123def4")
        src = LOADER.read_text().split("/*open*/")[1]
        script = (f"const openSealed = new Function(`{src.replace('`', '\\\\`')}; return openSealed;`)();"
                  f"openSealed('{key}', new Uint8Array(Buffer.from('{base64.b64encode(blob).decode()}', 'base64')),"
                  f" 'abc123def4').then(t => console.log(t)).catch(e => {{ console.error(e); process.exit(1); }});")
        res = subprocess.run(["node", "-e", script], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.strip(), "<h1>Grüezi</h1>")


if __name__ == "__main__":
    unittest.main()
