"""Run with: python3 -m unittest discover -s tests -v"""
import contextlib
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "tauri-audit"
sys.path.insert(0, str(SKILL / "scripts"))
import tauri_audit as ta  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"


def run(*argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        code = ta.main(list(argv))
    return code, buf.getvalue()


def rules_of(path, *extra):
    code, out = run(str(path), "--format", "json", "--fail-on", "never", *extra)
    return json.loads(out)


class FixtureTests(unittest.TestCase):
    def test_insecure_fires_all_families(self):
        data = rules_of(FIX / "insecure")
        found = {f["rule"] for f in data["findings"]}
        expected = {
            "CSP-UNSAFE-EVAL", "CSP-UNSAFE-INLINE", "CSP-WILDCARD-SOURCE", "CSP-DANGEROUS-SCHEME",
            "CSP-HOSTED-SCRIPT-HOST", "CSP-INSECURE-SOURCE", "CSP-ASSET-MODIFICATION-DISABLED",
            "GLOBAL-TAURI", "ASSET-PROTOCOL", "UPDATER-NO-PUBKEY", "UPDATER-INSECURE-TRANSPORT",
            "MACOS-PRIVATE-API", "DEFAULT-IDENTIFIER", "REMOTE-WINDOW-URL", "FREEZE-PROTOTYPE",
            "CAP-REMOTE-IPC", "CAP-WILDCARD-WINDOW", "CAP-FS-BROAD", "CAP-SHELL-SCOPE", "CAP-HTTP-BROAD",
            "CAP-OPENER-BROAD", "CAP-UNUSED-PLUGIN", "CARGO-DEVTOOLS", "CMD-UNSCOPED", "CMD-RAW-INPUT",
        }
        self.assertTrue(expected <= found, "missing: %s" % sorted(expected - found))
        self.assertGreaterEqual(data["summary"]["critical"], 4)

    def test_secure_is_clean(self):
        data = rules_of(FIX / "secure")
        self.assertEqual(data["findings"], [], data["findings"])

    def test_exit_codes(self):
        self.assertEqual(run(str(FIX / "insecure"))[0], 1)
        self.assertEqual(run(str(FIX / "insecure"), "--fail-on", "never")[0], 0)
        self.assertEqual(run(str(FIX / "secure"))[0], 0)
        self.assertEqual(run(str(FIX / "does-not-exist"))[0], 2)
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(run(t)[0], 2)

    def test_ignore_flag(self):
        data = rules_of(FIX / "insecure", "--ignore", "CSP-UNSAFE-EVAL")
        self.assertNotIn("CSP-UNSAFE-EVAL", {f["rule"] for f in data["findings"]})

    def test_no_frontend_scan(self):
        data = rules_of(FIX / "insecure", "--no-frontend-scan")
        self.assertNotIn("CAP-UNUSED-PLUGIN", {f["rule"] for f in data["findings"]})

    def test_formats_are_valid(self):
        code, out = run(str(FIX / "insecure"), "--format", "sarif", "--fail-on", "never")
        sarif = json.loads(out)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["runs"][0]["results"])
        code, out = run(str(FIX / "insecure"), "--format", "markdown", "--fail-on", "never")
        self.assertIn("# tauri-audit report", out)
        code, out = run(str(FIX / "insecure"), "--no-color", "--fail-on", "never")
        self.assertNotIn("\033[", out)
        code, out = run(str(FIX / "insecure"), "--format", "html", "--fail-on", "never")
        self.assertIn("ATTACK PATHS".title().replace("Attack Paths", "Attack paths"), out)

    def test_does_not_modify_project(self):
        before = {p: p.read_bytes() for p in FIX.rglob("*") if p.is_file()}
        run(str(FIX / "insecure"))
        run(str(FIX / "secure"))
        after = {p: p.read_bytes() for p in FIX.rglob("*") if p.is_file()}
        self.assertEqual(before, after)


class V2FeatureTests(unittest.TestCase):
    def test_attack_paths(self):
        data = rules_of(FIX / "insecure")
        ids = {p["id"] for p in data["attackPaths"]}
        self.assertEqual(ids, {"PATH-REMOTE-TAKEOVER", "PATH-XSS-TO-RCE", "PATH-UPDATE-HIJACK",
                               "PATH-XSS-TO-IPC", "PATH-FILE-EXFIL"})
        self.assertEqual(rules_of(FIX / "secure")["attackPaths"], [])

    def test_score_and_grade(self):
        bad, good = rules_of(FIX / "insecure"), rules_of(FIX / "secure")
        self.assertEqual((good["score"], good["grade"]), (100, "A"))
        self.assertEqual(bad["grade"], "F")
        self.assertEqual(ta.grade_of(90), "A")
        self.assertEqual(ta.grade_of(89), "B")
        self.assertEqual(ta.grade_of(59), "D")
        self.assertEqual(ta.grade_of(39), "F")

    def test_badge(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / "b.svg"
            run(str(FIX / "secure"), "--badge", str(out))
            svg = out.read_text()
            self.assertTrue(svg.startswith("<svg"))
            self.assertIn("A 100", svg)

    def test_html_report_escapes_content(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "tauri.conf.json").write_text(
                '{"identifier":"com.tauri.dev","app":{"security":{"csp":"default-src \'self\' <script>alert(1)</script>"}}}')
            code, out = run(t, "--format", "html", "--fail-on", "never")
            self.assertTrue(out.startswith("<!doctype html>"))
            self.assertNotIn("<script>alert(1)</script>", out)

    def test_baseline_roundtrip(self):
        with tempfile.TemporaryDirectory() as t:
            proj = Path(t) / "proj"
            proj.mkdir()
            conf = proj / "tauri.conf.json"
            conf.write_text('{"app":{"security":{"csp":null}}}')
            base = Path(t) / "base.json"
            self.assertEqual(run(str(proj), "--write-baseline", str(base))[0], 0)
            self.assertEqual(run(str(proj), "--baseline", str(base))[0], 0)
            data = json.loads(run(str(proj), "--baseline", str(base), "--format", "json")[1])
            self.assertEqual(data["findings"], [])
            self.assertGreater(data["suppressedByBaseline"], 0)
            conf.write_text('{"app":{"withGlobalTauri":true,"security":{"csp":null}}}')
            data = json.loads(run(str(proj), "--baseline", str(base), "--format", "json", "--fail-on", "never")[1])
            self.assertEqual([f["rule"] for f in data["findings"]], ["GLOBAL-TAURI"])
            self.assertEqual(run(str(proj), "--baseline", str(base), "--fail-on", "medium")[0], 1)
            self.assertEqual(run(str(proj), "--baseline", str(Path(t) / "nope.json"))[0], 2)


class ParserTests(unittest.TestCase):
    def test_jsonc(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "x.json"
            p.write_text('{ /* c */ "a": "http://x//y", // tail\n "b": [1,2,], }')
            self.assertEqual(ta.load_file(p), {"a": "http://x//y", "b": [1, 2]})

    @unittest.skipIf(ta.tomllib is None, "needs Python 3.11+")
    def test_toml_capability(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "src-tauri" / "capabilities").mkdir(parents=True)
            (root / "src-tauri" / "tauri.conf.json").write_text('{"app":{"security":{"csp":"default-src \'self\'","freezePrototype":true}}}')
            (root / "src-tauri" / "capabilities" / "x.toml").write_text(
                'identifier = "x"\nwindows = ["*"]\npermissions = ["fs:allow-home-read-recursive"]\n')
            rules = {f["rule"] for f in rules_of(root)["findings"]}
            self.assertIn("CAP-WILDCARD-WINDOW", rules)
            self.assertIn("CAP-FS-BROAD", rules)

    def test_bad_json_reports_parse_error_not_crash(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "tauri.conf.json").write_text("{ nope")
            rules = {f["rule"] for f in rules_of(t)["findings"]}
            self.assertIn("PARSE-ERROR", rules)

    def test_csp_object_form_and_missing(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "tauri.conf.json").write_text(
                '{"app":{"security":{"csp":{"default-src":"\'self\'","script-src":["\'self\'","\'unsafe-eval\'"]}}}}')
            self.assertIn("CSP-UNSAFE-EVAL", {f["rule"] for f in rules_of(t)["findings"]})
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "tauri.conf.json").write_text('{"app":{"security":{"csp":null}}}')
            self.assertIn("CSP-MISSING", {f["rule"] for f in rules_of(t)["findings"]})

    def test_v1_detection(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "tauri.conf.json").write_text(
                '{"tauri":{"allowlist":{"all":true,"fs":{"all":true}},"security":{"csp":null}}}')
            rules = {f["rule"] for f in rules_of(t)["findings"]}
            self.assertTrue({"V1-DETECTED", "V1-ALLOWLIST-ALL", "V1-ALLOWLIST-MODULE-ALL", "CSP-MISSING"} <= rules)

    def test_capability_file_directly(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "cap.json"
            p.write_text('{"identifier":"c","windows":["*"],"permissions":["core:default"]}')
            self.assertIn("CAP-WILDCARD-WINDOW", {f["rule"] for f in rules_of(p)["findings"]})

    def test_project_ignore_file(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "tauri.conf.json").write_text('{"app":{"security":{"csp":null}}}')
            (Path(t) / ".tauri-audit.json").write_text('{"ignore":["CSP-MISSING"]}')
            self.assertNotIn("CSP-MISSING", {f["rule"] for f in rules_of(t)["findings"]})


class ConsistencyTests(unittest.TestCase):
    def test_every_rule_is_documented(self):
        doc = (SKILL / "references" / "rules.md").read_text()
        missing = [r for r in ta.RULES if "`%s`" % r not in doc]
        self.assertEqual(missing, [], "undocumented rules: %s" % missing)

    def test_every_documented_rule_exists(self):
        doc = (SKILL / "references" / "rules.md").read_text()
        ids = set(re.findall(r"^### `([A-Z0-9-]+)`", doc, re.M))
        self.assertEqual(sorted(ids - set(ta.RULES)), [])

    def test_versions_match(self):
        plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
        self.assertEqual(plugin["version"], ta.__version__)

    def test_skill_frontmatter(self):
        text = (SKILL / "SKILL.md").read_text()
        m = re.match(r"^---\nname: ([a-z0-9-]+)\ndescription: (.+?)\n---\n", text, re.S)
        self.assertTrue(m)
        self.assertEqual(m.group(1), "tauri-audit")
        self.assertLessEqual(len(m.group(2)), 1024)


if __name__ == "__main__":
    unittest.main()
