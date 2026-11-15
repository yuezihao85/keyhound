"""Zero-dependency test suite: run with ``python -m unittest discover -s tests``.

Also compatible with ``pytest`` if you have it installed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from keyhound import __version__  # noqa: E402
from keyhound.baseline import dump as dump_baseline, load as load_baseline  # noqa: E402
from keyhound.config import load_config, write_template  # noqa: E402
from keyhound.entropy import (charset_of, looks_like_random,  # noqa: E402
                              shannon_entropy)
from keyhound.ignore import IgnoreMatcher  # noqa: E402
from keyhound.reporters import render_json, render_sarif  # noqa: E402
from keyhound.rules import BUILTIN_RULES, RuleSet, rule_from_dict  # noqa: E402
from keyhound.scanner import Scanner, fingerprint, mask_secret  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures")


def fresh_scanner(**kwargs):
    from keyhound.config import Config
    cfg = kwargs.pop("config", None) or Config()
    cfg.build_allowlist()
    rules = kwargs.pop("rule_set", None) or RuleSet()
    return Scanner(cfg, rules, **kwargs)


class EntropyTests(unittest.TestCase):
    def test_shannon_basics(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertEqual(shannon_entropy("ab"), 1.0)
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)

    def test_charset(self):
        self.assertEqual(charset_of("deadBEEF1234"), "hex")
        self.assertEqual(charset_of("abcDEF123+/="), "base64")
        self.assertEqual(charset_of("abcDEF123-_="), "base64url")
        self.assertEqual(charset_of("hello:world"), "mixed")

    def test_random_gate(self):
        self.assertFalse(looks_like_random("aaaaaaaaaaaaaaaaaaaa"))
        self.assertFalse(looks_like_random("production_env_prod"))
        self.assertFalse(looks_like_random("abc"))
        self.assertTrue(looks_like_random("9fB3kQ7mZ1xP4vT8nR6wL2cY5sH0jD"))


class MaskTests(unittest.TestCase):
    def test_mask_hides_middle(self):
        masked = mask_secret("AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(masked.startswith("AKIA"))
        self.assertIn("*", masked)
        self.assertNotIn("OSFODNN7", masked)

    def test_mask_short(self):
        self.assertEqual(mask_secret("hunter2"), "*******")

    def test_safe_to_show(self):
        header = "-----BEGIN RSA PRIVATE KEY-----"
        self.assertEqual(mask_secret(header, safe_to_show=True), header)

    def test_fingerprint_stability(self):
        a = fingerprint("r", "a/b.py", "S3cr3tValue!")
        b = fingerprint("r", "a/b.py", "S3cr3tValue!")
        c = fingerprint("r", "a/b.py", "OtherValue!")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual(len(a), 16)


class RuleTests(unittest.TestCase):
    def test_all_rules_compile(self):
        rs = RuleSet()
        self.assertEqual(len(rs), len(BUILTIN_RULES))
        ids = {r.id for r in BUILTIN_RULES}
        self.assertEqual(len(ids), len(BUILTIN_RULES), "duplicate rule ids")

    def test_disable(self):
        rs = RuleSet(disabled=["github-pat"])
        self.assertIsNone(rs.by_id("github-pat"))
        self.assertIsNotNone(rs.by_id("aws-access-key-id"))

    def test_bad_group_rejected(self):
        from keyhound.rules import Rule
        bad = Rule("x", "x", "low", r"(abc)", secret_group=2)
        with self.assertRaises(ValueError):
            RuleSet(rules=(bad,))

    def test_custom_rule_from_dict(self):
        rule = rule_from_dict({
            "id": "acme-token",
            "description": "ACME internal token",
            "severity": "high",
            "pattern": r"\bACME-[A-Z0-9]{12}\b",
            "tags": ["internal"],
        })
        rs = RuleSet(custom=[rule])
        self.assertIsNotNone(rs.by_id("acme-token"))
        self.assertEqual(rs.by_id("acme-token").severity, "high")

    def test_custom_rule_missing_field(self):
        with self.assertRaises(ValueError):
            rule_from_dict({"id": "x", "pattern": "y"})


class DetectionTests(unittest.TestCase):
    def test_detects_known_secret_types(self):
        scanner = fresh_scanner()
        result = scanner.scan([os.path.join(FIXTURES, "sample.env")])
        found = {f.rule_id for f in result.findings}
        expected = {
            "aws-access-key-id",
            "aws-secret-access-key",
            "github-pat",
            "stripe-live-key",
            "slack-webhook",
            "connection-string-password",
            "generic-high-entropy-secret",
        }
        for rule_id in expected:
            self.assertIn(rule_id, found, "missing %s; got %s" % (rule_id, sorted(found)))

    def test_clean_file_has_no_findings(self):
        result = fresh_scanner().scan([os.path.join(FIXTURES, "clean.py")])
        self.assertEqual(result.findings, [],
                         "false positives: %s" % [f.to_dict() for f in result.findings])

    def test_no_raw_secret_leaks_into_reports(self):
        secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        text = 'token = "%s"\n' % secret
        result = fresh_scanner().scan_text(text)
        self.assertTrue(result.findings)
        self.assertNotIn(secret, render_json(result))
        self.assertNotIn(secret, render_sarif(result))

    def test_generic_covered_by_specific_rule(self):
        # A GitHub PAT assigned to a token key must be reported once (specific),
        # not twice with an overlapping generic hit.
        text = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"\n'
        result = fresh_scanner().scan_text(text)
        self.assertEqual([f.rule_id for f in result.findings], ["github-pat"])

    def test_pem_and_jwt(self):
        text = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "jwt = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
                "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n")
        found = {f.rule_id for f in fresh_scanner().scan_text(text).findings}
        self.assertIn("private-key-block", found)
        self.assertIn("jwt", found)

    def test_min_severity_filter(self):
        text = "jwt = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n"
        result = fresh_scanner(severity="high").scan_text(text)
        self.assertEqual(result.findings, [])


class IgnoreTests(unittest.TestCase):
    def test_default_dirs(self):
        m = IgnoreMatcher("/repo")
        self.assertTrue(m.is_ignored("node_modules/pkg/index.js", is_dir=False))
        self.assertTrue(m.is_ignored(".git", is_dir=True))

    def test_gitignore_patterns(self):
        m = IgnoreMatcher("/repo")
        m.add_gitignore("", ["*.log", "vendor/", "!keep.log", "/local/"])
        self.assertTrue(m.is_ignored("app.log"))
        self.assertFalse(m.is_ignored("keep.log"))
        # A bare pattern with no separator matches at ANY depth (git semantics).
        self.assertTrue(m.is_ignored("vendor", is_dir=True))
        self.assertTrue(m.is_ignored("sub/vendor", is_dir=True))
        # A leading "/" anchors the pattern to the .gitignore's directory.
        # Use "local" (not "build", which is a DEFAULT_IGNORE_DIR) so the
        # assertion isolates the anchored rule from the default-dir logic.
        self.assertTrue(m.is_ignored("local", is_dir=True))
        self.assertFalse(m.is_ignored("sub/local", is_dir=True))

    def test_nested_gitignore_is_scoped(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "a"))
            os.makedirs(os.path.join(root, "b"))
            with open(os.path.join(root, "a", ".gitignore"), "w") as h:
                h.write("*.secret\n")
            for folder in ("a", "b"):
                with open(os.path.join(root, folder, "leak.secret"), "w") as h:
                    h.write("password = 9fB3kQ7mZ1xP4vT8nR6wL2cY5sH0jD\n")
            result = fresh_scanner().scan([root])
            paths = {os.path.dirname(f.path) for f in result.findings}
            self.assertNotIn("a", paths, "nested .gitignore was ignored")
            self.assertIn("b", paths, "nested rule leaked into sibling dir")

    def test_include_glob(self):
        m = IgnoreMatcher("/repo", include=["*.py"])
        self.assertTrue(m.included("src/main.py"))
        self.assertFalse(m.included("src/main.js"))


class BaselineTests(unittest.TestCase):
    def test_baseline_suppresses_and_new_finding_shows(self):
        text = ("token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n"
                "aws = AKIAIOSFODNN7EXAMPLE\n")
        first = fresh_scanner().scan_text(text)
        fps = {f.fingerprint for f in first.findings}
        self.assertEqual(len(fps), 2)
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "baseline.json")
            self.assertEqual(dump_baseline(path, first.findings, "known"), 2)
            loaded = load_baseline(path)
            second = fresh_scanner(baseline=loaded).scan_text(text)
            self.assertEqual(second.findings, [])
            self.assertEqual(len(second.suppressed), 2)
            changed = text + "slack = https://hooks.slack.com/services/T00000000/B00000000/EXAMPLEONLY000\n"
            third = fresh_scanner(baseline=loaded).scan_text(changed)
            self.assertEqual([f.rule_id for f in third.findings], ["slack-webhook"])

    def test_baseline_survives_line_shift(self):
        text = "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n"
        a = fresh_scanner().scan_text(text)
        b = fresh_scanner().scan_text("# comment\n" + text)
        self.assertEqual(a.findings[0].fingerprint, b.findings[0].fingerprint)

    def test_malformed_baseline(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "b.json")
            with open(path, "w") as h:
                h.write("{not json")
            with self.assertRaises(ValueError):
                load_baseline(path)


class ConfigTests(unittest.TestCase):
    def test_template_roundtrip(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, ".keyhound.json")
            self.assertTrue(write_template(path))
            self.assertFalse(write_template(path))
            cfg = load_config(path)
            self.assertEqual(cfg.min_entropy, 3.5)
            self.assertIn("*.min.js", cfg.exclude)
            self.assertTrue(cfg.use_gitignore)

    def test_custom_rules_from_config(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, ".keyhound.json")
            with open(path, "w") as h:
                json.dump({"custom_rules": [{
                    "id": "acme", "description": "ACME", "severity": "low",
                    "pattern": "ACME-[A-Z0-9]+"
                }]}, h)
            cfg = load_config(path)
            self.assertEqual(len(cfg.custom_rules), 1)
            rs = RuleSet(custom=cfg.custom_rules)
            self.assertIsNotNone(rs.by_id("acme"))

    def test_missing_explicit_config(self):
        with self.assertRaises(IOError):
            load_config(os.path.join(tempfile.gettempdir(), "no_such_keyhound.json"))


class ReportTests(unittest.TestCase):
    def test_json_shape(self):
        result = fresh_scanner().scan([os.path.join(FIXTURES, "sample.env")])
        payload = json.loads(render_json(result))
        self.assertEqual(payload["tool"], "keyhound")
        self.assertEqual(payload["summary"]["total"], len(result.findings))
        self.assertEqual(len(payload["findings"]), len(result.findings))
        for item in payload["findings"]:
            self.assertEqual(set(item), {"rule_id", "description", "severity",
                                         "path", "line", "column", "masked",
                                         "fingerprint", "tags"})

    def test_sarif_shape(self):
        result = fresh_scanner().scan([os.path.join(FIXTURES, "sample.env")])
        payload = json.loads(render_sarif(result))
        self.assertEqual(payload["version"], "2.1.0")
        run = payload["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "keyhound")
        self.assertEqual(len(run["results"]), len(result.findings))
        for res in run["results"]:
            self.assertIn("partialFingerprints", res)
            self.assertIn("startLine", res["locations"][0]["physicalLocation"]["region"])


class CliTests(unittest.TestCase):
    CLI = os.path.join(ROOT, "keyhound-cli.py")

    def run_cli(self, *args, **kwargs):
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        # Decode explicitly as UTF-8: universal_newlines would use the
        # parent's locale (cp936 on zh-CN Windows) and choke on UTF-8 output.
        proc = subprocess.run(
            [sys.executable, self.CLI] + list(args),
            cwd=kwargs.get("cwd", ROOT), input=kwargs.get("input"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
            encoding="utf-8", errors="replace",
        )
        return proc

    def test_version_and_list_rules(self):
        p = self.run_cli("--version")
        self.assertEqual(p.returncode, 0)
        self.assertIn(__version__, p.stdout)
        p = self.run_cli("--list-rules")
        self.assertEqual(p.returncode, 0)
        self.assertIn("aws-access-key-id", p.stdout)

    def test_exit_1_on_findings(self):
        p = self.run_cli("--no-baseline", "--color", "never",
                         os.path.join(FIXTURES, "sample.env"))
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("potential secret", p.stdout)

    def test_exit_0_on_clean(self):
        p = self.run_cli("--no-baseline", "--color", "never",
                         os.path.join(FIXTURES, "clean.py"))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("no secrets found", p.stdout)

    def test_fail_on_threshold(self):
        p = self.run_cli("--no-baseline", "--fail-on", "critical", "--color",
                         "never", os.path.join(FIXTURES, "sample.env"))
        # critical findings exist -> still 1
        self.assertEqual(p.returncode, 1)
        jwt = os.path.join(FIXTURES, "clean.py")
        p2 = self.run_cli("--no-baseline", "--fail-on", "critical", jwt)
        self.assertEqual(p2.returncode, 0)

    def test_disable_rule_changes_result(self):
        p = self.run_cli("--no-baseline", "--format", "json",
                         "--disable-rule", "generic-high-entropy-secret",
                         os.path.join(FIXTURES, "sample.env"))
        payload = json.loads(p.stdout)
        self.assertNotIn("generic-high-entropy-secret",
                         {f["rule_id"] for f in payload["findings"]})

    def test_stdin_mode(self):
        p = self.run_cli("--no-baseline", "-", input="token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n")
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("stdin", p.stdout)

    def test_sarif_output_file(self):
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "out.sarif")
            p = self.run_cli("--no-baseline", "--format", "sarif",
                             "--output", out, os.path.join(FIXTURES, "sample.env"))
            self.assertEqual(p.returncode, 1)
            with open(out, "r", encoding="utf-8") as h:
                payload = json.load(h)
            self.assertEqual(payload["version"], "2.1.0")

    def test_init_baseline_then_clean(self):
        with tempfile.TemporaryDirectory() as root:
            src = os.path.join(root, "app.env")
            with open(src, "w") as h:
                h.write("token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n")
            cwd = root
            p1 = self.run_cli("--init-baseline", "--no-config", src, cwd=cwd)
            self.assertEqual(p1.returncode, 0, p1.stdout + p1.stderr)
            self.assertTrue(os.path.isfile(os.path.join(root, ".keyhound-baseline.json")))
            p2 = self.run_cli("--no-config", src, cwd=cwd)
            self.assertEqual(p2.returncode, 0, p2.stdout + p2.stderr)
            self.assertIn("baseline-suppressed", p2.stdout)

    def test_bad_config_exit_2(self):
        p = self.run_cli("--config", os.path.join(tempfile.gettempdir(), "nope.json"), ".")
        self.assertEqual(p.returncode, 2)
        self.assertIn("config error", p.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
