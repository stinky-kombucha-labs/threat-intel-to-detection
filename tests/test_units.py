import json
import unittest
from pathlib import Path

from intel_to_rule import sigma_eval
from intel_to_rule.coverage import indicator_covers
from intel_to_rule.rule_formats import FORMATS, load_rules
from intel_to_rule.rule_formats.base import UpdateMeta, add_to_query_list
from intel_to_rule.util import norm_ioc, version_tuple

ROOT = Path(__file__).resolve().parents[1]
META = UpdateMeta(date="2026-10-23", cves=["CVE-2099-0001"], references=["https://example.com/a"], techniques=[])
DIRS = {"splunk": "rules/splunk", "sigma": "rules/sigma", "elastic": "rules/elastic"}


class RuleFiles(unittest.TestCase):
    def test_every_rule_loads_and_validates(self):
        rules = load_rules(DIRS, ROOT)
        self.assertGreaterEqual(len(rules), 12)
        for rule in rules:
            self.assertEqual(FORMATS[rule.format].validate(rule.text), [], rule.path)


class AddValues(unittest.TestCase):
    def rule(self, rel):
        return next(r for r in load_rules(DIRS, ROOT) if r.path == rel)

    def test_splunk_adds_once(self):
        rule = self.rule("rules/splunk/web_vpn_known_exploit_paths.yml")
        new = FORMATS["splunk"].add_values(rule, "uri", ["/x/y.cgi"], META)
        self.assertIn('"*/x/y.cgi*"', new)
        again = FORMATS["splunk"].add_values(type(rule)(**{**rule.__dict__, "text": new}), "uri", ["/x/y.cgi"], META)
        self.assertEqual(again.count("/x/y.cgi"), 1)

    def test_elastic_adds_to_query(self):
        rule = self.rule("rules/elastic/web_shell_url_patterns.json")
        new = FORMATS["elastic"].add_values(rule, "uri", ["/evil.aspx"], META)
        self.assertIn('"*/evil.aspx*"', json.loads(new)["query"])
        self.assertEqual(json.loads(new)["version"], 3)

    def test_sigma_does_not_touch_filter_lists(self):
        rule = self.rule("rules/sigma/file_event_win_script_in_iis_webroot.yml")
        new = FORMATS["sigma"].add_values(rule, "dir", ["\\Foo\\"], META)
        self.assertIn("'\\Foo\\'", new)
        self.assertIn("filter_deploy:", new)

    def test_returns_none_when_no_list_exists(self):
        rule = self.rule("rules/sigma/proc_creation_win_w3wp_spawns_shell.yml")
        self.assertIsNone(FORMATS["sigma"].add_values(rule, "uri", ["/a"], META))

    def test_query_list_keeps_or_separator(self):
        out = add_to_query_list('url.original : ("a" or "b")', r"url\.original", ['"c"'])
        self.assertEqual(out, 'url.original : ("a" or "b" or "c")')


class SigmaEval(unittest.TestCase):
    RULE = """
detection:
  sel:
    A|contains: [foo, bar]
    B|endswith: .aspx
  flt:
    C: skip
  condition: sel and not flt
"""

    def test_condition(self):
        self.assertTrue(sigma_eval.matches(self.RULE, {"A": "xxFOOxx", "B": "a.aspx"}))
        self.assertFalse(sigma_eval.matches(self.RULE, {"A": "foo", "B": "a.txt"}))
        self.assertFalse(sigma_eval.matches(self.RULE, {"A": "foo", "B": "a.aspx", "C": "skip"}))

    def test_one_of(self):
        rule = "detection:\n  s1: {A: x}\n  s2: {A: y}\n  condition: 1 of s*\n"
        self.assertTrue(sigma_eval.matches(rule, {"A": "y"}))
        self.assertFalse(sigma_eval.matches(rule, {"A": "z"}))


class Helpers(unittest.TestCase):
    def test_generic_indicator_does_not_cover_specific_ioc(self):
        self.assertFalse(indicator_covers(norm_ioc(".aspx"), norm_ioc("human2.aspx")))
        self.assertTrue(indicator_covers(norm_ioc("*human2.aspx*"), norm_ioc("/human2.aspx")))

    def test_space_and_slash_insensitive(self):
        self.assertEqual(norm_ioc("\\MOVEit Transfer\\wwwroot\\"), norm_ioc("/moveittransfer/wwwroot/"))

    def test_version_compare(self):
        self.assertLess(version_tuple("13.1-48.47"), version_tuple("13.1-49.15"))
        self.assertLess(version_tuple("2022.1.3"), version_tuple("2022.1.5"))


if __name__ == "__main__":
    unittest.main()
