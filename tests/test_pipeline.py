"""End-to-end test on the offline fixtures (the three public cases plus two unrelated KEV entries)."""
import os
import tempfile
import unittest
from pathlib import Path

from intel_to_rule import pipeline

ROOT = Path(__file__).resolve().parents[1]
os.environ["INTEL_TO_RULE_TODAY"] = "2026-10-23"


class FixtureRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.mkdtemp()
        ctx = pipeline.build_context(ROOT, ROOT / "config/pipeline.yaml", str(Path(tmp) / "state.sqlite"))
        items = pipeline.collect_fixtures(ctx)
        cls.reports = {r.finding.key: r for r in pipeline.run(ctx, items, Path(tmp) / "out")}
        cls.ctx = ctx
        cls.items = items

    def test_all_findings_present(self):
        self.assertEqual(
            set(self.reports),
            {"CVE-2023-34362", "CVE-2023-46805", "CVE-2023-4966", "CVE-2020-14883", "CVE-2020-29583"},
        )

    def test_unrelated_kev_entries_are_dropped(self):
        for key in ("CVE-2020-14883", "CVE-2020-29583"):
            self.assertEqual(self.reports[key].verdict, "not_relevant")
            self.assertIsNone(self.reports[key].proposal)

    def test_second_ivanti_cve_is_merged_not_duplicated(self):
        self.assertNotIn("CVE-2024-21887", self.reports)
        self.assertIn("CVE-2024-21887", self.reports["CVE-2023-46805"].finding.cves)

    def test_kev_data_is_applied(self):
        f = self.reports["CVE-2023-34362"].finding
        self.assertTrue(f.kev and f.ransomware)
        self.assertEqual(f.kev_added, "2023-06-02")

    def test_moveit_updates_native_splunk_and_sigma_rules(self):
        paths = {c.path: c for c in self.reports["CVE-2023-34362"].proposal.changes if c.action == "update"}
        self.assertIn("*/human2.aspx*", paths["rules/splunk/web_generic_webshell_requests.yml"].new)
        sigma = paths["rules/sigma/file_event_win_script_in_iis_webroot.yml"].new
        self.assertIn(r"'\MOVEit Transfer\wwwroot\'", sigma)
        self.assertIn("modified: 2026-10-23", sigma)

    def test_replay_shows_old_rule_blind_and_new_rule_firing(self):
        replay = self.reports["CVE-2023-34362"].proposal.replay
        attack = [r for r in replay if r["case"] == "attack event"]
        self.assertTrue(attack)
        self.assertTrue(all(r["old"] is False and r["new"] is True for r in attack))
        benign = [r for r in replay if r["case"] == "benign event"]
        self.assertTrue(all(r["new"] is False for r in benign))

    def test_ivanti_extends_the_product_specific_rule(self):
        changes = self.reports["CVE-2023-46805"].proposal.changes
        self.assertEqual(changes[0].path, "rules/splunk/web_vpn_known_exploit_paths.yml")
        self.assertIn("cloud-server-test-connection", changes[0].new)
        self.assertEqual(changes[0].new.count("\ncve:"), 1)

    def test_citrix_gets_new_rule_and_log_gap(self):
        r = self.reports["CVE-2023-4966"]
        self.assertEqual([c.action for c in r.proposal.changes], ["new"])
        self.assertIn("host_length>=150", r.proposal.changes[0].new)
        self.assertTrue(r.coverage.log_gaps)

    def test_no_proposal_has_validation_problems(self):
        for r in self.reports.values():
            if r.proposal:
                self.assertEqual(r.proposal.problems, [], r.finding.key)

    def test_second_run_is_idempotent(self):
        again = pipeline.run(self.ctx, self.items, Path(tempfile.mkdtemp()))
        self.assertEqual(again, [])


if __name__ == "__main__":
    unittest.main()
