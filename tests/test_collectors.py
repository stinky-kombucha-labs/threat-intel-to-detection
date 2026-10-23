import unittest

from intel_to_rule.collectors import feeds, kev, nvd, reddit
from intel_to_rule.extract import apply_kev, from_kev, heuristic, merge
from intel_to_rule.inventory import load_inventory
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

KEV = {"vulnerabilities": [
    {"cveID": "CVE-2099-0001", "vendorProject": "Acme", "product": "Widget", "vulnerabilityName": "Widget RCE",
     "dateAdded": "2099-01-02", "shortDescription": "RCE in Widget.", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2099-0002", "vendorProject": "Acme", "product": "Gadget", "vulnerabilityName": "Gadget XSS",
     "dateAdded": "2098-01-02", "shortDescription": "XSS.", "knownRansomwareCampaignUse": "Unknown"},
]}

RSS = b"""<rss><channel>
<item><title>Exploit of Widget</title><link>https://example.com/a</link><description>&lt;p&gt;widget RCE&lt;/p&gt;</description></item>
<item><title>Unrelated</title><link>https://example.com/b</link><description>nothing</description></item>
</channel></rss>"""

ATOM = b"""<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Widget advisory</title>
<link href="https://example.com/c"/><summary>widget</summary></entry></feed>"""


class Parsers(unittest.TestCase):
    def test_kev_since_filter_and_flags(self):
        items = kev.parse(KEV, since="2099-01-01")
        self.assertEqual([i.id for i in items], ["CVE-2099-0001"])
        finding = from_kev(items[0])
        self.assertTrue(finding.kev and finding.ransomware)

    def test_rss_keyword_filter_and_html_stripped(self):
        items = feeds.parse(RSS, "t", ["widget"])
        self.assertEqual(len(items), 1)
        self.assertNotIn("<p>", items[0].text)

    def test_atom_link_href(self):
        self.assertEqual(feeds.parse(ATOM, "t", [])[0].url, "https://example.com/c")

    def test_reddit_keyword_filter(self):
        payload = {"data": {"children": [
            {"data": {"id": "1", "title": "Widget exploited", "selftext": "", "permalink": "/r/x/1"}},
            {"data": {"id": "2", "title": "cats", "selftext": "", "permalink": "/r/x/2"}},
        ]}}
        self.assertEqual([i.id for i in reddit.parse(payload, "x", ["widget"])], ["1"])

    def test_nvd_description(self):
        payload = {"vulnerabilities": [{"cve": {"id": "CVE-2099-1", "published": "2099-01-01",
                                                 "descriptions": [{"lang": "en", "value": "Bad bug"}]}}]}
        self.assertEqual(nvd.parse(payload)[0].text, "Bad bug")


class Extraction(unittest.TestCase):
    def test_heuristic_finds_cve_product_and_uri(self):
        inv = load_inventory(ROOT / "data/inventory/software_inventory.yaml")
        raw = feeds.parse(
            b"<rss><channel><item><title>MOVEit Transfer CVE-2023-34362</title><link>https://e.com</link>"
            b"<description>requests to /human2.aspx and T1190</description></item></channel></rss>", "t", [])[0]
        f = heuristic(raw, inv)
        self.assertEqual(f.cves, ["CVE-2023-34362"])
        self.assertIn("MOVEit Transfer", f.products)
        self.assertEqual(f.iocs["uri"], ["/human2.aspx"])
        self.assertEqual(f.techniques, ["T1190"])

    def test_merge_unions_and_keeps_kev(self):
        a = from_kev(kev.parse(KEV)[0])
        b = heuristic(feeds.parse(RSS, "t", ["widget"])[0], load_inventory(ROOT / "data/inventory/software_inventory.yaml"))
        b.cves = ["CVE-2099-0001"]
        merged = apply_kev(merge(b, a), {"CVE-2099-0001": KEV["vulnerabilities"][0]})
        self.assertTrue(merged.kev)
        self.assertEqual(merged.cves, ["CVE-2099-0001"])


if __name__ == "__main__":
    unittest.main()
