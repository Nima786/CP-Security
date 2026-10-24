"""Known security holes: matching a version to a hole, caching the database, and the per-website list."""
import time
import unittest

from cpsec import config, util, vulns
from tests.helpers import EnvTestCase


def hole(cvss=7.5, cve="CVE-2024-0001", name="a hole", min_v=None, min_op=None, max_v=None, max_op=None, unfixed=0):
    return {"name": name, "impact": {"cvss": {"score": cvss}}, "source": [{"id": cve}],
            "operator": {"min_version": min_v, "min_operator": min_op, "max_version": max_v, "max_operator": max_op, "unfixed": unfixed}}


class Matching(unittest.TestCase):
    def test_a_version_below_the_fixed_one_is_affected_and_the_newer_one_is_not(self):
        op = {"max_version": "2.1.1", "max_operator": "lt"}
        self.assertTrue(vulns._affected("2.0", op))
        self.assertTrue(vulns._affected("2.1.0", op))
        self.assertFalse(vulns._affected("2.1.1", op))
        self.assertFalse(vulns._affected("4.0.2", op))

    def test_a_range_with_both_ends(self):
        op = {"min_version": "3.0", "min_operator": "ge", "max_version": "3.5", "max_operator": "le"}
        self.assertFalse(vulns._affected("2.9", op))
        self.assertTrue(vulns._affected("3.0", op))
        self.assertTrue(vulns._affected("3.5", op))
        self.assertFalse(vulns._affected("3.6", op))

    def test_greater_than_and_less_than_are_strict(self):
        op = {"min_version": "1.0", "min_operator": "gt", "max_version": "2.0", "max_operator": "lt"}
        self.assertFalse(vulns._affected("1.0", op))
        self.assertTrue(vulns._affected("1.5", op))
        self.assertFalse(vulns._affected("2.0", op))

    def test_no_bounds_means_the_whole_plugin(self):
        self.assertTrue(vulns._affected("9.9", {}))
        self.assertFalse(vulns._affected("", {"max_version": "2.0", "max_operator": "lt"}))

    def test_the_fix_is_the_version_it_was_closed_in(self):
        self.assertEqual(vulns._fix({"max_version": "2.1.1", "max_operator": "lt"}), ("update", "2.1.1"))
        self.assertEqual(vulns._fix({"max_version": "2.0", "max_operator": "le"}), ("update", ""))
        self.assertEqual(vulns._fix({"max_version": "2.0", "max_operator": "lt", "unfixed": 1}), ("none", ""))

    def test_the_database_sends_yes_no_as_strings(self):
        # the real database sends "0"/"1", not 0/1; "0" must count as "there is a fix", not as unfixed
        self.assertEqual(vulns._fix({"max_version": "2.6.5", "max_operator": "lt", "unfixed": "0"}), ("update", "2.6.5"))
        self.assertEqual(vulns._fix({"max_version": "2.6.5", "max_operator": "lt", "unfixed": "1"}), ("none", ""))
        self.assertFalse(vulns._truthy("0"))
        self.assertTrue(vulns._truthy("1"))
        self.assertFalse(vulns._truthy(0))
        self.assertFalse(vulns._truthy(None))

    def test_severity_from_the_score(self):
        self.assertEqual(vulns._severity(9.8)[0], "critical")
        self.assertEqual(vulns._severity(7.5)[0], "high")
        self.assertEqual(vulns._severity(5)[0], "medium")
        self.assertEqual(vulns._severity(2)[0], "low")
        self.assertEqual(vulns._severity(None)[0], "unknown")
        self.assertEqual(vulns._severity("x")[0], "unknown")


def found(severity="high", score=7.5, fix="update", fixed="", title="a hole"):
    return {"title": title, "severity": severity, "score": score, "fix": fix, "fixed_version": fixed, "cve": ""}


def plugin(*holes, version="3.7.8"):
    return {"kind": "plugin", "slug": "jet-engine", "name": "JetEngine", "version": version, "status": "active", "holes": list(holes)}


class Summary(unittest.TestCase):
    """Many holes in one plugin become ONE line: how bad, and which version to install."""

    def test_many_holes_give_one_version_to_install_the_newest_of_the_fixed_versions(self):
        item = vulns.summarize(plugin(found(fixed="3.7.9"), found(fixed="3.8.16.1"), found(fixed="3.8.10"), found(fixed="3.8.9")))
        self.assertEqual((item["fix_state"], item["fix_to"], item["hole_count"], item["no_fix_count"]), ("version", "3.8.16.1", 4, 0))

    def test_versions_are_compared_as_versions_not_as_text(self):
        item = vulns.summarize(plugin(found(fixed="3.8.9"), found(fixed="3.8.10")))
        self.assertEqual(item["fix_to"], "3.8.10", "10 is newer than 9")

    def test_the_worst_hole_decides_how_bad_it_is_even_if_it_is_listed_late(self):
        item = vulns.summarize(plugin(found("medium", 5.0, fixed="1"), found("critical", 9.8, fixed="1"), found("unknown", 0.0, fixed="1")))
        self.assertEqual((item["worst"], item["score"]), ("critical", 9.8))

    def test_holes_nobody_has_rated_are_shown_as_not_rated_not_as_alarms(self):
        item = vulns.summarize(plugin(found("unknown", 0.0, fixed="2.0"), found("unknown", 0.0, fixed="2.1")))
        self.assertEqual(item["worst"], "unknown")

    def test_some_holes_fixed_and_some_not_still_names_the_version_and_counts_the_unfixed(self):
        item = vulns.summarize(plugin(found(fixed="2.0"), found(fix="none")))
        self.assertEqual((item["fix_state"], item["fix_to"], item["no_fix_count"]), ("version", "2.0", 1))

    def test_no_fix_anywhere_says_so(self):
        item = vulns.summarize(plugin(found(fix="none"), found(fix="none")))
        self.assertEqual((item["fix_state"], item["fix_to"], item["no_fix_count"]), ("none", "", 2))

    def test_a_fix_that_exists_without_a_stated_version_is_still_a_fix(self):
        item = vulns.summarize(plugin(found(fixed=""), found(fixed="")))
        self.assertEqual((item["fix_state"], item["fix_to"]), ("update", ""))

    def test_the_page_counts_plugins_not_holes(self):
        many = plugin(*[found("high", 7.5, fixed="3.8.%d" % n) for n in range(14)])          # fourteen old holes in one plugin
        other = {"kind": "theme", "slug": "t", "name": "t", "version": "1", "status": "active", "holes": [found("medium", 5.0, fixed="2")]}
        row = vulns.site_row("a.example.com", {"checked": True, "items": [many, other]})
        self.assertEqual(row["counts"], {"critical": 0, "high": 1, "medium": 1, "low": 0, "unknown": 0})
        self.assertEqual(row["fixable"], 2)
        page = vulns.page([row, vulns.site_row("b.example.com", {"checked": True, "items": []})], "done", "now")
        self.assertEqual(page["totals"]["high"], 1)
        self.assertEqual([r["site"] for r in page["sites"]], ["a.example.com", "b.example.com"], "worst website first")

    def test_summarizing_twice_changes_nothing(self):
        item = vulns.summarize(plugin(found(fixed="2.0")))
        before = dict(item)
        self.assertEqual(vulns.summarize(item), before)

    def test_a_website_with_nothing_wrong_has_an_empty_line(self):
        row = vulns.site_row("a.example.com", {"checked": True, "items": []})
        self.assertEqual((row["items"], row["fixable"], row["worst"]), ([], 0, 0))


class FakeDatabase:
    def __init__(self):
        self.answers = {}            # "kind:slug" -> list of holes (or None to mean "no answer")
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        parts = url.rstrip("/").split("/")
        key = "core:" + parts[-1] if parts[-2] == "core" else parts[-2] + ":" + parts[-1]
        if key not in self.answers:
            return {"data": {"name": parts[-1], "vulnerability": None}}         # the database knows nothing
        holes = self.answers[key]
        if holes is None:
            return None                                                          # could not ask (network)
        return {"data": {"name": parts[-1], "vulnerability": holes}}


class CacheCase(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.db = FakeDatabase()
        self.patch("cpsec.vulns._fetch", side_effect=self.db)


class Caching(CacheCase):
    def test_a_hole_is_found_and_the_fixed_version_is_not(self):
        self.db.answers["plugin:bricksforge"] = [hole(cvss=7.5, max_v="2.1.1", max_op="lt", name="upload flaw")]
        found = vulns.check_item("plugin", "bricksforge", "2.0")
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0]["severity"], found[0]["fix"], found[0]["fixed_version"]), ("high", "update", "2.1.1"))
        self.assertEqual(vulns.check_item("plugin", "bricksforge", "4.0.2"), [])

    def test_the_answer_is_kept_for_a_day_then_asked_again(self):
        self.db.answers["plugin:woo"] = [hole(max_v="1.0", max_op="lt")]
        vulns.check_item("plugin", "woo", "0.9")
        vulns.check_item("plugin", "woo", "0.9")
        self.assertEqual(len(self.db.calls), 1, "the second look uses the kept answer")
        vulns.check_item("plugin", "woo", "0.9", refresh=True)
        self.assertEqual(len(self.db.calls), 2, "a refresh asks again")

    def test_a_stale_answer_is_refreshed_by_itself(self):
        self.db.answers["plugin:woo"] = [hole(max_v="1.0", max_op="lt")]
        vulns.check_item("plugin", "woo", "0.9")
        data = util.read_json(config.P.vuln_cache, {})
        data["plugin:woo"]["fetched"] = time.time() - vulns.CACHE_SECONDS - 10
        util.write_json(config.P.vuln_cache, data)
        vulns.check_item("plugin", "woo", "0.9")
        self.assertEqual(len(self.db.calls), 2)

    def test_when_the_database_cannot_be_reached_yesterdays_answer_is_kept(self):
        self.db.answers["plugin:woo"] = [hole(max_v="1.0", max_op="lt")]
        vulns.check_item("plugin", "woo", "0.9")
        data = util.read_json(config.P.vuln_cache, {})
        data["plugin:woo"]["fetched"] = time.time() - vulns.CACHE_SECONDS - 10
        util.write_json(config.P.vuln_cache, data)
        self.db.answers["plugin:woo"] = None                 # network down
        found = vulns.check_item("plugin", "woo", "0.9")
        self.assertEqual(len(found), 1, "the kept answer is still used")

    def test_a_never_before_seen_plugin_with_no_answer_reports_could_not_ask(self):
        self.db.answers["plugin:mystery"] = None
        self.assertIsNone(vulns.check_item("plugin", "mystery", "1.0"))

    def test_a_plugin_the_database_does_not_know_has_no_holes(self):
        self.assertEqual(vulns.check_item("plugin", "homemade", "1.0"), [])


class WebsiteCase(CacheCase):
    def setUp(self):
        super().setUp()
        self.inv = {"checked": True,
                    "plugin": {"bricksforge": {"version": "2.0", "status": "active"},
                               "woocommerce": {"version": "9.0", "status": "active"},
                               "safe-plugin": {"version": "1.0", "status": "inactive"}},
                    "theme": {"bricks": {"version": "1.5", "status": "active"}}}
        self.patch("cpsec.library._read_site", return_value=self.inv)
        self.patch("cpsec.wpupdate._site", return_value={"docroot": "/home/x/public_html", "user": "x", "home": "/home/x"})
        self.patch("cpsec.wpupdate._php", return_value="/php")
        self.patch("cpsec.vulns._core_version", return_value="6.5.2")
        self.patch("cpsec.updates._wordpress_sites", return_value=[("/home/shop.example.com/public_html", "shopuser", "shop.example.com")])
        self.db.answers["plugin:bricksforge"] = [hole(cvss=9.8, max_v="2.1.1", max_op="lt", name="upload flaw", cve="CVE-2026-85097")]
        self.db.answers["theme:bricks"] = [hole(cvss=6.1, max_v="1.6", max_op="lt", name="theme flaw")]
        self.db.answers["core:6.5.2"] = [hole(cvss=5.0, max_v="6.5.3", max_op="lt", name="core flaw", unfixed=1)]

    def test_only_the_affected_items_are_listed_worst_first(self):
        info = vulns._inspect("shop.example.com")
        self.assertTrue(info["checked"])
        got = [(i["kind"], i["slug"], i["holes"][0]["severity"]) for i in info["items"]]
        # critical first; then the two mediums, the higher score (the theme, 6.1) before the lower (core, 5.0)
        self.assertEqual(got, [("plugin", "bricksforge", "critical"), ("theme", "bricks", "medium"), ("core", "6.5.2", "medium")])
        self.assertNotIn("woocommerce", [i["slug"] for i in info["items"]], "the safe version is not flagged")

    def test_the_page_summary_counts_and_sorts(self):
        vulns.scan_start()
        for _ in range(300):
            if vulns.scan_state()["status"] != "running":
                break
            time.sleep(0.02)
        data = vulns.state()
        row = data["sites"][0]
        self.assertEqual(row["site"], "shop.example.com")
        self.assertEqual(row["counts"]["critical"], 1)
        self.assertEqual(row["counts"]["medium"], 2)
        self.assertEqual(row["items"][0]["fix_to"], "2.1.1")
        self.assertEqual(row["items"][2]["fix_state"], "none", "WordPress itself: no fixed version in the database")
        self.assertEqual(row["worst"], vulns.RANK["critical"])
        self.assertEqual(row["fixable"], 2, "the two fixable ones (not the unfixed core hole)")
        self.assertEqual(data["totals"]["critical"], 1)

    def test_a_website_whose_database_lookups_failed_is_flagged(self):
        self.db.answers["plugin:bricksforge"] = None
        info = vulns._inspect("shop.example.com")
        self.assertFalse(info["asked_ok"])

    def test_a_website_that_cannot_be_read_says_so(self):
        self.patch("cpsec.library._read_site", return_value={"checked": False})
        info = vulns._inspect("shop.example.com")
        self.assertFalse(info["checked"])
        self.assertIn("could not be read", info["problem"])


if __name__ == "__main__":
    unittest.main()
