import datetime
import os

from cpsec import access, config, util, waf
from tests.helpers import EnvTestCase

MODSEC = """<IfModule security2_module>
SecRuleEngine On
SecAuditEngine On
Include /usr/local/lsws/conf/cps-waf/rules.conf
</IfModule>
"""

AUDIT = """--aaaa1111-A--
[19/Oct/2026:03:07:47 +0100] TX1 203.0.113.9 51234 * 443
--aaaa1111-B--
GET /pbw-1?id=1%27%20UNION%20SELECT%20NULL HTTP/1.1
host: example.com
cookie: secret=do-not-show
--aaaa1111-H--
Message: Detected 200 (phase 2). Test 'ARGS' against '@detectSQLi' is true. [file "f"] [line "1"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"]
--aaaa1111-Z--

--bbbb2222-A--
[19/Oct/2026:03:07:47 +0100] TX1 203.0.113.9 51234 * 443
--bbbb2222-B--
GET /pbw-1?id=1%27%20UNION%20SELECT%20NULL HTTP/1.1
host: example.com
--bbbb2222-H--
Message: Detected 200 (phase 2). Test 'ARGS' against '@rx' is true. [id "942190"] [msg "MSSQL code execution"]
--bbbb2222-Z--

--cccc3333-A--
[19/Oct/2026:03:08:00 +0100] TX2 45.60.0.20 40000 * 443
--cccc3333-B--
POST /wp-admin/admin-ajax.php HTTP/1.1
host: shop.example.com
--cccc3333-H--
Message: Detected 200 (phase 2). Test 'ARGS' against '@rx' is true. [id "920440"] [msg "URL file extension is restricted by policy"]
--cccc3333-Z--

--dddd4444-A--
[19/Oct/2026:03:09:00 +0100] TX3 198.51.100.4 40001 * 443
--dddd4444-B--
GET /x?a=b HTTP/1.1
host: example.com
--dddd4444-H--
Message: Detected 200 (phase 2). Test 'TX' against '@ge 5' is true. [id "1000900"] [msg "Request blocked by the web firewall"]
Message: Detected 200 (phase 2). [id "1000901"] [msg "internal diagnostic"]
--dddd4444-Z--
"""


class FirewallEnv(EnvTestCase):
    def setUp(self):
        super().setUp()
        p = config.P
        self.write(p.modsec_conf, MODSEC)
        self.write(p.waf_rules, "# rules\n")
        self.write(p.waf_block, waf.WATCH_BLOCK)
        self.write(p.waf_before, "")
        self.write(p.waf_after, "")
        access.write_list(p.admin_list, [("45.60.0.20", "This server")], access.ADMIN_HEADER)
        self.restart = self.patch("cpsec.waf.restart_and_check", return_value=(True, []))


class Modes(FirewallEnv):
    def test_state_is_read_from_the_files(self):
        self.assertEqual(waf.mode(), "watch")
        self.assertEqual(waf.state(), (True, waf.MODE_TEXT["watch"]))
        self.write(config.P.modsec_conf, MODSEC.replace("SecRuleEngine On", "SecRuleEngine Off"))
        self.assertEqual(waf.mode(), "off")
        self.assertEqual(waf.state()[0], None)

    def test_not_set_up_at_all(self):
        os.remove(config.P.waf_rules)
        self.assertIsNone(waf.mode())
        self.assertEqual(waf.state(), (None, "not set up"))
        self.assertEqual(waf.set_mode("watch").code, "not_installed")

    def test_blocking_writes_the_rule_with_the_chosen_strictness(self):
        r = waf.set_mode("block", 10)
        self.assertTrue(r.ok, r.message)
        self.assertEqual(waf.mode(), "block")
        self.assertEqual(waf.threshold(), 10)
        self.assertIn('SecRule TX:ANOMALY_SCORE_PL1 "@ge 10"', self.read(config.P.waf_block))
        self.assertTrue(self.restart.called)

    def test_back_to_watch_removes_the_blocking_rule(self):
        waf.set_mode("block")
        waf.set_mode("watch")
        self.assertEqual(waf.mode(), "watch")
        self.assertNotIn("SecRule", self.read(config.P.waf_block))

    def test_off_turns_the_engine_off(self):
        waf.set_mode("off")
        self.assertIn("SecRuleEngine Off", self.read(config.P.modsec_conf))
        self.assertEqual(waf.mode(), "off")

    def test_a_site_that_breaks_undoes_the_change(self):
        self.restart.side_effect = [(False, [("shop.example.com", "500")]), (True, [])]
        r = waf.set_mode("block")
        self.assertFalse(r.ok)
        self.assertEqual(r.code, "rolled_back")
        self.assertEqual(waf.mode(), "watch")
        self.assertEqual(self.restart.call_count, 2, "restarted again after the undo")

    def test_bad_strictness_is_refused_before_anything_is_written(self):
        self.assertEqual(waf.set_mode("block", 0).code, "invalid")
        self.assertEqual(waf.set_mode("block", 500).code, "invalid")
        self.assertEqual(waf.set_mode("nonsense").code, "invalid")
        self.assertEqual(waf.mode(), "watch")


class Exceptions(FirewallEnv):
    def test_one_website_one_rule(self):
        self.assertTrue(waf.add_exception("site", "shop.example.com", "942100").ok)
        text = self.read(config.P.waf_before)
        self.assertIn(r'^(?:www\.)?shop\.example\.com(?::\d+)?$', text)
        self.assertIn("ctl:ruleRemoveById=942100", text)

    def test_every_website_and_firewall_off(self):
        waf.add_exception("all", "", "920350")
        waf.add_exception("site_off", "old.example.com", "ALL")
        self.assertIn("SecRuleRemoveById 920350", self.read(config.P.waf_after))
        self.assertIn("ctl:ruleEngine=Off", self.read(config.P.waf_before))

    def test_rule_ids_are_unique_and_duplicates_refused(self):
        waf.add_exception("site", "a.example.com", "1")
        waf.add_exception("site", "b.example.com", "2")
        ids = [part for part in self.read(config.P.waf_before).split('id:')[1:]]
        self.assertEqual([i.split(",")[0] for i in ids], ["1100001", "1100002"])
        self.assertEqual(waf.add_exception("site", "a.example.com", "1").code, "exists")

    def test_nothing_that_could_break_the_rule_syntax_gets_through(self):
        for host, rule in (('a.com" "x', "1"), ("a.com", "1;drop"), ("a b.com", "1"), ("", "1")):
            self.assertEqual(waf.add_exception("site", host, rule).code, "invalid", (host, rule))
        self.assertEqual(waf.add_exception("all", "", "abc").code, "invalid")
        self.assertEqual(waf.list_exceptions(), [])

    def test_remove(self):
        waf.add_exception("site", "a.example.com", "1")
        self.assertTrue(waf.remove_exception(0).ok)
        self.assertEqual(waf.list_exceptions(), [])
        self.assertEqual(waf.remove_exception(0).code, "missing")

    def test_a_failed_restart_restores_the_old_exceptions(self):
        self.restart.side_effect = [(False, [("a.example.com", "500")]), (True, [])]
        r = waf.add_exception("site", "a.example.com", "1")
        self.assertFalse(r.ok)
        self.assertEqual(waf.list_exceptions(), [])
        self.assertNotIn("a.example.com", self.read(config.P.waf_before))


class WhatItRecorded(FirewallEnv):
    def setUp(self):
        super().setUp()
        self.events = waf.parse_audit_text(AUDIT)

    def test_records_of_one_request_are_joined(self):
        self.assertEqual(len(self.events), 3, "two records share TX1 and TX3 only has an internal rule + the block")
        first = self.events[0]
        self.assertEqual(first["host"], "example.com")
        self.assertEqual(first["path"], "/pbw-1")
        self.assertEqual(sorted(r for r, _ in first["hits"]), ["942100", "942190"])
        self.assertEqual(first["ip"], "203.0.113.9")

    def test_blocking_is_detected_and_internal_rules_are_hidden(self):
        last = self.events[2]
        self.assertTrue(last["blocked"])
        self.assertEqual(last["hits"], [])

    def test_summary_counts_and_trusted_hits(self):
        now = datetime.datetime(2026, 10, 19, 12, 0, 0)
        s = waf.summary(self.events, now)
        day = s["periods"]["day"]
        self.assertEqual(day["requests"], 3)
        self.assertEqual(day["addresses"], 3)
        self.assertEqual(day["blocked"], 1)
        self.assertEqual(day["rules"][0]["count"], 1)
        self.assertEqual(s["trusted_hits"], 1, "45.60.0.20 is on the trusted list")

    def test_recent_lists_trusted_first_and_never_shows_cookies(self):
        groups = waf.recent(events=self.events)
        self.assertTrue(groups[0]["trusted"])
        self.assertEqual(groups[0]["host"], "shop.example.com")
        self.assertNotIn("secret", str(groups))

    def test_the_log_file_is_read_from_disk(self):
        self.write(config.P.audit_log, AUDIT)
        self.assertEqual(len(waf.parse_audit()), 3)
        os.remove(config.P.audit_log)
        self.assertEqual(waf.parse_audit(), [])
