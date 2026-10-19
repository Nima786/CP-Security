import os

from cpsec import config, util, waf, webserver
from tests.helpers import EnvTestCase

ENTERPRISE_MODSEC = """<IfModule security2_module>
SecRuleEngine On
SecAuditEngine RelevantOnly
Include /usr/local/lsws/conf/rules.conf
</IfModule>
"""

# what CyberPanel writes for OpenLiteSpeed when ModSecurity is installed
OLS_CONF = """docRoot                   $VH_ROOT/
listener Default{
  address                 *:80
}

module mod_security {
modsecurity  on
modsecurity_rules `
SecDebugLogLevel 0
SecAuditEngine on
SecRuleEngine On
`
modsecurity_rules_file /usr/local/lsws/conf/modsec/rules.conf
}
"""


class Detection(EnvTestCase):
    def test_nothing_installed(self):
        self.assertIsNone(webserver.kind())
        self.assertFalse(webserver.engine_installed())
        self.assertIn("No LiteSpeed", webserver.how_to_install_engine())

    def test_enterprise_is_recognised_by_its_settings_file(self):
        self.write(config.P.lsws_xml, "<config/>")
        self.write(config.P.lsws_version, "6.3.7\n")
        self.assertEqual(webserver.kind(), webserver.ENTERPRISE)
        info = webserver.info()
        self.assertEqual((info["name"], info["version"]), ("LiteSpeed Enterprise", "6.3.7"))

    def test_openlitespeed_is_recognised_by_its_program_file(self):
        self.write(config.P.lsws_bin_ols, "")
        self.write(config.P.lsws_xml, "<config/>")  # a leftover must not confuse it
        self.assertEqual(webserver.kind(), webserver.OPENLITESPEED)

    def test_openlitespeed_without_the_program_file_but_with_its_settings(self):
        self.write(config.P.ols_conf, OLS_CONF)
        self.assertEqual(webserver.kind(), webserver.OPENLITESPEED)

    def test_openlitespeed_needs_the_module_and_the_block(self):
        self.write(config.P.lsws_bin_ols, "")
        self.write(config.P.ols_conf, "listener Default{\n}\n")
        self.assertFalse(webserver.engine_installed())
        self.write(config.P.ols_conf, OLS_CONF)
        self.assertFalse(webserver.engine_installed(), "the module file is still missing")
        self.write(config.P.ols_module, "")
        self.assertTrue(webserver.engine_installed())
        self.assertIn("ModSecurity Conf", webserver.how_to_install_engine())


class EnterpriseHook(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.write(config.P.lsws_xml, "<config/>")
        self.write(config.P.modsec_conf, ENTERPRISE_MODSEC)

    def test_adds_one_line_inside_the_existing_block_and_nothing_else(self):
        self.assertTrue(webserver.connect().ok)
        text = self.read(config.P.modsec_conf)
        self.assertIn("Include %s\n</IfModule>" % config.P.waf_main, text)
        for original in ENTERPRISE_MODSEC.strip().splitlines():
            self.assertIn(original, text)
        self.assertTrue(webserver.hook_present())

    def test_running_it_twice_changes_nothing(self):
        webserver.connect()
        first = self.read(config.P.modsec_conf)
        webserver.connect()
        self.assertEqual(self.read(config.P.modsec_conf), first)
        self.assertEqual(first.count(config.P.waf_main), 1)

    def test_a_block_is_created_when_the_file_has_none(self):
        self.write(config.P.modsec_conf, "SecRuleEngine On\n")
        webserver.connect()
        text = self.read(config.P.modsec_conf)
        self.assertIn("<IfModule security2_module>", text)
        self.assertIn("SecRuleEngine On", text)

    def test_the_old_hand_made_line_is_replaced_not_duplicated(self):
        self.write(config.P.modsec_conf, ENTERPRISE_MODSEC.replace(
            "Include /usr/local/lsws/conf/rules.conf",
            "Include /usr/local/lsws/conf/pb-waf/rules.conf\nInclude /usr/local/lsws/conf/rules.conf"))
        webserver.connect()
        text = self.read(config.P.modsec_conf)
        self.assertNotIn("pb-waf", text)
        self.assertIn("Include /usr/local/lsws/conf/rules.conf", text, "CyberPanel's own line stays")
        self.assertTrue(webserver.hook_present())

    def test_taking_it_out_leaves_the_file_as_it_was(self):
        webserver.connect()
        webserver.disconnect()
        self.assertEqual(self.read(config.P.modsec_conf), ENTERPRISE_MODSEC)
        self.assertFalse(webserver.hook_present())

    def test_the_file_is_backed_up_before_it_is_changed(self):
        webserver.connect()
        self.assertTrue(any(n.startswith("modsec.conf.") for n in os.listdir(config.P.backup_dir)))

    def test_without_modsecurity_there_is_a_helpful_message(self):
        os.remove(config.P.modsec_conf)
        r = webserver.connect()
        self.assertFalse(r.ok)
        self.assertEqual(r.code, "no_engine")
        self.assertIn("CyberPanel", r.message)


class OpenLiteSpeedHook(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.write(config.P.lsws_bin_ols, "")
        self.write(config.P.ols_module, "")
        self.write(config.P.ols_conf, OLS_CONF)

    def test_the_line_goes_inside_the_module_block_after_the_backtick_rules(self):
        self.assertTrue(webserver.connect().ok)
        text = self.read(config.P.ols_conf)
        block = text[text.index("module mod_security"):]
        self.assertIn("modsecurity_rules_file %s\n}" % config.P.waf_main, block)
        self.assertEqual(text.count(config.P.waf_main), 1)
        self.assertIn("listener Default{", text, "the rest of the file is untouched")
        self.assertTrue(webserver.hook_present())

    def test_cyberpanels_own_text_search_cannot_mistake_our_line_for_its_own(self):
        webserver.connect()
        # CyberPanel rewrites lines containing these words when its ModSecurity page is saved
        ours = [l for l in self.read(config.P.ols_conf).splitlines() if "cps-waf" in l]
        for word in ("modsecurity ", "SecAuditEngine ", "SecRuleEngine ", "SecDebugLogLevel",
                     "SecAuditLogRelevantStatus ", "SecAuditLogParts ", "SecAuditLogType "):
            self.assertFalse(any(word in l for l in ours), word)

    def test_running_it_twice_changes_nothing(self):
        webserver.connect()
        first = self.read(config.P.ols_conf)
        webserver.connect()
        self.assertEqual(self.read(config.P.ols_conf), first)

    def test_taking_it_out_restores_the_file(self):
        webserver.connect()
        webserver.disconnect()
        self.assertEqual(self.read(config.P.ols_conf), OLS_CONF)

    def test_a_module_that_is_switched_off_is_switched_on(self):
        self.write(config.P.ols_conf, OLS_CONF.replace("modsecurity  on", "modsecurity  off"))
        webserver.connect()
        self.assertIn("modsecurity  on", self.read(config.P.ols_conf))

    def test_missing_block_means_it_is_not_installed(self):
        self.write(config.P.ols_conf, "listener Default{\n}\n")
        r = webserver.connect()
        self.assertEqual((r.ok, r.code), (False, "no_engine"))

    def test_rules_with_braces_inside_the_backticks_do_not_end_the_block_early(self):
        self.write(config.P.ols_conf, OLS_CONF.replace("SecDebugLogLevel 0",
                                                      "SecRule ARGS \"@rx a{2}\" \"id:1\"\n}\nSecDebugLogLevel 0"))
        webserver.connect()
        text = self.read(config.P.ols_conf)
        self.assertGreater(text.index(config.P.waf_main), text.index("SecDebugLogLevel 0"))


class OtherRulePacks(EnvTestCase):
    def test_cyberpanels_owasp_pack_on_openlitespeed_is_noticed(self):
        self.write(config.P.lsws_bin_ols, "")
        self.write(config.P.at("/usr/local/lsws/conf/modsec/owasp/rules/REQUEST-901.conf"), "")
        self.write(config.P.ols_conf, OLS_CONF.replace(
            "modsecurity_rules_file /usr/local/lsws/conf/modsec/rules.conf",
            "modsecurity_rules_file /usr/local/lsws/conf/modsec/owasp/rules/REQUEST-901.conf\n"
            "modsecurity_rules_file /usr/local/lsws/conf/modsec/rules.conf"))
        self.assertEqual(webserver.other_rule_packs(), ["OWASP rules switched on in CyberPanel"])

    def test_comodo_on_enterprise_is_noticed(self):
        self.write(config.P.lsws_xml, "<config/>")
        self.write(config.P.at("/usr/local/lsws/conf/comodo_litespeed/rules.dat.conf"), "")
        self.write(config.P.modsec_conf, ENTERPRISE_MODSEC)
        self.write(config.P.lsws_conf + "/rules.conf",
                   "Include /usr/local/lsws/conf/comodo_litespeed/rules.dat.conf\n")
        self.assertEqual(webserver.other_rule_packs(), ["Comodo rules switched on in CyberPanel"])

    def test_cyberpanels_untouched_file_names_empty_rule_folders_and_that_is_not_an_active_pack(self):
        # copied from a real, never-edited CyberPanel Enterprise server
        self.write(config.P.lsws_xml, "<config/>")
        self.write(config.P.modsec_conf, "<IfModule security2_module>\nSecRuleEngine off\nSecAuditEngine on\n"
                   "Include /usr/local/lsws/conf/comodo_litespeed/*.conf\n"
                   "Include /usr/local/lsws/conf/modsec/owasp-modsecurity-crs-3.0-master/*.conf\n</IfModule>\n")
        self.assertEqual(webserver.other_rule_packs(), [])
        os.makedirs(config.P.at("/usr/local/lsws/conf/comodo_litespeed"))
        self.assertEqual(webserver.other_rule_packs(), [], "an empty folder is still nothing")
        self.write(config.P.at("/usr/local/lsws/conf/comodo_litespeed/rules.conf"), "")
        self.assertEqual(webserver.other_rule_packs(), ["Comodo rules switched on in CyberPanel"],
                         "the same line counts once rule files are really there")
    def test_our_own_rules_do_not_count_as_somebody_elses(self):
        self.write(config.P.lsws_xml, "<config/>")
        self.write(config.P.modsec_conf, ENTERPRISE_MODSEC)
        webserver.connect()
        self.assertEqual(webserver.other_rule_packs(), [])


class SelfTest(EnvTestCase):
    def setUp(self):
        super().setUp()
        p = config.P
        self.write(p.lsws_xml, "<config/>")
        self.write(p.modsec_conf, ENTERPRISE_MODSEC)
        webserver.connect()
        self.write(p.waf_main, waf.render_main("On"))
        self.write(p.waf_rules, "")
        self.write(p.waf_block, waf.WATCH_BLOCK)
        self.patch("cpsec.waf.time.sleep")

    def test_a_request_that_shows_up_in_the_log_passes(self):
        self.write(config.P.audit_log, "--x-B--\nGET /cps-selftest-abc123?id=1 HTTP/1.1\n")
        r = waf.selftest("shop.example.com", sender=lambda d, t: 200, token="abc123")
        self.assertTrue(r.ok, r.message)
        self.assertEqual(r.code, "seen")

    def test_a_request_missing_from_the_log_fails_with_advice(self):
        self.write(config.P.audit_log, "")
        r = waf.selftest("shop.example.com", sender=lambda d, t: 200, token="abc123")
        self.assertEqual((r.ok, r.code), (False, "not_seen"))

    def test_no_answer_from_the_web_server(self):
        r = waf.selftest("shop.example.com", sender=lambda d, t: None, token="abc123")
        self.assertEqual(r.code, "no_answer")

    def test_off_means_nothing_to_test(self):
        self.write(config.P.waf_main, waf.render_main("Off"))
        self.assertEqual(waf.selftest("a.example.com", sender=lambda d, t: 200).code, "not_active")

    def test_blocking_mode_reports_a_refusal(self):
        self.write(config.P.waf_block, waf.BLOCK_TEMPLATE % (5, 5))
        self.write(config.P.audit_log, "GET /cps-selftest-zz9 HTTP/1.1\n")
        r = waf.selftest("shop.example.com", sender=lambda d, t: 403, token="zz9")
        self.assertIn("refused", r.message)

    def test_blocking_mode_that_lets_it_through_says_so(self):
        self.write(config.P.waf_block, waf.BLOCK_TEMPLATE % (50, 50))
        self.write(config.P.audit_log, "GET /cps-selftest-zz9 HTTP/1.1\n")
        r = waf.selftest("shop.example.com", sender=lambda d, t: 200, token="zz9")
        self.assertEqual(r.code, "seen_not_blocked")


class BothServersWordTheirLogsDifferently(EnvTestCase):
    def test_a_rule_line_without_the_word_message_is_still_read(self):
        text = ("--e1-A--\n[19/Oct/2026:03:07:47 +0100] TX1 203.0.113.9 51234 * 443\n--e1-B--\n"
                "GET /x?id=1 HTTP/1.1\nhost: example.com\n--e1-H--\n"
                "ModSecurity: Warning. Matched \"Operator Rx\" [file \"f\"] [id \"942100\"] [msg \"SQL Injection\"]\n"
                "--e1-Z--\n")
        events = waf.parse_audit_text(text)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["hits"], [("942100", "SQL Injection")])
