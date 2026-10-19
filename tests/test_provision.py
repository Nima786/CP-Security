import hashlib
import io
import os
import tarfile
import time
from unittest import mock

from cpsec import access, blocker, config, provision, settings, util, waf, webserver
from cpsec.util import Result
from tests.helpers import EnvTestCase


def make_tarball(files, extra=()):
    """A pretend OWASP download: coreruleset-3.3.10/rules/<name> for every file."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo("coreruleset-3.3.10/rules/" + name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for info, data in extra:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


CRS_FILES = {
    "REQUEST-901-INITIALIZATION.conf": 'SecRule REQUEST_HEADERS:Host "@rx ." "id:901001,phase:1,pass,nolog"\n',
    "REQUEST-905-COMMON-EXCEPTIONS.conf": 'SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" "id:905100,phase:1,allow"\n',
    "REQUEST-942-APPLICATION-ATTACK-SQLI.conf": 'SecRule ARGS "@detectSQLi" "id:942100,phase:2,pass,log"\n',
    "REQUEST-949-BLOCKING-EVALUATION.conf": 'SecRule TX:ANOMALY_SCORE "@ge 5" "id:949110,phase:2,deny"\n',
    "sql-errors.data": "error\n",
}


class Packages(EnvTestCase):
    def test_ubuntu_uses_apt_and_almalinux_uses_dnf(self):
        self.write(config.P.at("/etc/debian_version"), "12\n")
        self.assertTrue(provision.install_packages(["fail2ban"]).ok)
        self.assertTrue(self.fake.called("env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "fail2ban"))
        os.remove(config.P.at("/etc/debian_version"))
        self.fake.calls.clear()
        provision.install_packages(["fail2ban"])
        self.assertTrue(self.fake.called("dnf", "install", "-y", "epel-release"), "fail2ban lives in EPEL")
        self.assertTrue(self.fake.called("dnf", "install", "-y", "fail2ban"))

    def test_a_failed_install_says_so(self):
        self.fake.table.append((["dnf", "install", "-y", "nftables"], (1, "No match for argument: nftables\n")))
        r = provision.install_packages(["nftables"])
        self.assertEqual((r.ok, r.code), (False, "install_failed"))
        self.assertIn("No match", r.message)


class Download(EnvTestCase):
    def opener(self, data):
        return lambda url: io.BytesIO(data)

    def test_the_pinned_download_passes_its_fingerprint_check(self):
        data = b"hello"
        got = provision.fetch_crs("https://x", hashlib.sha256(data).hexdigest(), self.opener(data))
        self.assertEqual(got, data)

    def test_a_changed_download_is_refused(self):
        with self.assertRaises(ValueError):
            provision.fetch_crs("https://x", hashlib.sha256(b"hello").hexdigest(), self.opener(b"hellO"))

    def test_an_oversized_download_is_refused(self):
        big = b"x" * (provision.CRS_MAX_BYTES + 5)
        with self.assertRaises(ValueError):
            provision.fetch_crs("https://x", hashlib.sha256(big).hexdigest(), self.opener(big))

    def test_only_rule_files_are_unpacked_and_nothing_can_escape_the_folder(self):
        evil = tarfile.TarInfo("coreruleset-3.3.10/rules/../../escape.conf")
        evil.size = 1
        link = tarfile.TarInfo("coreruleset-3.3.10/rules/link.conf")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        other = tarfile.TarInfo("coreruleset-3.3.10/tests/regression.yaml")
        other.size = 1
        data = make_tarball(CRS_FILES, extra=[(evil, b"x"), (link, None), (other, b"x")])
        dest = os.path.join(self.root, "out")
        provision.extract_rules(data, dest)
        self.assertEqual(sorted(os.listdir(dest)), sorted(CRS_FILES))
        self.assertFalse(os.path.exists(os.path.join(self.root, "escape.conf")))

    def test_an_empty_download_is_an_error(self):
        with self.assertRaises(ValueError):
            provision.extract_rules(make_tarball({}), os.path.join(self.root, "out"))


class RulesFile(EnvTestCase):
    def test_only_files_that_exist_are_included_and_in_the_right_order(self):
        text = provision.render_rules({"REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "REQUEST-901-INITIALIZATION.conf",
                                       "REQUEST-905-COMMON-EXCEPTIONS.conf", "REQUEST-949-BLOCKING-EVALUATION.conf"})
        lines = [l for l in text.splitlines() if l.startswith("Include")]
        names = [os.path.basename(l.split(" ", 1)[1]) for l in lines]
        self.assertEqual(names, ["crs-setup.conf", "exceptions-before.conf", "REQUEST-901-INITIALIZATION.conf",
                                 "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "block-rule.conf", "exceptions-after.conf"])
        self.assertNotIn("905", text)
        self.assertNotIn("949", text)


class Plan(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.patch("cpsec.blocker.installed", return_value=False)

    def states(self):
        return {s["key"]: s["state"] for s in provision.plan()}

    def test_an_empty_server_is_ready_for_the_blocker_but_not_for_the_lock_or_firewall(self):
        st = self.states()
        self.assertEqual(st["lock"], "blocked", "no trusted address yet: it would lock the owner out")
        self.assertEqual(st["blocker"], "todo")
        self.assertEqual(st["feed"], "todo")
        self.assertEqual(st["waf"], "blocked")
        self.assertEqual(st["migrate"], "skip")
        self.assertEqual(st["retire"], "skip")

    def test_with_a_trusted_address_the_lock_can_go_ahead(self):
        access.write_list(config.P.admin_list, [("203.0.113.9", "Home")], access.ADMIN_HEADER)
        self.assertEqual(self.states()["lock"], "todo")

    def test_todo_steps_describe_what_they_will_do_in_plain_words(self):
        steps = {s["key"]: s for s in provision.plan()}
        self.assertTrue(steps["blocker"]["will_do"])
        self.assertEqual(steps["waf"]["will_do"], [], "blocked steps promise nothing")
        self.assertIn("No LiteSpeed", steps["waf"]["note"])

    def test_the_plan_changes_nothing_on_the_server(self):
        provision.plan()
        self.assertFalse(os.path.exists(config.P.conf_dir))
        self.assertEqual([c for c in self.fake.calls if c[0] in ("systemctl",) and c[1] in ("enable", "start", "stop")], [])

    def test_firewall_is_not_offered_when_cyberpanels_own_rules_are_on(self):
        self.write(config.P.lsws_xml, "<config/>")
        self.write(config.P.at("/usr/local/lsws/conf/comodo_litespeed/rules.conf"), "")
        self.write(config.P.modsec_conf, "<IfModule security2_module>\nInclude /usr/local/lsws/conf/comodo_litespeed/rules.conf\n</IfModule>\n")
        steps = {s["key"]: s for s in provision.plan()}
        self.assertEqual(steps["waf"]["state"], "blocked")
        self.assertIn("same rule numbers", steps["waf"]["note"])


class LockStep(EnvTestCase):
    def setUp(self):
        super().setUp()
        access.write_list(config.P.admin_list, [("203.0.113.9", "Home")], access.ADMIN_HEADER)
        self.patch("cpsec.blocker.installed", return_value=False)
        self.patch("cpsec.provision.shutil.which", return_value="/usr/sbin/nft")

    def test_loads_the_lock_and_makes_it_survive_a_restart(self):
        r = provision.BY_KEY["lock"].run(lambda m: None)
        self.assertTrue(r.ok, r.message)
        self.assertIn("203.0.113.9", util.read_text(config.P.nft_file))
        unit = util.read_text(config.P.systemd_dir + "/" + provision.SERVICE_LOCK)
        self.assertIn("ExecStart=/usr/sbin/nft -f " + config.P.nft_file, unit)
        self.assertTrue(self.fake.called("systemctl", "enable"))

    def test_a_firewall_that_refuses_the_list_stops_the_step(self):
        self.fake.table.append((["nft", "-c"], (1, "syntax error")))
        r = provision.BY_KEY["lock"].run(lambda m: None)
        self.assertEqual((r.ok, r.code), (False, "nft_rejected"))
        self.assertFalse(os.path.exists(config.P.systemd_dir + "/" + provision.SERVICE_LOCK))


class FeedStep(EnvTestCase):
    def test_writes_the_service_and_checks_it_stays_up(self):
        self.patch("cpsec.provision.time.sleep")
        self.fake.table.append((["systemctl", "is-active", provision.SERVICE_FEED], (0, "active\n")))
        r = provision.BY_KEY["feed"].run(lambda m: None)
        self.assertTrue(r.ok, r.message)
        unit = util.read_text(config.P.systemd_dir + "/" + provision.SERVICE_FEED)
        self.assertIn("-m cpsec.feed", unit)
        self.assertIn("PYTHONPATH=" + config.P.install_dir, unit)

    def test_a_service_that_dies_at_once_is_reported(self):
        self.patch("cpsec.provision.time.sleep")
        self.fake.table.append((["systemctl", "is-active", provision.SERVICE_FEED], (3, "failed\n")))
        self.assertEqual(provision.BY_KEY["feed"].run(lambda m: None).code, "not_running")


class BlockerStep(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.patch("cpsec.provision.time.sleep")
        self.write(config.P.at("/var/log/mail.log"), "")
        self.write(config.P.at("/var/log/syslog"), "")
        self.fake.table.append((["fail2ban-client", "-t"], (0, "OK")))

    def test_installs_when_missing_then_writes_enables_and_checks_the_protections_loaded(self):
        installed = mock.Mock(side_effect=[False, True, True, True, True])
        self.patch("cpsec.blocker.installed", installed)
        self.patch("cpsec.blocker.jails", return_value=["sshd", "cps-wp-login"])
        r = provision.BY_KEY["blocker"].run(lambda m: None)
        self.assertTrue(r.ok, r.message)
        self.assertTrue(self.fake.called("apt-get", "install") or self.fake.called("env") or self.fake.called("dnf"))
        self.assertTrue(self.fake.called("systemctl", "enable", "--now", "fail2ban"))
        self.assertIn("[cps-wp-login]", util.read_text(config.P.f2b_jails))
        self.assertTrue(os.path.exists(config.P.logrotate_dir + "/cps-wp-login"))

    def test_protections_that_did_not_load_are_reported(self):
        self.patch("cpsec.blocker.installed", return_value=True)
        self.patch("cpsec.blocker.jails", return_value=["sshd"])
        self.assertEqual(provision.BY_KEY["blocker"].run(lambda m: None).code, "not_loaded")

    def test_a_blocker_that_rejects_the_settings_leaves_nothing_behind(self):
        self.patch("cpsec.blocker.installed", return_value=True)
        self.fake.table.insert(0, (["fail2ban-client", "-t"], (1, "ERROR")))
        r = provision.BY_KEY["blocker"].run(lambda m: None)
        self.assertEqual(r.code, "f2b_rejected")
        self.assertFalse(os.path.exists(config.P.f2b_jails))


class WafStep(EnvTestCase):
    def setUp(self):
        super().setUp()
        p = config.P
        self.write(p.lsws_xml, "<config/>")
        self.original = "<IfModule security2_module>\nSecAuditLogParts AFH\n</IfModule>\n"
        self.write(p.modsec_conf, self.original)
        self.restart = self.patch("cpsec.waf.restart_and_check", return_value=(True, []))
        self.selftest = self.patch("cpsec.waf.selftest", return_value=Result(True, "The firewall saw the test request.", "seen"))
        self.fetch = self.patch("cpsec.provision.fetch_crs", return_value=make_tarball(CRS_FILES))

    def run_step(self):
        return provision.BY_KEY["waf"].run(lambda m: None)

    def test_a_fresh_install_ends_in_watch_only_mode_with_everything_connected(self):
        r = self.run_step()
        self.assertTrue(r.ok, r.message)
        self.assertEqual(waf.mode(), "watch")
        self.assertTrue(webserver.hook_present())
        rules = util.read_text(config.P.waf_rules)
        self.assertIn("REQUEST-942-APPLICATION-ATTACK-SQLI.conf", rules)
        self.assertNotIn("905", rules)
        self.assertTrue(os.path.exists(config.P.waf_crs + "/sql-errors.data"))
        self.assertIn("SecRuleEngine On", util.read_text(config.P.waf_main))
        self.assertIn("crs_setup_version=3310", util.read_text(config.P.waf_setup))
        self.assertTrue(os.path.exists(config.P.audit_log))
        self.assertTrue(self.restart.called and self.selftest.called)

    def test_the_settings_are_the_ones_proven_on_the_first_server(self):
        self.run_step()
        main = util.read_text(config.P.waf_main)
        for line in ("SecRequestBodyAccess On", "SecRequestBodyLimit 13107200", "SecRequestBodyNoFilesLimit 1310720",
                     "SecRequestBodyLimitAction ProcessPartial", "SecResponseBodyAccess Off", "SecAuditLogParts ABHZ",
                     "SecDataDir " + config.P.modsec_data):
            self.assertIn(line, main)
        setup = util.read_text(config.P.waf_setup)
        self.assertIn("GET HEAD POST OPTIONS PUT PATCH DELETE", setup, "the WordPress editor and the shop API use these")
        self.assertIn("tx.paranoia_level=1", setup)
        self.assertIn("inbound_anomaly_score_threshold=5", setup)
        self.assertTrue(os.path.isdir(config.P.modsec_data))
        rules = util.read_text(config.P.waf_rules)
        self.assertNotIn("934", rules)
        self.assertNotIn("944", rules)

    def test_the_firewall_log_is_rotated_and_never_twice(self):
        self.run_step()
        rotate = util.read_text(config.P.logrotate_dir + "/cps-waf")
        self.assertIn(config.P.audit_log, rotate)
        self.assertIn("chmod 600", rotate)

    def test_an_existing_rotation_of_the_same_log_is_respected(self):
        self.write(config.P.logrotate_dir + "/pb-waf", config.P.audit_log + " {\n    daily\n}\n")
        self.run_step()
        self.assertFalse(os.path.exists(config.P.logrotate_dir + "/cps-waf"), "two entries would make logrotate skip both")

    def test_the_converter_removed_the_skip_instructions(self):
        self.fetch.return_value = make_tarball({
            "REQUEST-942-APPLICATION-ATTACK-SQLI.conf":
                'SecRule ARGS "@detectSQLi" "id:942100,phase:2,pass,log"\n'
                'SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 2" "id:942011,phase:1,pass,nolog,skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"\n'
                'SecRule ARGS "@rx stricter" "id:942200,phase:2,pass,log"\n'
                'SecMarker "END-REQUEST-942-APPLICATION-ATTACK-SQLI"\n'})
        self.run_step()
        converted = util.read_text(config.P.waf_crs + "/REQUEST-942-APPLICATION-ATTACK-SQLI.conf")
        self.assertIn("942100", converted)
        self.assertNotIn("942200", converted, "the stricter levels are cut out")
        self.assertNotIn("skipAfter", converted)

    def test_running_it_again_is_harmless(self):
        self.run_step()
        first = util.read_text(webserver.firewall_file())
        self.assertTrue(self.run_step().ok)
        self.assertEqual(util.read_text(webserver.firewall_file()), first)
        self.assertEqual(provision.BY_KEY["waf"].state()[0], "done")

    def test_a_site_that_stops_answering_undoes_everything(self):
        self.restart.side_effect = [(False, [("shop.example.com", "500")]), (True, [])]
        r = self.run_step()
        self.assertEqual((r.ok, r.code), (False, "rolled_back"))
        self.assertEqual(util.read_text(config.P.modsec_conf), self.original)
        self.assertFalse(os.path.exists(config.P.waf_dir))
        self.assertIsNone(waf.mode())
        self.assertEqual(self.restart.call_count, 2, "restarted again after the undo")

    def test_a_firewall_that_cannot_see_attacks_is_taken_out_again(self):
        self.selftest.return_value = Result(False, "It did not record the test.", "not_seen")
        r = self.run_step()
        self.assertEqual((r.ok, r.code), (False, "not_seen"))
        self.assertEqual(util.read_text(config.P.modsec_conf), self.original)
        self.assertFalse(os.path.exists(config.P.waf_dir))

    def test_a_failed_download_changes_nothing(self):
        self.fetch.side_effect = ValueError("fingerprint")
        r = self.run_step()
        self.assertEqual((r.ok, r.code), (False, "download_failed"))
        self.assertEqual(util.read_text(config.P.modsec_conf), self.original)
        self.assertFalse(self.restart.called)
        self.assertFalse(os.path.exists(config.P.waf_dir))

    def test_cyberpanels_own_rules_are_never_doubled_up(self):
        self.write(config.P.at("/usr/local/lsws/conf/comodo_litespeed/x.conf"), "")
        self.write(config.P.modsec_conf, self.original + "Include /usr/local/lsws/conf/comodo_litespeed/x.conf\n")
        r = self.run_step()
        self.assertEqual((r.ok, r.code), (False, "blocked"))
        self.assertFalse(self.fetch.called)

    def test_openlitespeed_install_goes_into_the_module_block(self):
        os.remove(config.P.lsws_xml)
        os.remove(config.P.modsec_conf)
        self.write(config.P.lsws_bin_ols, "")
        self.write(config.P.ols_module, "")
        self.write(config.P.ols_conf, "module mod_security {\nmodsecurity on\nmodsecurity_rules_file /x/rules.conf\n}\n")
        r = self.run_step()
        self.assertTrue(r.ok, r.message)
        text = util.read_text(config.P.ols_conf)
        self.assertIn("modsecurity_rules_file " + config.P.waf_main, text)
        self.assertEqual(waf.mode(), "watch")

    def test_an_earlier_blocking_setup_stays_blocking(self):
        os.makedirs(config.P.legacy_conf_dir)
        self.write(config.P.lsws_conf + "/pb-waf/block-rule.conf",
                   'SecRule TX:ANOMALY_SCORE_PL1 "@ge 8" "id:1000900,phase:2,deny"\n')
        self.run_step()
        self.assertEqual(waf.mode(), "block")
        self.assertEqual(waf.threshold(), 8)


class Earlier(EnvTestCase):
    """The hand-made setup that was on the first server."""

    def setUp(self):
        super().setUp()
        p = config.P
        self.write(p.legacy_conf_dir + "/admin-access.list", "203.0.113.9 | Home\n")
        self.write(p.legacy_conf_dir + "/never-block.list", "104.16.0.0/13 | Cloudflare\n")
        self.write(p.legacy_conf_dir + "/something-unknown.txt", "keep me\n")
        self.write(p.systemd_dir + "/pb-wplogin-feed.service", "[Unit]\n")
        self.write(p.systemd_dir + "/pb-admin-firewall.service", "[Unit]\n")
        self.write(p.at("/etc/fail2ban/jail.d/pb-jails.local"), "[pb-wp-login]\n")
        self.write(p.f2b_filter_dir + "/pb-wp-login.conf", "[Definition]\n")
        self.write(p.lsws_conf + "/pb-waf/rules.conf", "x\n")
        self.write(p.at("/var/log/pb-wp-login.log"), "")
        self.write(p.at("/etc/pb-admin-firewall.nft"), "table inet pb_fw {}\n")
        self.write(p.at("/etc/pb-admin-firewall.nft.bak-20261017-103402"), "x")
        self.write(p.at("/usr/local/sbin/pb-wplogin-feed"), "#!/bin/bash\n")
        self.write(p.at("/usr/local/lib/pb-security/pb_rules_pl1.py"), "x")
        self.write(p.logrotate_dir + "/pb-waf", config.P.audit_log + " {\n    daily\n}\n")
        self.write(p.logrotate_dir + "/pb-wp-login", "/var/log/pb-wp-login.log {\n    daily\n}\n")
        self.fake.table.append((["nft", "list", "tables"], (0, "table inet pb_fw\ntable inet f2b-table\n")))
        self.patch("cpsec.blocker.installed", return_value=True)
        self.patch("cpsec.provision.time.sleep")

    def test_it_is_noticed(self):
        items = " ".join(provision.legacy_items())
        for word in ("pb-security", "pb-wplogin-feed.service", "pb-jails.local", "pb-waf", "pb_fw"):
            self.assertIn(word, items)

    def test_migrate_copies_the_lists_and_never_overwrites(self):
        self.write(config.P.admin_list, "198.51.100.7 | Already here\n")
        r = provision.BY_KEY["migrate"].run(lambda m: None)
        self.assertTrue(r.ok)
        self.assertEqual(util.read_text(config.P.admin_list), "198.51.100.7 | Already here\n")
        self.assertEqual(util.read_text(config.P.never_list), "104.16.0.0/13 | Cloudflare\n")
        self.assertEqual(provision.BY_KEY["migrate"].state()[0], "done")

    def test_the_old_setup_is_only_put_away_once_the_new_one_is_live(self):
        self.patch("cpsec.access.lock_is_live", return_value=False)
        self.assertEqual(provision.BY_KEY["retire"].state()[0], "blocked")
        self.assertEqual(provision.BY_KEY["retire"].run(lambda m: None).code, "not_ready")
        self.assertTrue(os.path.exists(config.P.legacy_conf_dir + "/admin-access.list"))
        self.assertEqual(self.fake.called("nft", "delete"), [])

    def test_retire_switches_the_old_things_off_and_moves_every_file_into_a_backup(self):
        self.patch("cpsec.access.lock_is_live", return_value=True)
        self.patch("cpsec.blocker.jails", return_value=["sshd", "cps-wp-login"])
        self.patch("cpsec.provision.unit_active", return_value=True)
        self.patch("cpsec.waf.mode", return_value="watch")
        r = provision.BY_KEY["retire"].run(lambda m: None)
        self.assertTrue(r.ok, r.message)
        self.assertTrue(self.fake.called("systemctl", "disable", "--now", "pb-wplogin-feed.service"))
        self.assertTrue(self.fake.called("nft", "delete", "table", "inet", "pb_fw"))
        self.assertEqual(self.fake.called("nft", "delete", "table", "inet", "f2b-table"), [], "someone else's table")
        for gone in (config.P.systemd_dir + "/pb-wplogin-feed.service", config.P.legacy_conf_dir,
                     config.P.at("/etc/fail2ban/jail.d/pb-jails.local"), config.P.lsws_conf + "/pb-waf",
                     config.P.at("/var/log/pb-wp-login.log")):
            self.assertFalse(os.path.exists(gone), gone)
        backup = [d for d in os.listdir(config.P.conf_dir) if d.startswith("legacy-")]
        self.assertEqual(len(backup), 1)
        saved = os.listdir(os.path.join(config.P.conf_dir, backup[0]))
        self.assertEqual(len(saved), 13, saved)
        for gone in ("/etc/pb-admin-firewall.nft", "/usr/local/sbin/pb-wplogin-feed", "/usr/local/lib/pb-security"):
            self.assertFalse(os.path.exists(config.P.at(gone)), gone)
        self.assertTrue(os.path.exists(config.P.logrotate_dir + "/cps-waf"),
                        "the firewall log keeps being rotated once the earlier rotation file is gone")
        # only the table is still "listed", and only because the pretend firewall tool keeps answering the same
        self.assertEqual([i for i in provision.legacy_items() if "firewall table" not in i], [])

    def test_a_blocker_that_rejects_the_cleanup_is_reported_with_the_backup_place(self):
        self.patch("cpsec.access.lock_is_live", return_value=True)
        self.patch("cpsec.blocker.jails", return_value=["sshd", "cps-wp-login"])
        self.patch("cpsec.provision.unit_active", return_value=True)
        self.patch("cpsec.waf.mode", return_value="watch")
        self.fake.table.insert(0, (["fail2ban-client", "-t"], (1, "ERROR")))
        r = provision.BY_KEY["retire"].run(lambda m: None)
        self.assertEqual((r.ok, r.code), (False, "f2b_rejected"))
        self.assertIn("legacy-", r.message)


class RunnerTests(EnvTestCase):
    class Fake(provision.Step):
        def __init__(self, key, state="todo", result=None, boom=False):
            self.key, self.title, self._state, self.result, self.boom, self.ran = key, key.title(), state, result, boom, False

        def state(self):
            return self._state, "note"

        def describe(self):
            return []

        def run(self, log):
            self.ran = True
            log("working on " + self.key)
            if self.boom:
                raise RuntimeError("kaboom")
            return self.result or Result(True, self.key + " ok")

    def go(self, steps, keys=None):
        runner = provision.Runner(steps)
        runner.start(keys, background=False)
        return runner.snapshot()

    def test_steps_run_in_order_and_are_reported(self):
        a, b = self.Fake("a"), self.Fake("b")
        job = self.go([a, b])
        self.assertEqual(job["status"], "done")
        self.assertEqual([s["state"] for s in job["steps"]], ["done", "done"])
        self.assertTrue(any("working on a" in l for l in job["log"]))

    def test_a_failure_stops_the_rest(self):
        a, b, c = self.Fake("a", result=Result(False, "no")), self.Fake("b"), self.Fake("c")
        job = self.go([a, b, c])
        self.assertEqual(job["status"], "failed")
        self.assertEqual([s["state"] for s in job["steps"]], ["failed", "skipped", "skipped"])
        self.assertFalse(b.ran or c.ran)

    def test_done_and_skipped_steps_are_not_run_again(self):
        a, b = self.Fake("a", state="done"), self.Fake("b", state="skip")
        job = self.go([a, b])
        self.assertFalse(a.ran or b.ran)
        self.assertEqual(job["status"], "done")

    def test_a_blocked_step_fails_the_job_with_its_reason(self):
        job = self.go([self.Fake("a", state="blocked"), self.Fake("b")])
        self.assertEqual(job["steps"][0]["message"], "note")
        self.assertEqual(job["status"], "failed")

    def test_an_exception_inside_a_step_is_caught(self):
        job = self.go([self.Fake("a", boom=True)])
        self.assertEqual(job["status"], "failed")
        self.assertIn("kaboom", job["steps"][0]["message"])

    def test_only_the_chosen_steps_run(self):
        a, b = self.Fake("a"), self.Fake("b")
        self.go([a, b], keys=["b"])
        self.assertFalse(a.ran)
        self.assertTrue(b.ran)

    def test_a_second_start_while_running_is_refused(self):
        runner = provision.Runner([self.Fake("a")])
        runner.job["status"] = "running"
        self.assertEqual(runner.start().code, "busy")
        self.assertEqual(provision.Runner([]).start().code, "empty")


class PanelService(EnvTestCase):
    def test_writes_and_starts_the_service(self):
        r = provision.install_panel_service()
        self.assertTrue(r.ok, r.message)
        unit = util.read_text(config.P.systemd_dir + "/" + provision.SERVICE_PANEL)
        self.assertIn("-m cpsec panel run", unit)
        self.assertIn("ExecReload=/bin/kill -HUP $MAINPID", unit)
        self.assertTrue(self.fake.called("systemctl", "enable", "--now", provision.SERVICE_PANEL))
