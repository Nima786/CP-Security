from cpsec import access, advisor, config, ports, serverfw, settings, util
from tests.helpers import EnvTestCase

SS = (
    'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("litespeed",pid=900,fd=21))\n'
    'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=800,fd=3))\n'
    'LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=800,fd=4))\n'
    'LISTEN 0 80 127.0.0.1:3306 0.0.0.0:* users:(("mariadbd",pid=700,fd=22))\n'
    'LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=701,fd=6))\n'
    'LISTEN 0 511 *:5000 *:* users:(("node",pid=702,fd=19))\n'
    'LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=1,fd=14))\n'
    'LISTEN 0 128 10.0.0.5:9999 0.0.0.0:*\n'
    'LISTEN 0 511 0.0.0.0:8090 0.0.0.0:* users:(("lscpd",pid=5,fd=3))\n'
    'LISTEN 0 128 [::1]:631 [::]:*\n'
)

LIVE_LOCK = "table inet cps_lock { chain input { tcp dport { 22, 5000, 7080, 8090 } drop } }"


def by_port(rows, port):
    return next(r for r in rows if r["port"] == port)


class PortsCase(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.patch("cpsec.blocker.installed", return_value=False)
        self.fake.table.append((["ss"], (0, SS)))
        self.fake.table.append((["nft", "list", "table"], (0, LIVE_LOCK)))
        access.write_list(config.P.admin_list, [("203.0.113.9", "Home")], access.ADMIN_HEADER)


class Reading(PortsCase):
    def test_listening_reads_numbers_programs_and_how_far_each_reaches(self):
        found = {p["port"]: p for p in ports.listening()}
        self.assertEqual(found[80]["programs"], ["litespeed"])
        self.assertEqual(found[22]["reach"], "everyone")
        self.assertEqual(found[22]["programs"], ["sshd"])            # the IPv4 and IPv6 lines become one door
        self.assertEqual(found[3306]["reach"], "server")
        self.assertEqual(found[53]["reach"], "server")                # 127.0.0.53%lo
        self.assertEqual(found[9999]["reach"], "private")
        self.assertEqual(found[5000]["reach"], "everyone")            # *:5000
        self.assertEqual(found[631]["reach"], "server")               # [::1]

    def test_a_server_where_ss_is_missing_is_reported_not_crashed(self):
        self.fake.table.insert(0, (["ss"], (127, "not installed")))
        self.assertIsNone(ports.listening())
        self.assertIsNone(ports.rows())
        st = ports.state()
        self.assertFalse(st["supported"])
        self.assertTrue(st["message"])

    def test_every_door_is_judged_by_what_it_is(self):
        rows = ports.rows()
        self.assertEqual(by_port(rows, 6379)["level"], "bad")         # a cache open to everybody
        self.assertEqual(by_port(rows, 5000)["level"], "warn")        # an unknown program open to everybody
        self.assertEqual(by_port(rows, 3306)["status"], "closed")     # a database only this server can reach
        self.assertEqual(by_port(rows, 3306)["level"], "ok")
        self.assertEqual(by_port(rows, 8090)["status"], "locked")     # CyberPanel is locked by default
        self.assertEqual(by_port(rows, 8090)["locked_by"], "default")
        self.assertEqual(by_port(rows, 80)["level"], "ok")
        self.assertEqual(by_port(rows, 22)["level"], "ok")
        self.assertEqual(by_port(rows, 9999)["status"], "private")
        self.assertEqual(rows[0]["port"], 6379)                       # the worst first

    def test_the_ssh_program_is_recognised_on_any_port(self):
        name, kind, _, _, _ = ports._identify(2222, ["sshd"])
        self.assertEqual((name, kind), ("Server login (SSH)", "service"))

    def test_the_fixed_doors_cannot_be_locked(self):
        rows = ports.rows()
        self.assertFalse(by_port(rows, 80)["can_lock"])
        self.assertIn("websites", by_port(rows, 80)["cannot_lock_reason"])
        self.assertTrue(by_port(rows, 5000)["can_lock"])
        self.assertFalse(by_port(rows, 3306)["can_lock"])            # nothing to lock: already closed to outsiders

    def test_the_panels_own_door_is_managed_on_the_settings_page(self):
        settings.save({"domain": "panel.example.com", "port": 5000, "access": "login"})
        row = by_port(ports.rows(), 5000)
        self.assertEqual((row["name"], row["level"], row["can_lock"]), ("CP-Security panel", "ok", False))

    def test_a_firewall_in_front_is_named(self):
        self.fake.table.insert(0, (["systemctl", "is-active", "firewalld"], (0, "active\n")))
        self.assertEqual(ports.state()["firewall"], "firewalld")


class Choices(PortsCase):
    def test_knowing_about_a_door_silences_the_warning_and_it_can_come_back(self):
        self.assertEqual(by_port(ports.rows(), 5000)["level"], "warn")
        self.assertTrue(ports.accept(5000).ok)
        row = by_port(ports.rows(), 5000)
        self.assertEqual((row["level"], row["ignored"]), ("info", True))
        self.assertTrue(ports.accept(5000, False).ok)
        self.assertEqual(by_port(ports.rows(), 5000)["level"], "warn")

    def test_garbage_port_numbers_are_refused(self):
        for bad in (0, 70000, -3, "abc", None, True):
            for fn in (ports.lock, ports.unlock, ports.accept):
                self.assertEqual(fn(bad).code, "invalid", (fn.__name__, bad))

    def test_choices_with_junk_in_the_file_are_cleaned(self):
        util.write_json(config.P.ports_settings, {"locked": [5000, "x", True, 99999, 5000], "opened": "no", "accepted": None})
        self.assertEqual(settings.port_choices(), {"locked": [5000], "opened": [], "accepted": []})


class Locking(PortsCase):
    def test_locking_a_door_saves_it_and_loads_the_lock(self):
        res = ports.lock(5000, caller_ip="203.0.113.9")
        self.assertTrue(res.ok, res.message)
        self.assertIn("5000", res.message)
        self.assertEqual(settings.port_choices()["locked"], [5000])
        self.assertIn(5000, settings.lock_ports())
        self.assertIn("tcp dport { 8090, 7080, 8888, 5000 }", self.read(config.P.nft_file))
        self.assertTrue(self.fake.called("nft", "-f", config.P.nft_file))
        self.assertEqual(by_port(ports.rows(), 5000)["locked_by"], "you")
        self.assertEqual(by_port(ports.rows(), 5000)["status"], "locked")

    def test_the_lock_is_checked_against_what_is_really_loaded(self):
        self.fake.table[1] = (["nft", "list", "table"], (0, "table inet cps_lock { chain input { tcp dport { 8090 } drop } }"))
        res = ports.lock(5000)
        self.assertTrue(res.ok)
        self.assertIn("does not show it yet", res.message)

    def test_a_range_in_the_loaded_firewall_counts(self):
        self.fake.table[1] = (["nft", "list", "table"], (0, "tcp dport { 7000-7100, 8090 } drop"))
        self.assertTrue(ports._in_live_lock(7080))
        self.assertFalse(ports._in_live_lock(5000))

    def test_the_websites_themselves_can_never_be_locked(self):
        res = ports.lock(80, caller_ip="203.0.113.9", confirmed=True)
        self.assertEqual((res.ok, res.code), (False, "protected"))
        self.assertFalse(self.fake.called("nft", "-f", config.P.nft_file))

    def test_443_is_protected_too(self):
        self.fake.table[0] = (["ss"], (0, SS + 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("litespeed",pid=900,fd=22))\n'))
        self.assertEqual(ports.lock(443, confirmed=True).code, "protected")

    def test_a_door_nothing_listens_on_is_refused(self):
        self.assertEqual(ports.lock(12345).code, "not_listening")

    def test_a_door_only_this_server_can_reach_has_nothing_to_lock(self):
        self.assertEqual(ports.lock(3306).code, "already")

    def test_an_already_locked_door_is_not_locked_twice(self):
        self.assertEqual(ports.lock(8090).code, "already")

    def test_nothing_is_locked_without_a_trusted_address(self):
        access.write_list(config.P.admin_list, [], access.ADMIN_HEADER)
        self.assertEqual(ports.lock(5000).code, "no_trusted")
        self.assertEqual(settings.port_choices()["locked"], [])

    def test_the_server_login_needs_a_warning_acknowledged_and_a_trusted_caller(self):
        res = ports.lock(22, caller_ip="203.0.113.9")
        self.assertEqual(res.code, "needs_confirm")
        self.assertIn("emergency console", res.message)
        res = ports.lock(22, caller_ip="198.51.100.4", confirmed=True)
        self.assertEqual(res.code, "would_lock_you_out")
        self.assertEqual(settings.port_choices()["locked"], [])
        self.assertTrue(ports.lock(22, caller_ip="203.0.113.9", confirmed=True).ok)
        self.assertEqual(settings.port_choices()["locked"], [22])

    def test_docker_published_doors_are_refused_with_a_reason(self):
        self.fake.table[0] = (["ss"], (0, SS + 'LISTEN 0 4096 0.0.0.0:8123 0.0.0.0:* users:(("docker-proxy",pid=9,fd=4))\n'))
        res = ports.lock(8123)
        self.assertEqual(res.code, "not_supported")
        self.assertIn("Docker", res.message)
        self.assertFalse(by_port(ports.rows(), 8123)["can_lock"])

    def test_a_firewall_that_rejects_the_change_leaves_everything_as_it_was(self):
        self.fake.table.insert(0, (["nft", "-c"], (1, "syntax error")))
        res = ports.lock(5000, caller_ip="203.0.113.9")
        self.assertEqual((res.ok, res.code), (False, "nft_rejected"))
        self.assertIn("Nothing was changed", res.message)
        self.assertEqual(settings.port_choices()["locked"], [])

    def test_the_panel_port_is_not_locked_here(self):
        settings.save({"domain": "panel.example.com", "port": 5000, "access": "login"})
        self.assertEqual(ports.lock(5000).code, "managed")
        self.assertEqual(ports.unlock(5000).code, "managed")


class Unlocking(PortsCase):
    def test_a_door_locked_by_the_owner_can_be_opened_again(self):
        ports.lock(5000, caller_ip="203.0.113.9")
        res = ports.unlock(5000)
        self.assertTrue(res.ok, res.message)
        self.assertEqual(settings.port_choices()["locked"], [])
        self.assertNotIn(5000, settings.lock_ports())
        self.assertNotIn("5000", self.read(config.P.nft_file))

    def test_opening_an_admin_page_needs_a_warning_acknowledged_and_can_be_undone(self):
        res = ports.unlock(8090)
        self.assertEqual(res.code, "needs_confirm")
        self.assertIn("attacked", res.message)
        self.assertEqual(settings.lock_ports(), [8090, 7080, 8888])
        self.assertTrue(ports.unlock(8090, confirmed=True).ok)
        self.assertEqual(settings.lock_ports(), [7080, 8888])
        row = by_port(ports.rows(), 8090)
        self.assertEqual((row["status"], row["level"]), ("open", "info"))     # the owner's choice is not nagged about
        self.assertTrue(ports.lock(8090).ok)                                   # locking it again restores the default
        self.assertEqual(settings.lock_ports(), [8090, 7080, 8888])
        self.assertEqual(settings.port_choices()["opened"], [])

    def test_a_door_that_is_not_locked_cannot_be_opened(self):
        self.assertEqual(ports.unlock(5000).code, "not_locked")

    def test_a_locked_door_stays_on_the_page_while_its_program_is_stopped(self):
        ports.lock(5000, caller_ip="203.0.113.9")
        self.fake.table[0] = (["ss"], (0, SS.replace("*:5000", "127.0.0.1:1")))          # the program stopped
        row = by_port(ports.rows(), 5000)
        self.assertEqual((row["status"], row["can_open"]), ("idle", True))

    def test_opening_every_admin_page_leaves_a_valid_empty_lock(self):
        for p in config.ADMIN_PORTS:
            self.assertTrue(ports.unlock(p, confirmed=True).ok)
        self.assertEqual(settings.lock_ports(), [])
        text = self.read(config.P.nft_file)
        self.assertNotIn("dport", text)
        self.assertIn("table inet cps_lock", text)
        self.fake.table[1] = (["nft", "list", "table"], (0, "table inet cps_lock { chain input { } }"))
        self.assertTrue(access.lock_is_live())


class Advisor(PortsCase):
    def test_a_cache_open_to_the_internet_is_bad_and_a_localhost_database_is_not(self):
        findings = advisor.check_open_services()
        bad = next(f for f in findings if f["id"] == "open_services")
        self.assertEqual(bad["level"], "bad")
        self.assertIn("Redis", bad["detail"])
        self.assertNotIn("MariaDB", bad["detail"])
        self.assertEqual(bad["fix"], {"kind": "page", "id": "ports", "label": "Open the Open ports page"})

    def test_unknown_open_programs_are_one_warning_and_the_owner_can_silence_it(self):
        warn = next(f for f in advisor.check_open_services() if f["id"] == "open_ports")
        self.assertEqual(warn["level"], "warn")
        self.assertIn("5000", warn["detail"])
        ports.accept(5000)
        self.assertNotIn("open_ports", [f["id"] for f in advisor.check_open_services()])

    def test_locked_doors_are_not_complained_about(self):
        ports.lock(5000, caller_ip="203.0.113.9")
        ports.accept(6379)
        self.assertEqual(advisor.check_open_services(), [])

    def test_a_lock_with_no_ports_is_a_note_not_an_alarm(self):
        for p in config.ADMIN_PORTS:
            ports.unlock(p, confirmed=True)
        f = advisor.check_lock()[0]
        self.assertEqual((f["id"], f["level"]), ("lock", "info"))


class WithTheServerFirewall(PortsCase):
    def switch_on(self, *allowed):
        for p in allowed:
            self.assertTrue(serverfw.add_rule("x", "tcp", "", str(p)).ok)
        self.fake.table.insert(0, (["nft", "list", "table", "inet", "cps_fw"], (0, "table inet cps_fw { counter drop }")))

    def test_a_port_the_firewall_does_not_list_shows_as_refused_not_as_open(self):
        self.switch_on(80)
        rows = ports.rows()
        row = by_port(rows, 5000)
        self.assertEqual((row["status"], row["level"], row["can_lock"]), ("refused", "ok", False))
        self.assertIn("server firewall", row["status_text"])
        self.assertEqual((by_port(rows, 6379)["status"], by_port(rows, 6379)["level"]), ("refused", "ok"), "a cache the firewall refuses is no longer a danger")

    def test_a_port_on_the_firewalls_list_stays_open_and_says_why(self):
        self.switch_on(5000)
        row = by_port(ports.rows(), 5000)
        self.assertEqual((row["status"], row["level"]), ("open", "warn"))
        self.assertIn("Allowed by the server firewall's list", row["status_text"])

    def test_locked_and_server_only_ports_are_unchanged(self):
        self.switch_on()
        rows = ports.rows()
        self.assertEqual(by_port(rows, 8090)["status"], "locked")
        self.assertEqual(by_port(rows, 3306)["status"], "closed")

    def test_without_the_firewall_nothing_changes(self):
        self.assertEqual(by_port(ports.rows(), 5000)["status"], "open")


EXTRA_SS = (
    'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("litespeed",pid=900,fd=22))\n'
    'LISTEN 0 100 0.0.0.0:465 0.0.0.0:* users:(("master",pid=650,fd=13))\n'
    'LISTEN 0 100 0.0.0.0:587 0.0.0.0:* users:(("master",pid=650,fd=14))\n'
    'LISTEN 0 100 0.0.0.0:25 0.0.0.0:* users:(("master",pid=650,fd=15))\n'
    'LISTEN 0 100 0.0.0.0:21 0.0.0.0:* users:(("pure-ftpd-mysql",pid=651,fd=3))\n'
    'LISTEN 0 100 0.0.0.0:53 0.0.0.0:* users:(("pdns_server",pid=652,fd=3))\n'
    'LISTEN 0 100 0.0.0.0:4545 0.0.0.0:* users:(("tunnel",pid=660,fd=3))\n'
    'LISTEN 0 100 0.0.0.0:4546 0.0.0.0:* users:(("tunnel",pid=660,fd=4))\n'
)
FACTS = {"websites": ["a.example.com", "b.example.com"], "mail_domains": [], "mailboxes": 0, "ftp": [], "dns": []}


class InPlainWords(PortsCase):
    """The page tells the owner who uses each door today and what would stop if it were limited."""

    def setUp(self):
        super().setUp()
        self.fake.table.insert(0, (["ss"], (0, SS.replace('LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=1,fd=14))\n', "") + EXTRA_SS)))

    def row(self, port, facts=FACTS, commands=None):
        self.patch("cpsec.ports.usage_facts", return_value=facts)
        self.patch("cpsec.ports.program_info", side_effect=lambda pid: commands.get(pid, "") if commands else "")
        return by_port(ports.rows(details=True), port)

    def test_doors_that_belong_together_share_a_group(self):
        rows = ports.rows()
        self.assertEqual(by_port(rows, 80)["group"], by_port(rows, 443)["group"])
        self.assertEqual(by_port(rows, 465)["group"], by_port(rows, 587)["group"])
        self.assertNotEqual(by_port(rows, 25)["group"], by_port(rows, 465)["group"], "receiving mail and sending mail are different choices")
        self.assertNotEqual(by_port(rows, 4545)["group"], by_port(rows, 4546)["group"], "two unknown doors are never merged")

    def test_the_websites_are_named_and_cannot_be_limited(self):
        r = self.row(80)
        self.assertIn("2 websites", r["uses"])
        self.assertIn("a.example.com", r["uses"])
        self.assertIn("never be limited", r["if_limited"])
        self.assertFalse(r["nothing_stops"])

    def test_a_mail_door_on_a_server_without_mail_says_nothing_would_stop(self):
        for port in (25, 465, 587):
            r = self.row(port)
            self.assertTrue(r["nothing_stops"], port)
            self.assertEqual(r["if_limited"], ports.NOTHING)
            self.assertIn("No", r["uses"])

    def test_a_mail_door_names_the_domains_that_would_lose_their_email(self):
        r = self.row(25, dict(FACTS, mail_domains=["shop.example.com", "blog.example.com"]))
        self.assertIn("2 domains", r["uses"])
        self.assertIn("shop.example.com", r["uses"])
        self.assertIn("could no longer deliver email", r["if_limited"])
        self.assertFalse(r["nothing_stops"])

    def test_mailboxes_are_counted(self):
        r = self.row(465, dict(FACTS, mailboxes=3))
        self.assertIn("3 mailboxes", r["uses"])
        self.assertFalse(r["nothing_stops"])

    def test_ftp_accounts_are_named_and_sftp_is_said_to_be_unaffected(self):
        r = self.row(21, dict(FACTS, ftp=["uploader", "editor"]))
        self.assertIn("2 FTP accounts: uploader, editor", r["uses"])
        self.assertIn("SFTP", r["if_limited"])
        self.assertTrue(self.row(21)["nothing_stops"], "no FTP accounts: nobody uses it")

    def test_dns_explains_that_it_only_matters_when_the_name_servers_point_here(self):
        r = self.row(53, dict(FACTS, dns=["a.example.com", "b.example.com"]))
        self.assertIn("2 domains", r["uses"])
        self.assertIn("name servers point to this server", r["uses"])
        self.assertIn("another company hosts", r["if_limited"])

    def test_what_could_not_be_read_is_never_guessed(self):
        """Without CyberPanel's database nothing is claimed about mailboxes or accounts: the general sentence is used."""
        blank = {"websites": [], "mail_domains": None, "mailboxes": None, "ftp": None, "dns": None}
        for port in (21, 25, 53, 465):
            r = self.row(port, blank)
            self.assertFalse(r["nothing_stops"], port)
            self.assertTrue(r["uses"] and r["if_limited"], port)

    def test_an_unknown_program_says_where_it_comes_from(self):
        r = self.row(4545, commands={660: "/usr/local/bin/tunnel, service tunnel.service, run by root"})
        self.assertIn("/usr/local/bin/tunnel", r["uses"])
        self.assertIn("service tunnel.service", r["uses"])
        self.assertEqual(len(r["commands"]), 1)
        self.assertIn("trusted addresses", r["if_limited"])
        self.assertNotIn("safe", r["if_limited"].lower(), "a tunnel or an app may need outsiders: no promise that limiting it is safe")

    def test_the_advisors_list_does_not_read_the_database(self):
        calls = self.patch("cpsec.ports.usage_facts", return_value=FACTS)
        ports.rows()
        calls.assert_not_called()

    def test_the_page_state_lists_the_trusted_addresses(self):
        self.patch("cpsec.ports.usage_facts", return_value=FACTS)
        st = ports.state()
        self.assertEqual([t["address"] for t in st["trusted_list"]], ["203.0.113.9"])
        self.assertEqual(st["trusted"], 1)


class WhatTheServerReallyDoes(PortsCase):
    def test_without_cyberpanel_nothing_is_read_from_its_database(self):
        facts = ports.usage_facts()
        self.assertEqual([facts["mail_domains"], facts["mailboxes"], facts["ftp"], facts["dns"]], [None, None, None, None])
        self.assertEqual(self.fake.called("mysql"), [])

    def test_with_cyberpanel_the_answers_are_used(self):
        import os
        os.makedirs(config.P.at("/usr/local/CyberCP"))
        os.makedirs(config.P.home_dir + "/shop.example.com/public_html")

        def mysql(cmd):
            q = cmd[-1]
            if "e_domains" in q:
                return 0, "shop.example.com\n"
            if "count(*)" in q:
                return 0, "4\n"
            if "cyberpanel.users" in q:
                return 0, "uploader\n"
            if "cyberpanel.domains" in q:
                return 0, "a.example.com\nb.example.com\n"
            return 1, ""
        self.fake.table.insert(0, (["mysql"], mysql))
        f = ports.usage_facts()
        self.assertEqual(f["websites"], ["shop.example.com"])
        self.assertEqual(f["mail_domains"], ["shop.example.com"])
        self.assertEqual(f["mailboxes"], 4)
        self.assertEqual(f["ftp"], ["uploader"])
        self.assertEqual(f["dns"], ["a.example.com", "b.example.com"])

    def test_a_failed_question_is_unknown_not_empty(self):
        import os
        os.makedirs(config.P.at("/usr/local/CyberCP"))
        self.fake.table.insert(0, (["mysql"], (1, "ERROR 1045 Access denied")))
        f = ports.usage_facts()
        self.assertIsNone(f["mail_domains"])
        self.assertIsNone(f["mailboxes"])
        self.assertIsNone(f["ftp"])

    def test_a_program_is_described_without_its_arguments(self):
        """Arguments can hold passwords, so only the program, its folder, its service and its owner are shown."""
        try:
            import pwd
        except ImportError:
            self.skipTest("needs Linux")
        from unittest import mock
        links = {"/proc/7/exe": "/usr/bin/node", "/proc/7/cwd": "/opt/app"}
        with mock.patch("cpsec.ports.os.readlink", side_effect=lambda p: links[p]), \
                mock.patch("cpsec.ports.os.stat", return_value=mock.Mock(st_uid=0)), \
                mock.patch.object(pwd, "getpwuid", return_value=mock.Mock(pw_name="root")), \
                mock.patch("builtins.open", mock.mock_open(read_data="0::/system.slice/app.service\n")):
            text = ports.program_info(7)
        self.assertEqual(text, "/usr/bin/node, started in /opt/app, service app.service, run by root")

    def test_a_program_that_has_gone_is_just_blank(self):
        self.assertEqual(ports.program_info(999999999), "")
