import argparse
import os
import threading
from unittest import mock

from cpsec import access, cli, config, installer, provision, settings, tls, util, webserver
from cpsec.panel import auth
from cpsec.panel import cli as panel_cli
from cpsec.util import Result
from tests.helpers import EnvTestCase

GOOD_DNS = {"exists": True, "ips": ["203.0.113.50"], "cloudflare": False, "points_here": True}
PASSWORD = "a long enough password"


class FakeConsole:
    """Answers questions from a table of (part of the question, answer)."""
    assume_yes = False

    def __init__(self, answers=None, secrets=None, yeses=None):
        self.said, self.answers, self.secrets, self.yeses = [], answers or [], list(secrets or [PASSWORD, PASSWORD]), yeses or {}
        self.asked = []

    def say(self, text=""):
        self.said.append(text)

    def ask(self, prompt, default=""):
        self.asked.append(prompt)
        for part, answer in self.answers:
            if part in prompt:
                return answer
        return default

    def secret(self, prompt):
        return self.secrets.pop(0)

    def yes(self, prompt, default=True):
        for part, answer in self.yeses.items():
            if part in prompt:
                return answer
        return default

    @property
    def text(self):
        return "\n".join(self.said)


def args(**kw):
    base = dict(domain=None, port=None, email=None, username=None, trusted_ip=None, open_login=False,
                skip_protections=False, skip_certificate=False)
    base.update(kw)
    return argparse.Namespace(**base)


class Asking(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.patch("cpsec.installer.preflight", return_value=[("ok", "Web server: OpenLiteSpeed 1.8.3")])
        self.patch("cpsec.installer.port_in_use", return_value=False)
        self.dns = self.patch("cpsec.installer.netinfo.check_domain", return_value=GOOD_DNS)
        env = mock.patch.dict(os.environ, {"SSH_CONNECTION": "45.60.0.10 51000 185.1.1.1 22"})
        env.start()
        self.addCleanup(env.stop)

    def gather(self, console, **kw):
        return installer.gather(console, args(**kw))

    def test_the_happy_path_collects_everything(self):
        c = FakeConsole(answers=[("Sub-domain", "Security.Example.com"), ("Another trusted", "")])
        cfg = self.gather(c)
        self.assertEqual((cfg["domain"], cfg["port"], cfg["username"]), ("security.example.com", 9443, "admin"))
        self.assertEqual(cfg["email"], "admin@security.example.com")
        self.assertEqual(cfg["trusted"], ["45.60.0.10"], "the address of the SSH session is offered and taken")
        self.assertEqual((cfg["access"], cfg["protections"]), ("trusted", True))

    def test_choosing_the_open_login_page(self):
        c = FakeConsole(answers=[("Sub-domain", "security.example.com"), ("Another trusted", ""), ("Choose 1 or 2", "2")])
        self.assertEqual(self.gather(c)["access"], "login")

    def test_a_bad_domain_is_asked_again_a_missing_one_stops_a_given_one(self):
        self.assertIsNone(installer.netinfo.clean_domain("https://nope"))
        self.assertIsNone(self.gather(FakeConsole(), domain="not a domain"), "a bad answer given as an option stops")
        c = FakeConsole(answers=[("Sub-domain", "https://nope")])
        self.assertIsNone(self.gather(c), "a person who keeps typing nonsense is not asked forever")
        self.assertIn("plain host name", c.text)

    def test_a_name_that_does_not_exist_yet_explains_what_to_do(self):
        self.dns.return_value = {"exists": False, "ips": [], "cloudflare": False, "points_here": False}
        c = FakeConsole()
        self.assertIsNone(self.gather(c, domain="security.example.com"))
        self.assertIn("A record", c.text)

    def test_a_name_pointing_elsewhere_needs_a_yes(self):
        self.dns.return_value = {"exists": True, "ips": ["203.0.113.99"], "cloudflare": False, "points_here": False}
        c = FakeConsole(yeses={"Continue anyway": False})
        self.assertIsNone(self.gather(c, domain="security.example.com"))
        self.assertIn("203.0.113.99", c.text)

    def test_a_name_with_a_certificate_already_does_not_need_dns(self):
        self.dns.return_value = {"exists": False, "ips": [], "cloudflare": False, "points_here": False}
        live = config.P.letsencrypt_live + "/security.example.com"
        self.write(live + "/fullchain.pem", "x")
        self.write(live + "/privkey.pem", "x")
        c = FakeConsole(answers=[("Another trusted", "")])
        self.assertIsNotNone(self.gather(c, domain="security.example.com"))

    def test_behind_cloudflare_the_default_port_is_one_cloudflare_passes(self):
        self.dns.return_value = dict(GOOD_DNS, cloudflare=True)
        c = FakeConsole(answers=[("Another trusted", "")])
        cfg = self.gather(c, domain="security.example.com")
        self.assertEqual(cfg["port"], 8443)
        self.assertIn("orange cloud", c.text)

    def test_an_unusable_port_is_explained_and_asked_again(self):
        c = FakeConsole(answers=[("Another trusted", "")])
        ports = iter(["8090"])
        plain = c.ask
        c.ask = lambda prompt, default="": next(ports, default) if "Port" in prompt else plain(prompt, default)
        cfg = self.gather(c, domain="security.example.com")
        self.assertIn("already used", c.text)
        self.assertEqual(cfg["port"], 9443)

    def test_a_weak_password_is_refused_with_the_reason(self):
        c = FakeConsole(answers=[("Another trusted", "")], secrets=["short", PASSWORD, PASSWORD])
        cfg = self.gather(c, domain="security.example.com")
        self.assertEqual(cfg["password"], PASSWORD)
        self.assertIn("characters", c.text)

    def test_two_different_passwords_are_not_accepted(self):
        c = FakeConsole(answers=[("Another trusted", "")], secrets=[PASSWORD, "something else entirely", PASSWORD, PASSWORD])
        self.assertEqual(self.gather(c, domain="security.example.com")["password"], PASSWORD)
        self.assertIn("did not match", c.text)

    def test_a_trusted_address_is_always_required(self):
        os.environ.pop("SSH_CONNECTION")
        c = FakeConsole(answers=[("Another trusted", "")])
        # nothing typed: asks again; it only ends because the scripted person types a real address next time
        answers = iter(["", "45.60.0.55", ""])
        c.ask = lambda prompt, default="": next(answers) if "Another trusted" in prompt else default
        cfg = self.gather(c, domain="security.example.com")
        self.assertIn("At least one trusted address", c.text)
        self.assertEqual(cfg["trusted"], ["45.60.0.55"])

    def test_a_private_address_is_refused(self):
        os.environ.pop("SSH_CONNECTION")
        answers = iter(["192.168.1.5", "45.60.0.55", ""])
        c = FakeConsole()
        c.ask = lambda prompt, default="": next(answers) if "Another trusted" in prompt else default
        cfg = self.gather(c, domain="security.example.com")
        self.assertIn("private address", c.text)
        self.assertEqual(cfg["trusted"], ["45.60.0.55"])

    def test_saying_no_at_the_end_installs_nothing(self):
        c = FakeConsole(answers=[("Another trusted", "")], yeses={"Go ahead": False})
        self.assertIsNone(self.gather(c, domain="security.example.com"))

    def test_a_problem_found_before_anything_stops_everything(self):
        installer.preflight.return_value = [("stop", "No LiteSpeed web server was found.")]
        c = FakeConsole()
        self.assertIsNone(self.gather(c))
        self.assertIn("No LiteSpeed", c.text)

    def test_without_questions_everything_must_be_given(self):
        # the real console, not the scripted one: with --yes the password can only come from the environment
        given = dict(domain="security.example.com", email="me@example.com", username="owner",
                     trusted_ip=["45.60.0.55"], port=9443)
        with mock.patch.dict(os.environ, {"CPSEC_PASSWORD": PASSWORD}), mock.patch("builtins.print"):
            cfg = installer.gather(installer.Console(assume_yes=True), args(**given))
        self.assertEqual((cfg["username"], cfg["trusted"], cfg["access"]), ("owner", ["45.60.0.55"], "trusted"))
        self.assertEqual(cfg["password"], PASSWORD)
        os.environ.pop("CPSEC_PASSWORD", None)
        with mock.patch("builtins.print"):
            self.assertIsNone(installer.gather(installer.Console(assume_yes=True), args(**given)), "no password given")


class PortRules(EnvTestCase):
    def test_which_ports_are_fine(self):
        with mock.patch("cpsec.installer.port_in_use", return_value=False):
            self.assertIsNone(installer.port_problem(9443))
            self.assertIn("1024", installer.port_problem(80))
            self.assertIn("already used", installer.port_problem(8090))
            self.assertIn("Cloudflare", installer.port_problem(9443, cloudflare=True))
            self.assertIsNone(installer.port_problem(8443, cloudflare=True))
        with mock.patch("cpsec.installer.port_in_use", return_value=True):
            self.assertIn("listening", installer.port_problem(9443))


class Preflight(EnvTestCase):
    def test_no_web_server_stops_it(self):
        levels = [l for l, _ in installer.preflight()]
        self.assertIn("stop", levels)

    def test_a_cyberpanel_server_passes(self):
        self.write(config.P.lsws_bin_ols, "")
        os.makedirs(config.P.at("/usr/local/CyberCP"))
        levels = [l for l, _ in installer.preflight()]
        self.assertNotIn("stop", levels)
        self.assertNotIn("warn", levels)


class Doing(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.cfg = {"domain": "security.example.com", "port": 9443, "email": "me@example.com", "username": "owner",
                    "password": PASSWORD, "trusted": ["45.60.0.10"], "access": "trusted", "protections": False,
                    "certificate": True}
        self.source = os.path.join(self.root, "source")
        self.write(os.path.join(self.source, "cpsec", "__init__.py"), "")
        self.write(os.path.join(self.source, "cpsec", "feed.py"), "x")
        self.write(os.path.join(self.source, "VERSION"), "9.9.9\n")
        self.cert = self.patch("cpsec.installer.tls.get_certificate", return_value=Result(True, "A certificate was issued for security.example.com."))
        self.patch("cpsec.installer.wait_for_panel", return_value=True)
        self.patch("cpsec.provision.shutil.which", return_value="/usr/sbin/nft")
        self.patch("cpsec.provision.time.sleep")
        self.patch("cpsec.blocker.installed", return_value=False)

    def test_a_full_install_leaves_a_working_panel_and_a_locked_server(self):
        c = FakeConsole()
        self.assertEqual(installer.execute(c, self.cfg, self.source), 0, c.text)
        s = settings.load()
        self.assertEqual((s["domain"], s["port"], s["access"]), ("security.example.com", 9443, "trusted"))
        user = settings.get_user()
        self.assertEqual(user["name"], "owner")
        self.assertTrue(auth.verify_password(PASSWORD, user["password_hash"]))
        self.assertNotIn(PASSWORD, util.read_text(config.P.panel_settings))
        self.assertEqual([a["address"] for a in access.list_admin()], ["45.60.0.10"])
        lock = util.read_text(config.P.nft_file)
        self.assertIn("9443", lock, "the panel port is behind the admin lock in trusted mode")
        self.assertTrue(os.path.exists(config.P.systemd_dir + "/" + provision.SERVICE_PANEL))
        self.assertTrue(os.path.exists(config.P.install_dir + "/cpsec/feed.py"))
        self.assertEqual(util.read_text(config.P.install_dir + "/VERSION"), "9.9.9\n")
        launcher = util.read_text(config.P.at(installer.LAUNCHER))
        self.assertIn("-m cpsec", launcher)
        self.assertIn("https://security.example.com:9443", c.text)

    def test_the_open_login_mode_leaves_the_panel_port_out_of_the_lock(self):
        self.cfg["access"] = "login"
        installer.execute(FakeConsole(), self.cfg, self.source)
        self.assertNotIn("9443", util.read_text(config.P.nft_file))

    def test_a_certificate_that_cannot_be_had_changes_nothing_else(self):
        self.cert.return_value = Result(False, "DNS does not point here.", "issue_failed")
        c = FakeConsole()
        self.assertEqual(installer.execute(c, self.cfg, self.source), 1)
        self.assertIsNone(settings.get_user())
        self.assertFalse(os.path.exists(config.P.systemd_dir + "/" + provision.SERVICE_PANEL))
        self.assertIn("Nothing else was changed", c.text)

    def test_the_protections_run_when_asked_and_a_failure_is_reported_not_fatal(self):
        self.cfg["protections"] = True
        self.patch("cpsec.provision.fetch_crs", side_effect=ValueError("no network"))
        self.patch("cpsec.provision.install_packages", return_value=Result(False, "apt is busy", "install_failed"))
        c = FakeConsole()
        code = installer.execute(c, self.cfg, self.source)
        self.assertEqual(code, 0, "the panel is still installed so the owner can look and retry")
        self.assertIn("PROBLEM", c.text)
        self.assertIn("Setup page", c.text)

    def test_running_from_the_installed_place_copies_nothing(self):
        res = installer.deploy_code(config.P.install_dir)
        self.assertIn("already", res.message)

    def test_an_older_security_command_is_kept_as_a_backup(self):
        path = config.P.at(installer.LAUNCHER)
        self.write(path, "#!/usr/bin/python3\nprint('old menu')\n")
        installer.write_launcher()
        self.assertTrue(os.path.exists(path + ".before-cp-security"))
        self.assertIn("-m cpsec", util.read_text(path))
        installer.write_launcher()
        self.assertIn("old menu", util.read_text(path + ".before-cp-security"), "second run keeps the first backup")


class Uninstalling(EnvTestCase):
    def setUp(self):
        super().setUp()
        for unit in (provision.SERVICE_PANEL, provision.SERVICE_FEED, provision.SERVICE_LOCK):
            self.write(config.P.systemd_dir + "/" + unit, "[Unit]\n")
        self.write(config.P.f2b_jails, "x")
        self.write(config.P.f2b_filter_dir + "/cps-wp-login.conf", "x")
        self.write(config.P.f2b_filter_dir + "/someone-elses.conf", "keep")
        self.write(config.P.conf_dir + "/admin-access.list", "45.60.0.10 | Home\n")
        self.write(config.P.install_dir + "/cpsec/__init__.py", "")

    def run_it(self, yeses, purge=False):
        c = FakeConsole(yeses=yeses)
        self.assertEqual(installer.uninstall(c, purge=purge), 0)
        return c

    def test_by_default_only_the_panel_goes(self):
        self.run_it({"Continue?": True, "Also remove the attack": False, "Also remove the admin lock": False})
        self.assertFalse(os.path.exists(config.P.systemd_dir + "/" + provision.SERVICE_PANEL))
        self.assertTrue(os.path.exists(config.P.systemd_dir + "/" + provision.SERVICE_LOCK))
        self.assertTrue(os.path.exists(config.P.f2b_jails))
        self.assertTrue(os.path.exists(config.P.conf_dir + "/admin-access.list"))

    def test_nothing_happens_without_a_yes(self):
        c = FakeConsole(yeses={"Continue?": False})
        self.assertEqual(installer.uninstall(c), 1)
        self.assertTrue(os.path.exists(config.P.systemd_dir + "/" + provision.SERVICE_PANEL))

    def test_the_protections_go_only_when_asked_and_other_peoples_files_stay(self):
        self.run_it({"Continue?": True, "Also remove the attack": True, "Also remove the admin lock": False})
        self.assertFalse(os.path.exists(config.P.f2b_jails))
        self.assertFalse(os.path.exists(config.P.f2b_filter_dir + "/cps-wp-login.conf"))
        self.assertTrue(os.path.exists(config.P.f2b_filter_dir + "/someone-elses.conf"))
        self.assertTrue(os.path.exists(config.P.systemd_dir + "/" + provision.SERVICE_LOCK), "the lock has its own question")

    def test_the_lock_is_removed_only_on_its_own_yes(self):
        self.run_it({"Continue?": True, "Also remove the attack": False, "Also remove the admin lock": True})
        self.assertFalse(os.path.exists(config.P.systemd_dir + "/" + provision.SERVICE_LOCK))
        self.assertTrue(self.fake.called("nft", "delete", "table", "inet", access.TABLE))

    def test_purge_deletes_settings_and_program(self):
        self.run_it({"Continue?": True, "Also remove the attack": False, "Also remove the admin lock": False}, purge=True)
        self.assertFalse(os.path.exists(config.P.conf_dir))
        self.assertFalse(os.path.exists(config.P.install_dir))


class Certificates(EnvTestCase):
    def test_a_renewed_certificate_is_loaded_without_restarting(self):
        live = config.P.letsencrypt_live + "/security.example.com"
        self.write(live + "/fullchain.pem", "old")
        self.write(live + "/privkey.pem", "key")
        server = mock.Mock()
        stop = threading.Event()
        calls = []

        def fake_sleep(seconds):
            calls.append(seconds)
            if len(calls) == 1:
                os.utime(live + "/fullchain.pem", (1_900_000_000, 1_900_000_000))    # CyberPanel renewed it
            else:
                stop.set()

        with mock.patch("cpsec.panel.cli.time.sleep", fake_sleep):
            panel_cli.watch_certificate(server, "security.example.com", "c", "k", every=1, stop=stop)
        server.reload_certificate.assert_called_once_with(live + "/fullchain.pem", live + "/privkey.pem")

    def test_an_unchanged_certificate_is_left_alone(self):
        live = config.P.letsencrypt_live + "/security.example.com"
        self.write(live + "/fullchain.pem", "old")
        self.write(live + "/privkey.pem", "key")
        server = mock.Mock()
        stop = threading.Event()
        with mock.patch("cpsec.panel.cli.time.sleep", lambda s: stop.set()):
            panel_cli.watch_certificate(server, "security.example.com", "c", "k", every=1, stop=stop)
        self.assertFalse(server.reload_certificate.called)

    def test_certificate_discovery_prefers_cyberpanels_place(self):
        live = config.P.letsencrypt_live + "/security.example.com"
        self.write(live + "/fullchain.pem", "a")
        self.write(live + "/privkey.pem", "b")
        self.write(config.P.tls_dir + "/fullchain.pem", "c")
        self.write(config.P.tls_dir + "/privkey.pem", "d")
        self.assertEqual(tls.find("security.example.com"), (live + "/fullchain.pem", live + "/privkey.pem"))
        self.assertIsNotNone(tls.find("other.example.com"), "a certificate placed by hand is used for any name")
        os.remove(config.P.tls_dir + "/fullchain.pem")
        self.assertIsNone(tls.find("other.example.com"))

    def test_asking_cyberpanel_for_a_certificate(self):
        self.patch("cpsec.tls.cyberpanel_available", return_value=True)
        live = config.P.letsencrypt_live + "/security.example.com"

        def issue(cmd):
            self.write(live + "/fullchain.pem", "a")
            self.write(live + "/privkey.pem", "b")
            return 0, '{"success": 1}'
        self.fake.table.append((["cyberpanel", "issueSSL"], issue))
        r = tls.get_certificate("security.example.com", "me@example.com")
        self.assertTrue(r.ok, r.message)
        self.assertTrue(self.fake.called("cyberpanel", "createWebsite", "--package", "Default", "--owner", "admin",
                                         "--domainName", "security.example.com", "--email", "me@example.com",
                                         "--php", "8.1"))

    def test_an_existing_website_is_not_created_twice_and_a_refused_certificate_is_explained(self):
        self.patch("cpsec.tls.cyberpanel_available", return_value=True)
        os.makedirs(config.P.home_dir + "/security.example.com")
        self.fake.table.append((["cyberpanel", "issueSSL"], (1, "Challenge failed\n")))
        r = tls.get_certificate("security.example.com", "me@example.com")
        self.assertEqual((r.ok, r.code), (False, "issue_failed"))
        self.assertIn("orange-cloud", r.message)
        self.assertEqual(self.fake.called("cyberpanel", "createWebsite"), [])

    def test_without_cyberpanel_the_message_says_what_to_do(self):
        self.patch("cpsec.tls.cyberpanel_available", return_value=False)
        self.assertEqual(tls.get_certificate("security.example.com", "me@example.com").code, "no_cyberpanel")

    def test_the_panel_port_is_opened_in_the_firewall_that_is_on(self):
        self.fake.table.append((["systemctl", "is-active", "firewalld"], (0, "active\n")))
        r = tls.open_port(9443)
        self.assertTrue(r.ok and r.code == "firewalld")
        self.assertTrue(self.fake.called("firewall-cmd", "--permanent", "--add-port=9443/tcp"))
        self.fake.table.clear()
        self.fake.table.append((["ufw", "status"], (0, "Status: active\n")))
        self.assertEqual(tls.open_port(9443).code, "ufw")
        self.fake.table.clear()
        self.assertEqual(tls.open_port(9443).code, "none")


class CommandLine(EnvTestCase):
    def test_advice_prints_the_findings(self):
        with mock.patch("builtins.print") as shown:
            self.assertEqual(cli.main(["advice"]), 0)
        text = "\n".join(str(c.args[0]) for c in shown.call_args_list if c.args)
        self.assertIn("ADVICE", text)

    def test_setup_prints_the_plan_and_asks_before_doing_anything(self):
        self.patch("cpsec.blocker.installed", return_value=False)
        with mock.patch("builtins.print") as shown, mock.patch("cpsec.menu.ask", return_value="no"):
            self.assertEqual(cli.main(["setup"]), 1)
        text = "\n".join(str(c.args[0]) for c in shown.call_args_list if c.args)
        self.assertIn("Install the attack blocker", text)
        self.assertEqual([c for c in self.fake.calls if c[:2] == ["systemctl", "enable"]], [])

    def test_unknown_commands_show_the_usage(self):
        with mock.patch("builtins.print") as shown:
            self.assertEqual(cli.main(["nonsense"]), 1)
        self.assertIn("security install", str(shown.call_args[0][0]))
