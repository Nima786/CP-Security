import json
import os

from cpsec import cli, config, provision, serverfw, settings, util
from tests.helpers import EnvTestCase

TCP = (
    'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("litespeed",pid=900,fd=21))\n'
    'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("litespeed",pid=900,fd=22))\n'
    'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=800,fd=3))\n'
    'LISTEN 0 511 *:5000 *:* users:(("node",pid=702,fd=19))\n'
    'LISTEN 0 80 127.0.0.1:3306 0.0.0.0:* users:(("mariadbd",pid=700,fd=22))\n'
    'LISTEN 0 511 0.0.0.0:8090 0.0.0.0:* users:(("lscpd",pid=5,fd=3))\n'
)
UDP = (
    'UNCONN 0 0 0.0.0.0:443 0.0.0.0:* users:(("litespeed",pid=900,fd=10))\n'
    'UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("pdns_server",pid=386,fd=5))\n'
    'UNCONN 0 0 0.0.0.0:59017 0.0.0.0:* users:(("lscpd",pid=996,fd=13))\n'
    'UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n'
)
IPTABLES = (
    "-P INPUT ACCEPT\n"
    '-A INPUT -s 198.51.100.46/32 -p tcp -m tcp --dport 2053 -m comment --comment "tunnel:test" -j ACCEPT\n'
    '-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 2053 -m comment --comment "tunnel:test" -j ACCEPT\n'
    '-A INPUT -p tcp -m tcp --dport 2053 -m comment --comment "tunnel:test" -j DROP\n'
    "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
)
CYBERPANEL_ROWS = (
    "1\tpanel\ttcp\t0.0.0.0/0\t8090\n"
    "2\thttp\ttcp\t0.0.0.0/0\t80\n"
    "3\thttps\ttcp\t0.0.0.0/0\t443\n"
    "4\tdns\tudp\t0.0.0.0/0\t53\n"
    "5\tftptls\ttcp\t0.0.0.0/0\t40110-40210\n"
    "6\tSSHCustom\ttcp\t0.0.0.0/0\t22\n"
    "7\tbroken\ttcp\t0.0.0.0/0\t99999\n"
)


def rows_of(text):
    return "\n".join(line.split("\t", 1)[1] for line in text.strip().splitlines()) + "\n"


class FwCase(EnvTestCase):
    def setUp(self):
        super().setUp()
        self.loaded = False
        self.clock = [1_000_000.0]
        self.patch("cpsec.serverfw._now", side_effect=lambda: self.clock[0])
        os.makedirs(config.P.at("/usr/local/CyberCP"))

        def nft_list(cmd):
            return (0, "table inet cps_fw { chain input { counter drop } }") if self.loaded else (1, "No such file or directory")

        def nft_load(cmd):
            self.loaded = True
            return 0, ""

        def nft_delete(cmd):
            self.loaded = False
            return 0, ""
        t = self.fake.table
        t += [
            (["nft", "list", "table", "inet", "cps_fw"], nft_list),
            (["nft", "delete", "table", "inet", "cps_fw"], nft_delete),
            (["nft", "-f"], nft_load),
            (["systemctl", "status", "firewalld"], (4, "Unit firewalld.service could not be found.\n")),
            (["systemctl", "is-active", "firewalld"], (4, "inactive\n")),
            (["systemctl", "cat", "firewalld"], (1, "No files found for firewalld.service.")),
            (["ufw", "status"], (0, "Status: inactive\n")),
            (["sshd", "-T"], (0, "port 22\nport 22\n")),
            (["ss", "-H", "-ltnp"], (0, TCP)),
            (["ss", "-H", "-lunp"], (0, UDP)),
            (["iptables", "-S", "INPUT"], (0, IPTABLES)),
            (["ip6tables", "-S", "INPUT"], (0, "-P INPUT ACCEPT\n")),
            (["mysql"], (0, rows_of(CYBERPANEL_ROWS))),
        ]
        self.cp_rows = CYBERPANEL_ROWS

    def rule(self, port, proto="tcp", address="", name="x"):
        res = serverfw.add_rule(name, proto, address, port)
        self.assertTrue(res.ok, res.message)

    def ports_on_list(self):
        return [(r["proto"], r["port"]) for r in serverfw.load()["rules"]]


class OneRule(FwCase):
    def test_a_good_rule_is_cleaned_up(self):
        clean, err = serverfw.check_rule("  Web  <script> server! ", "TCP", "0.0.0.0/0", " 4445 ")
        self.assertIsNone(err)
        self.assertEqual(clean, {"name": "Web script server", "proto": "tcp", "address": "", "port": "4445"})

    def test_addresses_ranges_and_single_hosts(self):
        self.assertEqual(serverfw.check_rule("a", "tcp", "203.0.113.5/32", "80")[0]["address"], "203.0.113.5")
        self.assertEqual(serverfw.check_rule("a", "tcp", "203.0.113.0/24", "80")[0]["address"], "203.0.113.0/24")
        self.assertEqual(serverfw.check_rule("a", "udp", "2001:db8::/32", "53")[0]["address"], "2001:db8::/32")
        self.assertEqual(serverfw.check_rule("a", "tcp", "::/0", "80")[0]["address"], "")
        self.assertEqual(serverfw.check_rule("a", "tcp", "", "40110-40210")[0]["port"], "40110-40210")
        self.assertEqual(serverfw.check_rule("a", "tcp", "", "80-80")[0]["port"], "80")

    def test_nonsense_is_refused_with_a_reason(self):
        for args in (("a", "icmp", "", "80"), ("a", "tcp", "not an address", "80"), ("a", "tcp", "", "0"),
                     ("a", "tcp", "", "70000"), ("a", "tcp", "", "90-80"), ("a", "tcp", "", "abc"), ("a", "tcp", "", ""),
                     ("a", "tcp", "", "80;drop"), ("a", "tcp", "", "80 90")):
            clean, err = serverfw.check_rule(*args)
            self.assertIsNone(clean, args)
            self.assertTrue(err, args)


class NftText(FwCase):
    def test_the_list_becomes_accept_rules_and_everything_else_is_dropped(self):
        rules = [dict(serverfw.check_rule("Web", "tcp", "", "80")[0], id=1),
                 dict(serverfw.check_rule("Tunnel", "tcp", "198.51.100.46", "2053")[0], id=2),
                 dict(serverfw.check_rule("Six", "udp", "2001:db8::/32", "53")[0], id=3),
                 dict(serverfw.check_rule("Passive FTP", "tcp", "", "40110-40210")[0], id=4)]
        text = serverfw.build_nft(rules, [22, 8090])
        for line in ('tcp dport 80 accept comment "Web"', 'ip saddr 198.51.100.46 tcp dport 2053 accept comment "Tunnel"',
                     'ip6 saddr 2001:db8::/32 udp dport 53 accept comment "Six"', "tcp dport 40110-40210 accept",
                     "tcp dport { 22, 8090 } accept", "ct state established,related accept", 'iifname "lo" accept',
                     "meta l4proto icmp accept", "meta l4proto ipv6-icmp accept", "udp dport 546 accept"):
            self.assertIn(line, text)
        self.assertTrue(text.rstrip().endswith("}"))
        self.assertLess(text.index("tcp dport 80"), text.index("counter drop"), "the final drop comes after every allow")
        self.assertIn("flush table inet cps_fw", text)

    def test_the_test_mode_only_judges_one_stand_in_address_and_never_trusts_the_loopback(self):
        text = serverfw.build_nft([], [22], table="cps_fw_test", test_source="127.0.0.2")
        self.assertIn("ip saddr != 127.0.0.2 accept", text)
        self.assertNotIn('iifname "lo"', text)
        self.assertIn("table inet cps_fw_test", text)

    def test_a_name_cannot_break_out_of_its_comment(self):
        clean, _ = serverfw.check_rule('x" accept; drop #', "tcp", "", "80")
        self.assertNotIn('"', clean["name"])
        self.assertNotIn(";", clean["name"])


class TheTruth(FwCase):
    def test_cyberpanels_on_light_without_firewalld_is_called_out(self):
        t = serverfw.truth()
        self.assertTrue(t["cyberpanel"]["page_says_on"])
        self.assertFalse(t["cyberpanel"]["firewalld_running"])
        self.assertEqual(t["cyberpanel"]["level"], "bad")
        self.assertIn("not installed", t["cyberpanel"]["text"])
        self.assertFalse(t["protected"])
        self.assertEqual(t["verdict"]["level"], "bad")
        self.assertEqual(t["cyberpanel"]["rules_listed"], 7)

    def test_firewalld_stopped_is_reported_as_off_and_true(self):
        self.fake.table.insert(0, (["systemctl", "status", "firewalld"], (3, "Active: inactive (dead)\n")))
        self.fake.table.insert(0, (["systemctl", "cat", "firewalld"], (0, "[Unit]")))
        t = serverfw.truth()
        self.assertFalse(t["cyberpanel"]["page_says_on"])
        self.assertEqual(t["cyberpanel"]["level"], "info")

    def test_a_running_firewalld_means_cyberpanels_page_is_telling_the_truth(self):
        self.fake.table.insert(0, (["systemctl", "status", "firewalld"], (0, "Active: active (running)\n")))
        self.fake.table.insert(0, (["systemctl", "is-active", "firewalld"], (0, "active\n")))
        t = serverfw.truth()
        self.assertEqual(t["cyberpanel"]["level"], "ok")
        self.assertTrue(t["protected"])
        self.assertIn("firewalld", t["others"])

    def test_ufw_or_our_own_firewall_count_as_protection(self):
        self.fake.table.insert(0, (["ufw", "status"], (0, "Status: active\n")))
        self.assertEqual(serverfw.truth()["others"], ["ufw"])
        self.fake.table.pop(0)
        self.loaded = True
        t = serverfw.truth()
        self.assertTrue(t["ours"]["loaded"])
        self.assertEqual(t["verdict"]["level"], "ok")

    def test_a_server_without_cyberpanel_is_not_accused(self):
        os.rmdir(config.P.at("/usr/local/CyberCP"))
        t = serverfw.truth()
        self.assertEqual(t["cyberpanel"]["level"], "info")
        self.assertIsNone(t["cyberpanel"]["rules_listed"])


class Copying(FwCase):
    def test_cyberpanels_list_is_read_and_copied_without_the_always_open_ports_or_junk(self):
        res = serverfw.import_cyberpanel()
        self.assertTrue(res.ok, res.message)
        self.assertEqual(sorted(self.ports_on_list()), [("tcp", "40110-40210"), ("tcp", "443"), ("tcp", "80"), ("udp", "53")])
        self.assertIn("Copied 4 rules", res.message)
        self.assertEqual([r["source"] for r in serverfw.load()["rules"]], ["cyberpanel"] * 4)
        again = serverfw.import_cyberpanel()
        self.assertIn("Copied 0 rules", again.message)
        self.assertEqual(len(serverfw.load()["rules"]), 4)

    def test_an_unreadable_list_is_reported(self):
        self.fake.table.insert(0, (["mysql"], (1, "ERROR 1045")))
        self.assertEqual(serverfw.import_cyberpanel().code, "unreadable")

    def test_things_in_use_and_things_other_programs_allow_are_suggested(self):
        found = {s["key"]: s for s in serverfw.suggestions()}
        self.assertIn("tcp::80", found)
        self.assertIn("tcp::5000", found)
        self.assertEqual(found["tcp::5000"]["why"], "In use right now by node")
        self.assertNotIn("tcp::22", found, "the server login is always open")
        self.assertNotIn("tcp::8090", found, "the admin pages are always open")
        self.assertNotIn("tcp::3306", found, "a database only this server can reach needs nothing")
        self.assertIn("udp::443", found)
        self.assertIn("udp::53", found)
        self.assertNotIn("udp::59017", found, "a random high UDP port is not a service")
        self.assertIn("tcp:198.51.100.46:2053", found)
        self.assertEqual(found["tcp:198.51.100.46:2053"]["name"], "tunnel test")
        self.assertNotIn("tcp:127.0.0.1:2053", found)

    def test_a_port_on_the_list_is_no_longer_suggested(self):
        self.rule("5000")
        self.assertNotIn("tcp::5000", [s["key"] for s in serverfw.suggestions()])

    def test_all_suggestions_can_be_added_in_one_go(self):
        res = serverfw.add_suggested()
        self.assertTrue(res.ok)
        have = serverfw.load()["rules"]
        self.assertTrue(any(r["port"] == "5000" and r["source"] == "in use" for r in have))
        self.assertTrue(any(r["port"] == "2053" and r["source"] == "other firewall" for r in have))
        self.assertEqual(serverfw.suggestions(), [])
        self.assertEqual(serverfw.add_suggested().code, "none")


class EditingTheList(FwCase):
    def test_adding_and_removing_while_the_firewall_is_off_only_saves(self):
        res = serverfw.add_rule("Tunnel", "tcp", "", "4445")
        self.assertIn("firewall is off", res.message)
        self.assertFalse(self.fake.called("nft", "-f"))
        rid = serverfw.load()["rules"][0]["id"]
        self.assertTrue(serverfw.remove_rule(rid).ok)
        self.assertEqual(serverfw.load()["rules"], [])

    def test_the_same_rule_twice_is_refused(self):
        self.rule("4445")
        self.assertEqual(serverfw.add_rule("again", "tcp", "", "4445").code, "exists")
        self.assertTrue(serverfw.add_rule("udp one", "udp", "", "4445").ok, "a different protocol is a different rule")

    def test_while_the_firewall_is_on_a_change_is_loaded_at_once_and_undone_if_it_does_not_load(self):
        self.rule("80")
        serverfw.turn_on(add_in_use=False)
        serverfw.confirm()
        self.fake.calls.clear()
        self.assertTrue(serverfw.add_rule("Tunnel", "tcp", "", "4445").ok)
        self.assertIn("tcp dport 4445 accept", self.read(config.P.fw_nft))
        self.assertTrue(self.fake.called("nft", "-f", config.P.fw_nft))
        self.fake.table.insert(0, (["nft", "-c"], (1, "syntax error")))
        res = serverfw.add_rule("Bad", "tcp", "", "5555")
        self.assertFalse(res.ok)
        self.assertIn("Nothing was changed", res.message)
        self.assertNotIn("5555", [r["port"] for r in serverfw.load()["rules"]])

    def test_removing_the_rule_of_something_in_use_asks_first(self):
        self.rule("80")
        serverfw.turn_on(add_in_use=False)
        serverfw.confirm()
        rid = next(r["id"] for r in serverfw.load()["rules"] if r["port"] == "80")
        res = serverfw.remove_rule(rid)
        self.assertEqual(res.code, "needs_confirm")
        self.assertIn("litespeed", res.message)
        self.assertEqual(len(serverfw.load()["rules"]), 1)
        self.assertTrue(serverfw.remove_rule(rid, confirmed=True).ok)
        self.assertNotIn("tcp dport 80 accept", self.read(config.P.fw_nft))

    def test_a_missing_rule_and_a_full_list(self):
        self.assertEqual(serverfw.remove_rule(999).code, "missing")
        cfg = serverfw.load()
        for i in range(serverfw.MAX_RULES):
            serverfw._add(cfg, {"name": "r", "proto": "tcp", "address": "", "port": str(1000 + i)}, "you")
        serverfw.save(cfg)
        self.assertEqual(serverfw.add_rule("one more", "tcp", "", "65000").code, "full")


class SwitchingItOn(FwCase):
    def test_it_needs_a_yes(self):
        self.assertEqual(serverfw.power("on").code, "needs_confirm")
        self.assertFalse(self.loaded)

    def test_switching_on_loads_the_rules_starts_the_undo_timer_and_waits_for_keep(self):
        self.rule("80")
        res = serverfw.power("on", add_in_use=True, confirmed=True)
        self.assertEqual((res.ok, res.code), (True, "pending"))
        self.assertTrue(self.loaded)
        timer = self.fake.called("systemd-run")[0]
        self.assertIn("--on-active=120", timer)
        self.assertEqual(timer[-4:], ["-m", "cpsec", "serverfw", "revert"])
        self.assertTrue(any(a.startswith("--setenv=PYTHONPATH=") for a in timer))
        text = self.read(config.P.fw_nft)
        self.assertIn("tcp dport 5000 accept", text, "what is in use is allowed so nothing stops working")
        self.assertIn("tcp dport { 22, 7080, 8090, 8888 } accept", text)
        cfg = serverfw.load()
        self.assertTrue(cfg["enabled"])
        self.assertEqual(cfg["pending"]["previous"]["enabled"], False)
        self.assertEqual([r["port"] for r in cfg["pending"]["previous"]["rules"]], ["80"], "what to go back to")
        self.assertFalse(self.fake.called("systemctl", "enable"), "not permanent before 'Keep it'")
        self.assertEqual(serverfw.state()["pending"]["seconds_left"], 120)

    def test_without_adding_what_is_in_use_the_list_stays_as_it_is(self):
        self.rule("80")
        serverfw.turn_on(add_in_use=False)
        self.assertNotIn("5000", self.read(config.P.fw_nft))

    def test_it_is_not_switched_on_if_the_undo_net_cannot_be_set_up(self):
        self.fake.table.insert(0, (["systemd-run"], (1, "no systemd")))
        res = serverfw.turn_on()
        self.assertEqual(res.code, "no_timer")
        self.assertFalse(self.loaded)
        self.assertFalse(serverfw.load()["enabled"])
        self.assertIsNone(serverfw.load()["pending"])

    def test_it_is_not_switched_on_if_the_firewall_program_rejects_the_list(self):
        self.fake.table.insert(0, (["nft", "-c"], (1, "syntax error")))
        res = serverfw.turn_on()
        self.assertFalse(res.ok)
        self.assertFalse(self.loaded)
        self.assertFalse(serverfw.load()["enabled"])
        self.assertFalse(self.fake.called("systemd-run"))

    def test_a_second_switch_on_while_waiting_is_refused(self):
        serverfw.turn_on()
        self.assertEqual(serverfw.turn_on().code, "pending")

    def test_keep_makes_it_permanent_and_stops_the_timer(self):
        serverfw.turn_on()
        res = serverfw.confirm()
        self.assertTrue(res.ok, res.message)
        self.assertIsNone(serverfw.load()["pending"])
        self.assertTrue(self.fake.called("systemctl", "stop", "cps-fw-revert.timer"))
        self.assertTrue(self.fake.called("systemctl", "enable"))
        self.assertTrue(os.path.exists(config.P.systemd_dir + "/cps-firewall.service"))
        self.assertIn("table", self.read(config.P.systemd_dir + "/cps-firewall.service"))
        self.assertEqual(serverfw.confirm().code, "none")

    def test_undo_returns_to_the_state_before_and_the_rules_before(self):
        self.rule("4445")
        before = serverfw.load()["rules"]
        serverfw.turn_on(add_in_use=True)
        self.assertGreater(len(serverfw.load()["rules"]), len(before))
        res = serverfw.revert()
        self.assertTrue(res.ok, res.message)
        cfg = serverfw.load()
        self.assertEqual((cfg["enabled"], cfg["pending"], cfg["rules"]), (False, None, before))
        self.assertFalse(self.loaded)
        self.assertEqual(serverfw.revert().message, "Nothing to undo.")

    def test_undo_of_a_reload_that_was_already_on_goes_back_to_the_earlier_list(self):
        self.rule("80")
        serverfw.turn_on(add_in_use=False)
        serverfw.confirm()
        cfg = serverfw.load()
        cfg["pending"] = {"until": self.clock[0] + 60, "action": "on", "previous": {"enabled": True, "rules": cfg["rules"][:1]}}
        cfg["rules"].append(dict(serverfw.check_rule("late", "tcp", "", "6000")[0], id=99, source="you"))
        serverfw.save(cfg)
        self.assertTrue(serverfw.revert().ok)
        self.assertTrue(serverfw.load()["enabled"])
        self.assertNotIn("6000", self.read(config.P.fw_nft))
        self.assertTrue(self.loaded)

    def test_if_the_timer_never_fires_the_page_undoes_it_by_itself(self):
        serverfw.turn_on()
        self.clock[0] += 200
        st = serverfw.state()
        self.assertIsNone(st["pending"])
        self.assertFalse(st["enabled"])
        self.assertFalse(self.loaded)

    def test_switching_off_removes_the_table_and_the_boot_start(self):
        serverfw.turn_on()
        serverfw.confirm()
        res = serverfw.power("off")
        self.assertTrue(res.ok)
        self.assertFalse(self.loaded)
        self.assertFalse(serverfw.load()["enabled"])
        self.assertTrue(self.fake.called("systemctl", "disable", "cps-firewall.service"))
        self.assertTrue(self.fake.called("systemctl", "stop", "cps-fw-revert.timer"))

    def test_reload_needs_the_firewall_to_be_on_and_then_loads_the_list_again(self):
        self.assertEqual(serverfw.power("reload").code, "off")
        serverfw.turn_on()
        serverfw.confirm()
        self.fake.calls.clear()
        res = serverfw.power("reload")
        self.assertTrue(res.ok, res.message)
        self.assertTrue(self.fake.called("nft", "-f", config.P.fw_nft))

    def test_reload_puts_the_firewall_back_if_something_else_flushed_it(self):
        serverfw.turn_on()
        serverfw.confirm()
        self.loaded = False                                  # another tool removed our table
        self.assertFalse(serverfw.truth()["ours"]["loaded"])
        self.assertTrue(serverfw.power("reload").ok)
        self.assertTrue(self.loaded)

    def test_an_unknown_action_is_refused(self):
        self.assertEqual(serverfw.power("explode").code, "invalid")

    def test_the_panel_port_and_the_ssh_port_are_always_in_the_always_open_list(self):
        settings.save({"domain": "p.example.com", "port": 9443, "access": "login"})
        self.assertEqual(serverfw.always_open_ports(), [22, 7080, 8090, 8888, 9443])
        self.fake.table.insert(0, (["sshd", "-T"], (0, "port 2222\n")))
        self.assertIn(2222, serverfw.always_open_ports())
        self.assertNotIn(22, serverfw.always_open_ports())

    def test_a_damaged_settings_file_is_read_as_an_empty_list(self):
        self.write(config.P.fw_settings, '{"rules": [{"id": "x", "port": "80"}, 5, {"id": 1, "name": "a", "proto": "tcp", "address": "", "port": "80"}], "pending": 7}')
        cfg = serverfw.load()
        self.assertEqual([r["port"] for r in cfg["rules"]], ["80"])
        self.assertIsNone(cfg["pending"])
        self.assertEqual(cfg["next_id"], 2)


class FromTheCommandLine(FwCase):
    def test_status_and_the_other_words_work_without_crashing(self):
        self.assertEqual(cli._serverfw(["status"]), 0)
        self.assertEqual(cli._serverfw(["on"]), 0)
        self.assertEqual(cli._serverfw(["keep"]), 0)
        self.assertEqual(cli._serverfw(["reload"]), 0)
        self.assertEqual(cli._serverfw(["off"]), 0)
        self.assertEqual(cli._serverfw(["undo"]), 0)
        self.assertEqual(cli._serverfw(["nonsense"]), 1)

    def test_the_unit_file_is_one_that_systemd_can_read(self):
        text = provision.UNIT_FW.format(nft="/usr/sbin/nft", nft_file="/etc/cp-security/firewall.nft", table="cps_fw")
        self.assertIn("ExecStart=/usr/sbin/nft -f /etc/cp-security/firewall.nft", text)
        self.assertIn("ExecStop=-/usr/sbin/nft delete table inet cps_fw", text)
        self.assertIn(util.__name__, "cpsec.util")


REFUSED_TCP = json.dumps({"nftables": [{"metainfo": {"version": "1.0.2"}}, {"set": {"family": "inet", "name": "refused_tcp", "table": "cps_fw",
    "type": "inet_service", "elem": [
        {"elem": {"val": 4445, "timeout": 3600, "expires": 3500, "counter": {"packets": 12, "bytes": 720}}},
        {"elem": {"val": 5000, "timeout": 3600, "expires": 3400, "counter": {"packets": 40, "bytes": 2400}}},
        {"elem": {"val": 23, "timeout": 3600, "expires": 100, "counter": {"packets": 3, "bytes": 180}}}]}}]})
REFUSED_UDP = json.dumps({"nftables": [{"set": {"family": "inet", "name": "refused_udp", "elem": [
    {"elem": {"val": 5060, "counter": {"packets": 7, "bytes": 700}}}, 9]}}]})


class RefusedPorts(FwCase):
    def listen(self):
        self.loaded = True
        self.fake.table.insert(0, (["nft", "-j", "list", "set", "inet", "cps_fw", "refused_tcp"], (0, REFUSED_TCP)))
        self.fake.table.insert(0, (["nft", "-j", "list", "set", "inet", "cps_fw", "refused_udp"], (0, REFUSED_UDP)))

    def test_the_busiest_refused_ports_are_listed_with_the_program_that_uses_them(self):
        self.listen()
        rows = serverfw.refused()
        self.assertEqual([(r["proto"], r["port"], r["packets"]) for r in rows],
                         [("tcp", 5000, 40), ("tcp", 4445, 12), ("udp", 5060, 7), ("tcp", 23, 3), ("udp", 9, 0)],
                         "an element without a counter is still listed, with 0")
        self.assertEqual(rows[0]["programs"], ["node"])
        self.assertEqual(rows[1]["programs"], [])
        self.assertEqual(serverfw.state()["refused"], rows)

    def test_nothing_is_shown_while_the_firewall_is_off_or_cannot_count(self):
        self.assertIsNone(serverfw.refused())
        self.assertIsNone(serverfw.state()["refused"])
        self.loaded = True
        self.fake.table.insert(0, (["nft", "-j", "list", "set"], (1, "Error: No such file or directory")))
        self.assertIsNone(serverfw.refused())

    def test_a_damaged_answer_does_not_crash_the_page(self):
        self.loaded = True
        self.fake.table.insert(0, (["nft", "-j", "list", "set"], (0, "not json at all")))
        self.assertEqual(serverfw.refused(), [])

    def test_the_file_counts_refused_ports_unless_the_firewall_program_is_too_old(self):
        text = serverfw.build_nft([], [22])
        self.assertIn("set refused_tcp { type inet_service; flags dynamic,timeout; timeout 1h; size 256; counter; }", text)
        self.assertIn("tcp flags & (syn | ack) == syn update @refused_tcp { tcp dport timeout 1h }", text)
        self.assertIn("meta l4proto udp update @refused_udp { udp dport timeout 1h }", text)
        self.assertLess(text.index("update @refused_tcp"), text.index("counter drop"))
        plain = serverfw.build_nft([], [22], counting=False)
        self.assertNotIn("refused", plain)

    def test_if_the_firewall_program_does_not_know_the_counters_the_plain_file_is_used(self):
        def old_nft(cmd):
            return (1, "syntax error, unexpected counter") if "refused_tcp" in open(cmd[-1]).read() else (0, "")
        self.fake.table.insert(0, (["nft", "-c"], old_nft))
        res = serverfw.turn_on(add_in_use=False)
        self.assertTrue(res.ok, res.message)
        self.assertNotIn("refused_tcp", self.read(config.P.fw_nft))

    def test_the_policy_says_what_the_list_allows(self):
        self.assertIsNone(serverfw.policy(), "no policy while the firewall is off")
        self.rule("80")
        self.rule("53", proto="udp")
        self.loaded = True
        allowed = serverfw.policy()
        self.assertTrue(allowed("tcp", 80))
        self.assertTrue(allowed("tcp", 22), "the server login is always allowed")
        self.assertTrue(allowed("udp", 53))
        self.assertFalse(allowed("tcp", 4445))
        self.assertFalse(allowed("udp", 80))
