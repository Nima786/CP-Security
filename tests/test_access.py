
from cpsec import access, config, settings, util
from tests.helpers import EnvTestCase


class AddressChecks(EnvTestCase):
    def test_single_public_address_is_accepted(self):
        self.assertEqual(access.check_address(" 93.184.216.35 "), ("93.184.216.35", None))

    def test_private_and_loopback_are_refused(self):
        for text in ("192.168.1.5", "10.0.0.0/24", "127.0.0.1", "169.254.1.1"):
            clean, err = access.check_address(text)
            self.assertIsNone(clean, text)
            self.assertIn("private", err)

    def test_garbage_and_huge_ranges_are_refused(self):
        self.assertIn("does not look", access.check_address("abc")[1])
        self.assertIn("does not look", access.check_address("")[1])
        self.assertIn("too many", access.check_address("8.0.0.0/8")[1])

    def test_small_range_and_ipv6(self):
        self.assertEqual(access.check_address("8.8.8.0/24"), ("8.8.8.0/24", None))
        self.assertEqual(access.check_address("2001:4860:4860::8888")[1], None)
        self.assertIn("too many", access.check_address("2001::/16")[1])


class NftText(EnvTestCase):
    def test_lock_text_lists_ports_and_addresses(self):
        text = access.build_nft([("1.2.3.4", "x"), ("2001:db8::1", "v6"), ("1.2.3.4", "dup")], [8090, 7080])
        self.assertIn("tcp dport { 8090, 7080 } ip saddr { 127.0.0.1, 1.2.3.4 } accept", text)
        self.assertIn("ip6 saddr { ::1, 2001:db8::1 } accept", text)
        self.assertIn("tcp dport { 8090, 7080 } drop", text)
        self.assertEqual(text.count("1.2.3.4"), 1)

    def test_panel_port_joins_the_lock_only_when_trusted_only(self):
        util.write_json(config.P.panel_settings, {"port": 9443, "access": "login"})
        self.assertEqual(settings.lock_ports(), [8090, 7080, 8888])
        util.write_json(config.P.panel_settings, {"port": 9443, "access": "trusted"})
        self.assertEqual(settings.lock_ports(), [8090, 7080, 8888, 9443])


class AdminList(EnvTestCase):
    def setUp(self):
        super().setUp()
        access.write_list(config.P.admin_list, [("45.60.0.10", "Home Wi-Fi"), ("45.60.0.20", "This server")],
                          access.ADMIN_HEADER)

    def test_list_marks_the_home_entry(self):
        items = access.list_admin()
        self.assertEqual([i["address"] for i in items], ["45.60.0.10", "45.60.0.20"])
        self.assertEqual([i["is_home"] for i in items], [True, False])

    def test_add_writes_the_list_and_loads_the_lock(self):
        r = access.add_admin("93.184.216.34", "Office | evil")
        self.assertTrue(r.ok, r.message)
        self.assertIn("93.184.216.34 | Office evil\n", self.read(config.P.admin_list))   # the | in the label is removed
        self.assertTrue(self.fake.called("nft", "-c", "-f"))
        self.assertTrue(self.fake.called("nft", "-f", config.P.nft_file))
        self.assertIn("93.184.216.34", self.read(config.P.nft_file))

    def test_add_twice_is_refused(self):
        access.add_admin("93.184.216.34", "a")
        r = access.add_admin("93.184.216.34", "b")
        self.assertFalse(r.ok)
        self.assertEqual(r.code, "exists")

    def test_bad_address_changes_nothing(self):
        before = self.read(config.P.admin_list)
        r = access.add_admin("192.168.0.1", "x")
        self.assertFalse(r.ok)
        self.assertEqual(self.read(config.P.admin_list), before)

    def test_a_firewall_that_rejects_the_list_rolls_everything_back(self):
        before = self.read(config.P.admin_list)
        self.fake.table.insert(0, (("nft", "-c", "-f"), (1, "syntax error")))
        r = access.add_admin("93.184.216.34", "x")
        self.assertFalse(r.ok)
        self.assertIn("Nothing was changed", r.message)
        self.assertEqual(self.read(config.P.admin_list), before)

    def test_remove_refuses_the_last_address_and_asks_before_cutting_yourself_off(self):
        r = access.remove_admin("45.60.0.10", caller_ip="45.60.0.10")
        self.assertEqual(r.code, "needs_confirm")
        r = access.remove_admin("45.60.0.10", caller_ip="45.60.0.10", confirmed=True)
        self.assertTrue(r.ok, r.message)
        r = access.remove_admin("45.60.0.20")
        self.assertEqual(r.code, "last_address")
        self.assertEqual(access.remove_admin("9.9.9.9").code, "missing")

    def test_set_home_replaces_only_the_home_entry(self):
        r = access.set_home("45.33.32.156")
        self.assertTrue(r.ok, r.message)
        self.assertIn("The old address 45.60.0.10 was removed", r.message)
        addrs = [i["address"] for i in access.list_admin()]
        self.assertEqual(addrs, ["45.33.32.156", "45.60.0.20"])

    def test_set_home_adds_one_when_there_is_none(self):
        access.write_list(config.P.admin_list, [("45.60.0.20", "This server")], access.ADMIN_HEADER)
        self.assertTrue(access.set_home("45.33.32.156").ok)
        self.assertEqual(len(access.list_admin()), 2)

    def test_blocker_never_blocks_trusted_addresses(self):
        self.patch("cpsec.blocker.installed", return_value=True)
        self.patch("cpsec.blocker.jails", return_value=["sshd"])
        access.add_admin("93.184.216.34", "Office")
        ignore = self.read(config.P.f2b_ignore)
        self.assertIn("ignoreip = 127.0.0.1/8 ::1 45.60.0.10 45.60.0.20 93.184.216.34", ignore)
        self.assertTrue(self.fake.called("fail2ban-client", "reload"))
        self.assertTrue(self.fake.called("fail2ban-client", "unban", "93.184.216.34"))


class InPlainWords(EnvTestCase):
    """The page explains ranges, groups the Cloudflare lines and says which doors the trusted list protects."""

    CLOUDFLARE = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22"]

    def test_counts_are_said_in_words(self):
        self.assertEqual(access.humanize_count(1), "1 address")
        self.assertEqual(access.humanize_count(4096), "4,096 addresses")
        self.assertEqual(access.humanize_count(65536), "about 66 thousand addresses")
        self.assertEqual(access.humanize_count(1048576), "about 1 million addresses")
        self.assertEqual(access.humanize_count(1900000), "about 1.9 million addresses")
        self.assertEqual(access.humanize_count(3 * 10 ** 9), "about 3 billion addresses")
        self.assertEqual(access.humanize_count(2 ** 64), "a huge number of addresses")

    def test_a_slash_entry_is_described_as_a_range(self):
        self.assertEqual(access.describe_range("173.245.48.0/20")["size_text"], "a range of 4,096 addresses")
        self.assertEqual(access.describe_range("203.0.113.9")["size_text"], "1 address")
        self.assertEqual(access.describe_range("203.0.113.9")["count"], 1)
        self.assertEqual(access.describe_range("2606:4700::/32")["count"], 2 ** 96)
        self.assertIn("IPv6 range", access.describe_range("2606:4700::/32")["size_text"])
        self.assertEqual(access.describe_range("2606:4700::1")["size_text"], "1 address")
        self.assertEqual(access.describe_range("not an address")["size_text"], "")

    def test_entries_with_the_same_name_become_one_line_with_the_total(self):
        items = [{"address": a, "label": "Cloudflare"} for a in self.CLOUDFLARE] + [{"address": "203.0.113.9", "label": "Office"}]
        groups = access.group_never(items)
        self.assertEqual([g["label"] for g in groups], ["Cloudflare", "Office"])
        cf, office = groups
        self.assertTrue(cf["many"])
        self.assertEqual(len(cf["entries"]), 3)
        self.assertEqual(cf["total_text"], "3 IPv4 ranges covering 6,144 addresses")          # 4096 + 1024 + 1024
        self.assertIn("Cloudflare", cf["hint"])
        self.assertFalse(office["many"])
        self.assertEqual(office["hint"], "")
        self.assertEqual(office["entries"][0]["size_text"], "1 address")

    def test_ipv6_ranges_are_counted_apart_from_ipv4(self):
        items = [{"address": a, "label": "Cloudflare"} for a in self.CLOUDFLARE[:2] + ["2400:cb00::/32", "2606:4700::/32"]]
        cf = access.group_never(items)[0]
        self.assertEqual(cf["total_text"], "2 IPv4 ranges covering about 5 thousand addresses and 2 IPv6 ranges".replace("about 5 thousand", "5,120"))
        only6 = access.group_never([{"address": "2400:cb00::/32", "label": "x"}])[0]
        self.assertEqual(only6["total_text"], "1 IPv6 range")
        singles = access.group_never([{"address": "203.0.113.1", "label": "Office"}, {"address": "203.0.113.2", "label": "Office"}])[0]
        self.assertEqual(singles["total_text"], "2 IPv4 addresses")

    def test_several_addresses_can_be_taken_off_in_one_go(self):
        access.write_list(config.P.never_list, [(a, "Cloudflare") for a in self.CLOUDFLARE] + [("203.0.113.9", "Office")], access.NEVER_HEADER)
        res = access.remove_never_many(self.CLOUDFLARE[:2])
        self.assertTrue(res.ok, res.message)
        self.assertEqual([x["address"] for x in access.list_never_block()], [self.CLOUDFLARE[2], "203.0.113.9"])
        self.assertFalse(access.remove_never_many(["198.51.100.1"]).ok)
        self.assertEqual(access.remove_never_many(["198.51.100.1"]).code, "missing")
