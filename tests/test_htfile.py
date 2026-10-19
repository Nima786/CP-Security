import os
import tempfile
import unittest

from cpsec import htfile

BLOCK = (htfile.BEGIN + "\n<IfModule mod_headers.c>\n    Header always set X-Frame-Options \"SAMEORIGIN\"\n"
         "</IfModule>\n" + htfile.END + "\n")
WP = "# BEGIN WordPress\nRewriteEngine On\nRewriteRule . /index.php [L]\n# END WordPress\n"


class Text(unittest.TestCase):
    def test_our_block_goes_on_top_and_comes_off_cleanly(self):
        text = htfile.compose(WP, BLOCK)
        self.assertTrue(text.startswith(htfile.BEGIN))
        self.assertEqual(htfile.strip_block(text), WP)
        self.assertEqual(htfile.compose(htfile.strip_block(text), BLOCK), text)       # applying twice changes nothing

    def test_an_empty_file_gets_just_the_block(self):
        self.assertEqual(htfile.compose("", BLOCK), BLOCK)
        self.assertEqual(htfile.strip_block(BLOCK), "")

    def test_windows_line_endings_are_kept(self):
        wp = WP.replace("\n", "\r\n")
        text = htfile.compose(wp, BLOCK)
        self.assertEqual(htfile.strip_block(text), wp)

    def test_a_damaged_block_is_refused_not_guessed_at(self):
        for text in (htfile.BEGIN + "\nx\n", htfile.END + "\n" + htfile.BEGIN + "\n", BLOCK + BLOCK):
            with self.assertRaises(htfile.Refused):
                htfile.split_block(text)

    def test_header_names_ignore_comments_and_read_every_form(self):
        text = ('# Header set X-Nope "1"\n'
                '<IfModule mod_headers.c>\n'
                '  Header always set Strict-Transport-Security "max-age=1" env=HTTPS\n'
                '  Header set "X-Quoted" "1"\n'
                '  header unset X-Powered-By\n'
                '  Header always merge Content-Security-Policy "upgrade-insecure-requests"\n'
                '</IfModule>\n'
                'RewriteRule ^Header set X-Fake$ /\n')
        self.assertEqual(htfile.header_names(text),
                         {"strict-transport-security", "x-quoted", "x-powered-by", "content-security-policy"})

    def test_taking_over_switches_lines_off_and_giving_back_restores_them_exactly(self):
        text = 'Header always set X-Frame-Options "DENY"\nHeader set Cache-Control "x"\n  Header unset X-Powered-By\n'
        new, n = htfile.take_over_lines(text, ["X-Frame-Options", "x-powered-by"])
        self.assertEqual(n, 2)
        self.assertEqual(htfile.header_names(new), {"cache-control"})
        self.assertIn(htfile.TAKEN + 'Header always set X-Frame-Options "DENY"\n', new)
        back, m = htfile.give_back_lines(new)
        self.assertEqual((back, m), (text, 2))

    def test_continued_lines_are_not_cut_in_half(self):
        text = 'Header set Content-Security-Policy "a" \\\n  "b"\n'
        new, n = htfile.take_over_lines(text, ["content-security-policy"])
        self.assertEqual((new, n), (text, 0))


class Files(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.path = os.path.join(self.dir, ".htaccess")

    def put(self, text, mode=0o640):
        with open(self.path, "wb") as f:
            f.write(text.encode("utf-8", errors="surrogateescape"))
        os.chmod(self.path, mode)

    def get(self):
        with open(self.path, "rb") as f:
            return f.read().decode("utf-8", errors="surrogateescape")

    def leftovers(self):
        return [n for n in os.listdir(self.dir) if n != ".htaccess"]

    def test_apply_adds_the_block_on_top_and_keeps_the_rest_and_the_permissions(self):
        self.put(WP, 0o640)
        res = htfile.apply(self.dir, BLOCK)
        self.assertTrue(res["changed"])
        self.assertEqual(res["original"], WP)
        self.assertEqual(self.get(), htfile.compose(WP, BLOCK))
        if os.name == "posix":
            self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o640)
        self.assertEqual(self.leftovers(), [], "no temporary file is left behind")

    def test_a_second_apply_changes_nothing(self):
        self.put(WP)
        htfile.apply(self.dir, BLOCK)
        before = os.stat(self.path).st_mtime_ns
        res = htfile.apply(self.dir, BLOCK)
        self.assertFalse(res["changed"])
        self.assertEqual(os.stat(self.path).st_mtime_ns, before)

    def test_a_new_file_is_created_and_removing_the_block_deletes_a_file_with_nothing_else_in_it(self):
        res = htfile.apply(self.dir, BLOCK)
        self.assertEqual((res["changed"], res["existed"], res["original"]), (True, False, None))
        self.assertEqual(self.get(), BLOCK)
        htfile.apply(self.dir, None)
        self.assertFalse(os.path.exists(self.path))

    def test_removing_the_block_keeps_the_sites_own_lines(self):
        self.put(WP)
        htfile.apply(self.dir, BLOCK)
        htfile.apply(self.dir, None)
        self.assertEqual(self.get(), WP)

    def test_remove_gives_back_what_was_taken_over(self):
        site = 'Header always set X-Frame-Options "DENY"\n' + WP
        self.put(site)
        res = htfile.apply(self.dir, BLOCK, take_over=["X-Frame-Options"])
        self.assertEqual(res["taken"], 1)
        self.assertEqual(htfile.inspect(self.dir)["site_names"], [])
        res = htfile.apply(self.dir, None, give_back=True)
        self.assertEqual((res["given"], self.get()), (1, site))

    def test_restore_puts_the_file_back_exactly(self):
        self.put(WP)
        res = htfile.apply(self.dir, BLOCK)
        htfile.restore(self.dir, res["original"])
        self.assertEqual(self.get(), WP)
        res = htfile.apply(self.dir, None)           # nothing to remove: unchanged
        self.assertFalse(res["changed"])
        os.remove(self.path)
        htfile.apply(self.dir, BLOCK)
        htfile.restore(self.dir, None)
        self.assertFalse(os.path.exists(self.path))

    def test_bytes_that_are_not_clean_text_survive(self):
        odd = "# caf\udce9 \udcff\n" + WP                 # what bytes e9 and ff read as
        self.put(odd)
        htfile.apply(self.dir, BLOCK)
        htfile.apply(self.dir, None)
        with open(self.path, "rb") as f:
            self.assertEqual(f.read(), odd.encode("utf-8", errors="surrogateescape"))

    def test_a_damaged_block_leaves_the_file_alone(self):
        self.put(htfile.BEGIN + "\nHeader set X-A 1\n")
        res = htfile.handle({"op": "apply", "docroot": self.dir, "block": BLOCK})
        self.assertFalse(res["ok"])
        self.assertIn("damaged", res["error"])
        self.assertEqual(self.get(), htfile.BEGIN + "\nHeader set X-A 1\n")
        self.assertTrue(htfile.inspect(self.dir)["damaged"])

    def test_a_huge_file_is_refused(self):
        self.put("# x\n" * (htfile.MAX_SIZE // 4 + 10))
        res = htfile.handle({"op": "apply", "docroot": self.dir, "block": BLOCK})
        self.assertFalse(res["ok"])
        self.assertIn("large", res["error"])

    @unittest.skipUnless(hasattr(os, "symlink") and hasattr(os, "O_NOFOLLOW"), "needs links and O_NOFOLLOW")
    def test_a_link_instead_of_the_file_is_never_followed(self):
        target = os.path.join(self.dir, "secret.txt")
        with open(target, "w") as f:
            f.write("root only\n")
        try:
            os.symlink(target, self.path)
        except OSError:
            self.skipTest("links cannot be made here")
        res = htfile.handle({"op": "apply", "docroot": self.dir, "block": BLOCK})
        self.assertFalse(res["ok"])
        self.assertIn("link", res["error"])
        with open(target) as f:
            self.assertEqual(f.read(), "root only\n")
        self.assertIn("link", htfile.inspect(self.dir)["error"])

    @unittest.skipUnless(hasattr(os, "symlink"), "needs links")
    def test_a_folder_that_is_a_link_is_refused(self):
        real = os.path.join(self.dir, "real")
        os.mkdir(real)
        link = os.path.join(self.dir, "public_html")
        try:
            os.symlink(real, link)
        except OSError:
            self.skipTest("links cannot be made here")
        res = htfile.handle({"op": "apply", "docroot": link, "block": BLOCK})
        self.assertFalse(res["ok"])
        self.assertFalse(os.path.exists(os.path.join(real, ".htaccess")))

    def test_requests_that_make_no_sense_are_answered_not_crashed_on(self):
        self.assertFalse(htfile.handle({})["ok"])
        self.assertFalse(htfile.handle({"op": "apply"})["ok"])
        self.assertFalse(htfile.handle({"op": "apply", "docroot": os.path.join(self.dir, "missing"), "block": BLOCK})["ok"])

    def test_inspect_reports_what_the_site_sets_itself(self):
        self.put('Header always set X-Frame-Options "DENY"\n')
        htfile.apply(self.dir, BLOCK)
        info = htfile.inspect(self.dir)
        self.assertEqual((info["exists"], info["has_block"], info["site_names"]), (True, True, ["x-frame-options"]))
        self.assertEqual(htfile.inspect(os.path.join(self.dir, "nowhere"))["exists"], False)
