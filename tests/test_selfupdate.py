import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
import unittest
from unittest import mock

from cpsec import __version__, config, provision, selfupdate, settings, util
from tests.helpers import EnvTestCase

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build_release(version, extra=(), skip_init=False):
    """A real release file made from this very source tree, labelled with another version number."""
    buf = io.BytesIO()
    prefix = "cp-security-%s/" % version
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for folder, dirs, files in os.walk(os.path.join(REPO_ROOT, "cpsec")):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for name in files:
                if name.endswith(".pyc") or (skip_init and name == "__init__.py" and folder.endswith("cpsec")):
                    continue
                full = os.path.join(folder, name)
                tar.add(full, arcname=prefix + os.path.relpath(full, REPO_ROOT).replace(os.sep, "/"))
        data = (version + "\n").encode()
        info = tarfile.TarInfo(prefix + "VERSION")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        for info, content in extra:
            tar.addfile(info, io.BytesIO(content) if content is not None else None)
    return buf.getvalue()


class FakeGitHub:
    """Stands in for the internet: answers the release API and the two downloads of a release."""

    def __init__(self, version, tarball=None, sums=True, newest=None):
        self.version = version
        self.tarball = tarball if tarball is not None else build_release(version)
        self.sums = sums
        self.newest = newest or version
        self.requested = []

    def __call__(self, url):
        self.requested.append(url)
        if url == selfupdate.API_LATEST:
            body = json.dumps({"tag_name": "v" + self.newest, "body": "* what is new", "published_at": "2026-10-19T10:00:00Z"})
            return io.BytesIO(body.encode())
        if url.endswith("SHA256SUMS"):
            if not self.sums:
                return io.BytesIO(b"")
            digest = hashlib.sha256(self.tarball).hexdigest()
            return io.BytesIO(("%s  cp-security-%s.tar.gz\n%s  install.sh\n" % (digest, self.version, "0" * 64)).encode())
        if url.endswith(".tar.gz"):
            return io.BytesIO(self.tarball)
        raise OSError("unexpected address " + url)


class Versions(unittest.TestCase):
    def test_parsing_and_comparing(self):
        self.assertEqual(selfupdate.parse_version("v1.2.3"), (1, 2, 3))
        for bad in ("", "1.2", "1.2.3.4", "1.2.x", "latest", "../1.2.3", "1.2.3; rm -rf /"):
            self.assertIsNone(selfupdate.parse_version(bad), bad)
        self.assertTrue(selfupdate.is_newer("0.10.0", "0.9.9"), "numbers, not text")
        self.assertFalse(selfupdate.is_newer("0.2.2", "0.2.2"))
        self.assertFalse(selfupdate.is_newer("0.2.1", "0.2.2"))
        self.assertFalse(selfupdate.is_newer("garbage", "0.2.2"))


class Looking(EnvTestCase):
    def test_the_newest_release_is_read(self):
        found = selfupdate.latest(FakeGitHub("9.9.9"))
        self.assertEqual((found["version"], found["published"]), ("9.9.9", "2026-10-19"))

    def test_a_draft_a_pre_release_or_a_strange_tag_is_ignored(self):
        for body in ({"tag_name": "v9.9.9", "draft": True}, {"tag_name": "v9.9.9", "prerelease": True},
                     {"tag_name": "nightly"}, {}):
            with self.assertRaises(ValueError):
                selfupdate.latest(lambda url, b=body: io.BytesIO(json.dumps(b).encode()))

    def test_no_internet_is_a_plain_message_not_a_crash(self):
        def down(url):
            raise OSError("Name or service not known")
        u = selfupdate.Updater(down)
        r = u.check()
        self.assertEqual((r.ok, r.code), (False, "no_answer"))
        self.assertIn("Could not reach GitHub", u.state()["check_error"])

    def test_the_state_says_whether_something_newer_exists(self):
        u = selfupdate.Updater(FakeGitHub("9.9.9"))
        self.assertFalse(u.state()["available"], "before looking, nothing is claimed")
        self.assertEqual(u.check().code, "available")
        s = u.state()
        self.assertEqual((s["current"], s["latest"], s["available"]), (__version__, "9.9.9", True))
        u2 = selfupdate.Updater(FakeGitHub(__version__))
        self.assertEqual(u2.check().code, "current")
        self.assertFalse(u2.state()["available"])


class TheDownload(EnvTestCase):
    def test_a_good_release_passes_its_fingerprint_check(self):
        self.assertTrue(selfupdate.fetch_release("9.9.9", FakeGitHub("9.9.9")))

    def test_only_the_official_address_is_used_and_only_for_a_version_number(self):
        gh = FakeGitHub("9.9.9")
        selfupdate.fetch_release("9.9.9", gh)
        for url in gh.requested:
            self.assertTrue(url.startswith("https://github.com/Nima786/CP-Security/releases/download/v9.9.9/"), url)
        with self.assertRaises(ValueError):
            selfupdate.fetch_release("9.9.9/../../evil", gh)

    def test_a_download_that_does_not_match_is_refused(self):
        real = build_release("9.9.9")
        digest = hashlib.sha256(real).hexdigest()

        def serve(url):
            if url.endswith("SHA256SUMS"):
                return io.BytesIO(("%s  cp-security-9.9.9.tar.gz\n" % digest).encode())
            return io.BytesIO(real + b"tampered")
        with self.assertRaises(ValueError) as caught:
            selfupdate.fetch_release("9.9.9", serve)
        self.assertIn("fingerprint", str(caught.exception))

    def test_a_release_without_a_published_fingerprint_is_refused(self):
        with self.assertRaises(ValueError):
            selfupdate.fetch_release("9.9.9", FakeGitHub("9.9.9", sums=False))

    def test_an_oversized_download_is_refused(self):
        def huge(url):
            return io.BytesIO(b"x" * (selfupdate.MAX_DOWNLOAD + 10))
        with self.assertRaises(ValueError):
            selfupdate.fetch_release("9.9.9", huge)

    def test_only_program_files_are_unpacked_and_nothing_can_escape(self):
        evil = tarfile.TarInfo("cp-security-9.9.9/cpsec/../../escape.py")
        evil.size = 1
        other = tarfile.TarInfo("cp-security-9.9.9/install.sh")
        other.size = 1
        link = tarfile.TarInfo("cp-security-9.9.9/cpsec/link.py")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        data = build_release("9.9.9", extra=[(evil, b"x"), (other, b"x"), (link, None)])
        dest = os.path.join(self.root, "new")
        n = selfupdate.extract_program(data, "9.9.9", dest)
        self.assertGreater(n, 10)
        self.assertFalse(os.path.exists(os.path.join(self.root, "escape.py")))
        self.assertFalse(os.path.exists(os.path.join(dest, "install.sh")))
        self.assertFalse(os.path.exists(os.path.join(dest, "cpsec", "link.py")))
        self.assertEqual(util.read_text(os.path.join(dest, "VERSION")).strip(), "9.9.9")

    def test_a_download_labelled_with_the_wrong_version_is_refused(self):
        data = build_release("9.9.8")
        data = data.replace(b"cp-security-9.9.8/", b"cp-security-9.9.9/")
        with self.assertRaises(ValueError):
            selfupdate.extract_program(data, "9.9.9", os.path.join(self.root, "new"))

    def test_new_program_files_must_start_before_anything_is_replaced(self):
        dest = os.path.join(self.root, "new")
        selfupdate.extract_program(build_release("9.9.9"), "9.9.9", dest)
        self.assertEqual(selfupdate.self_test(dest), "9.9.9", "the new files report their own version")
        with open(os.path.join(dest, "cpsec", "cli.py"), "a") as f:
            f.write("\nthis is not python (\n")
        with self.assertRaises(ValueError):
            selfupdate.self_test(dest)


class Installing(EnvTestCase):
    """The whole switch-over on a pretend server."""

    def setUp(self):
        super().setUp()
        p = config.P
        # the 'installed' program: a copy of this source tree
        shutil.copytree(os.path.join(REPO_ROOT, "cpsec"), os.path.join(p.install_dir, "cpsec"),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        self.write(p.install_dir + "/VERSION", "0.0.1\n")
        settings.save({"domain": "sec.example.com", "port": 8091, "access": "trusted"})
        self.patch("cpsec.selfupdate.shutil.which", return_value="/usr/bin/tool")
        self.gh = FakeGitHub("9.9.9")
        self.u = selfupdate.Updater(self.gh)
        self.u.check()

    def run_install(self, **kw):
        r = self.u.install("9.9.9", background=False, **kw)
        return r, self.u.state()

    def test_a_full_update_switches_the_files_keeps_the_old_ones_and_hands_over_the_restart(self):
        r, s = self.run_install()
        self.assertTrue(r.ok, r.message)
        self.assertEqual(s["job"]["status"], "restarting", s["job"])
        self.assertEqual(util.read_text(config.P.install_dir + "/VERSION").strip(), "9.9.9")
        self.assertEqual(util.read_text(config.P.install_dir + ".previous/VERSION").strip(), "0.0.1")
        self.assertTrue(os.path.isdir(config.P.install_dir + ".previous/cpsec"))
        self.assertFalse(os.path.exists(config.P.install_dir + "/cpsec.old"))
        self.assertFalse(os.path.exists(config.P.install_dir + "/cpsec.new"))
        run = self.fake.called("systemd-run")[0]
        self.assertTrue(any(a.startswith("--unit=cps-self-update-") for a in run), "started by systemd, so it survives the restart")
        script = util.read_text(os.path.join(config.P.conf_dir, selfupdate.HELPER_FILE))
        self.assertIn('"version": "9.9.9"', script)
        self.assertIn("sec.example.com:8091:127.0.0.1", script)
        self.assertIn("https://sec.example.com:8091/api/me", script)
        if os.name == "posix":
            mode = stat.S_IMODE(os.stat(os.path.join(config.P.conf_dir, selfupdate.HELPER_FILE)).st_mode)
            self.assertEqual(mode & 0o077, 0, "only root may read or change the helper")
        self.assertTrue(self.fake.called("systemctl", "restart", "cps-wplogin-feed"))

    def test_a_bad_download_changes_nothing(self):
        self.gh.tarball = b"not a release"
        r, s = self.run_install()
        self.assertEqual(s["job"]["status"], "failed")
        self.assertEqual(util.read_text(config.P.install_dir + "/VERSION").strip(), "0.0.1")
        self.assertFalse(os.path.exists(config.P.install_dir + ".previous"))
        self.assertEqual(self.fake.called("systemd-run"), [])

    def test_new_files_that_do_not_start_are_never_switched_on(self):
        broken = build_release("9.9.9", skip_init=True)
        self.gh.tarball = broken
        r, s = self.run_install()
        self.assertEqual(s["job"]["status"], "failed")
        self.assertEqual(util.read_text(config.P.install_dir + "/VERSION").strip(), "0.0.1")

    def test_if_the_restart_cannot_be_scheduled_the_old_version_is_put_back(self):
        self.fake.table.append((["systemd-run"], (1, "Failed to connect to bus")))
        r, s = self.run_install()
        self.assertEqual(s["job"]["status"], "failed")
        self.assertIn("old version was put back", s["job"]["message"])
        self.assertEqual(util.read_text(config.P.install_dir + "/VERSION").strip(), "0.0.1")
        self.assertTrue(os.path.exists(config.P.install_dir + "/cpsec/__init__.py"))

    def test_refusals(self):
        self.assertEqual(self.u.install("0.0.1", background=False).code, "not_newer")
        self.assertEqual(self.u.install("nonsense", background=False).code, "unknown_version")
        self.patch("cpsec.selfupdate.shutil.which", return_value=None)
        self.assertEqual(self.u.install("9.9.9", background=False).code, "no_tools")

    def test_a_second_update_while_one_runs_is_refused(self):
        self.u.job["status"] = "working"
        self.assertEqual(self.u.install("9.9.9", background=False).code, "busy")

    def test_reinstalling_the_same_version_is_possible_on_purpose(self):
        self.patch("cpsec.selfupdate.__version__", "9.9.9")
        r = self.u.install("9.9.9", force=True, background=False)
        self.assertTrue(r.ok, r.message)

    def test_the_result_of_the_last_update_is_shown_after_the_panel_comes_back(self):
        self.write(os.path.join(config.P.conf_dir, selfupdate.RESULT_FILE),
                   json.dumps({"ok": False, "version": "9.9.9", "when": "2026-10-19 10:00:00"}))
        self.assertIs(self.u.state()["last_result"]["ok"], False)
        self.u.install("9.9.9", background=False)
        self.assertIsNone(self.u.state()["last_result"], "a new attempt starts with a clean slate")


@unittest.skipUnless(shutil.which("sh") and os.name == "posix", "needs a Unix shell")
class TheRestartHelper(EnvTestCase):
    """The shell script that decides between 'it worked' and 'put the old version back', run for real with stand-in
    systemctl and curl programs."""

    def setUp(self):
        super().setUp()
        p = config.P
        settings.save({"domain": "sec.example.com", "port": 8091, "access": "trusted"})
        self.write(p.install_dir + "/cpsec/marker", "NEW")
        self.write(p.install_dir + "/VERSION", "9.9.9\n")
        self.write(p.install_dir + ".previous/cpsec/marker", "OLD")
        self.write(p.install_dir + ".previous/VERSION", "0.0.1\n")
        self.bin = os.path.join(self.root, "stubs")
        os.makedirs(self.bin)
        self.calls = os.path.join(self.root, "calls.txt")
        self.reply = os.path.join(self.root, "reply.txt")
        self.stub("systemctl", 'echo "systemctl $*" >> %s' % self.calls)
        self.stub("curl", "cat %s" % self.reply)
        self.script = os.path.join(p.conf_dir, selfupdate.HELPER_FILE)
        util.atomic_write(self.script, selfupdate.helper_script("9.9.9"), 0o700)

    def stub(self, name, body):
        path = os.path.join(self.bin, name)
        with open(path, "w") as f:
            f.write("#!/bin/sh\n%s\n" % body)
        os.chmod(path, 0o755)

    def run_helper(self, reply):
        with open(self.reply, "w") as f:
            f.write(reply)
        env = dict(os.environ, PATH=self.bin + os.pathsep + os.environ["PATH"], CPS_UPDATE_WAIT="0", CPS_UPDATE_TRIES="3")
        subprocess.run(["sh", self.script], env=env, check=True, timeout=60)
        return json.loads(util.read_text(os.path.join(config.P.conf_dir, selfupdate.RESULT_FILE)))

    def test_a_panel_that_answers_with_the_new_version_is_left_alone(self):
        result = self.run_helper('{"authenticated": false, "version": "9.9.9", "twofa": false}')
        self.assertTrue(result["ok"])
        self.assertEqual(util.read_text(config.P.install_dir + "/cpsec/marker"), "NEW")
        self.assertEqual(util.read_text(self.calls).splitlines(), ["systemctl restart cp-security-panel"])

    def test_a_panel_that_does_not_come_up_is_rolled_back(self):
        result = self.run_helper("")
        self.assertFalse(result["ok"])
        self.assertEqual(util.read_text(config.P.install_dir + "/cpsec/marker"), "OLD")
        self.assertEqual(util.read_text(config.P.install_dir + "/VERSION").strip(), "0.0.1")
        self.assertIn("systemctl restart cp-security-panel cps-wplogin-feed", util.read_text(self.calls))
        self.assertTrue(os.path.isdir(config.P.install_dir + "/cpsec.failed"), "the failed files are kept to look at")

    def test_a_panel_that_still_runs_the_old_version_counts_as_not_updated(self):
        result = self.run_helper('{"authenticated": false, "version": "0.0.1"}')
        self.assertFalse(result["ok"])

    def test_the_script_is_valid_shell(self):
        subprocess.run(["sh", "-n", self.script], check=True)


class RefreshingTheSystemAfterwards(EnvTestCase):
    def test_service_files_are_refreshed_only_where_they_exist_and_differ(self):
        p = config.P
        self.patch("cpsec.blocker.installed", return_value=False)
        self.assertEqual(provision.refresh_after_update(), [], "nothing installed, nothing touched")
        self.assertFalse(os.path.exists(p.systemd_dir + "/" + provision.SERVICE_FEED))
        self.write(p.systemd_dir + "/" + provision.SERVICE_FEED, "[Unit]\nOld text\n")
        done = provision.refresh_after_update()
        self.assertEqual(done, ["service file " + provision.SERVICE_FEED])
        self.assertIn("-m cpsec.feed", util.read_text(p.systemd_dir + "/" + provision.SERVICE_FEED))
        self.assertTrue(self.fake.called("systemctl", "daemon-reload"))
        self.assertEqual(provision.refresh_after_update(), [], "a second time there is nothing left to do")

    def test_the_blockers_filters_are_rewritten_when_ours_are_installed(self):
        p = config.P
        self.patch("cpsec.blocker.installed", return_value=True)
        self.patch("cpsec.blocker.time.sleep")
        self.write(p.f2b_jails, "# old\n")
        self.write(p.at("/var/log/mail.log"), "")
        self.fake.table.append((["fail2ban-client", "-t"], (0, "OK")))
        done = provision.refresh_after_update()
        self.assertEqual(done, ["blocker settings"])
        self.assertIn("WPLOGIN", util.read_text(p.f2b_filter_dir + "/cps-wp-login.conf"))


class FromTheCommandLine(EnvTestCase):
    def test_checking_only_changes_nothing(self):
        from cpsec import cli
        with mock.patch("cpsec.selfupdate.latest", return_value={"version": "9.9.9", "notes": "n", "published": ""}), \
                mock.patch("builtins.print") as shown:
            self.assertEqual(cli.main(["update", "--check"]), 0)
        text = "\n".join(str(c.args[0]) for c in shown.call_args_list if c.args)
        self.assertIn("9.9.9 is available", text)

    def test_nothing_to_do_when_up_to_date(self):
        from cpsec import cli
        with mock.patch("cpsec.selfupdate.latest", return_value={"version": __version__, "notes": "", "published": ""}), \
                mock.patch("builtins.print") as shown:
            self.assertEqual(cli.main(["update"]), 0)
        self.assertIn("newest version", str(shown.call_args_list[0]))

    def test_it_asks_before_installing(self):
        from cpsec import cli
        with mock.patch("cpsec.selfupdate.latest", return_value={"version": "9.9.9", "notes": "n", "published": ""}), \
                mock.patch("cpsec.menu.ask", return_value="no"), mock.patch("builtins.print"), \
                mock.patch.object(selfupdate.Updater, "install") as install:
            self.assertEqual(cli.main(["update"]), 1)
        self.assertFalse(install.called)
