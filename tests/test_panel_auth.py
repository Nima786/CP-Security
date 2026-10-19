import unittest

from cpsec.panel import auth


class Passwords(unittest.TestCase):
    def test_a_correct_password_verifies_and_a_wrong_one_does_not(self):
        stored = auth.hash_password("correct horse battery", n=16)
        self.assertTrue(auth.verify_password("correct horse battery", stored))
        self.assertFalse(auth.verify_password("correct horse batterz", stored))
        self.assertFalse(auth.verify_password("", stored))

    def test_every_hash_is_different_and_garbage_never_verifies(self):
        self.assertNotEqual(auth.hash_password("same password!!", n=16), auth.hash_password("same password!!", n=16))
        for bad in ("", "nonsense", "scrypt$x$y", "md5$1$2$3$4$5", None):
            self.assertFalse(auth.verify_password("anything", bad))

    def test_password_rules(self):
        self.assertIn("at least", auth.password_problem("short"))
        self.assertIn("repetitive", auth.password_problem("aaaaaaaaaaaaaaaa"))
        self.assertIn("username", auth.password_problem("my-admin-password!", "admin"))
        self.assertIsNone(auth.password_problem("a long enough passphrase", "admin"))


class OneTimeCodes(unittest.TestCase):
    # RFC 6238 test secret "12345678901234567890", SHA-1, last six digits of the published 8-digit codes
    SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    def test_published_test_vectors(self):
        self.assertEqual(auth.totp_now(self.SECRET, now=59), "287082")
        self.assertEqual(auth.totp_now(self.SECRET, now=1111111109), "081804")
        self.assertEqual(auth.totp_now(self.SECRET, now=1234567890), "005924")

    def test_a_code_works_once_and_a_neighbouring_step_is_tolerated(self):
        now = 1234567890
        code = auth.totp_now(self.SECRET, now=now)
        counter = auth.verify_totp(self.SECRET, code, now=now)
        self.assertEqual(counter, now // 30)
        self.assertIsNone(auth.verify_totp(self.SECRET, code, last_counter=counter, now=now), "replay refused")
        self.assertIsNotNone(auth.verify_totp(self.SECRET, code, now=now + 30), "one step late is fine")
        self.assertIsNone(auth.verify_totp(self.SECRET, code, now=now + 120), "too old")

    def test_malformed_codes_are_refused(self):
        for bad in ("", "12345", "1234567", "abcdef", None):
            self.assertIsNone(auth.verify_totp(self.SECRET, bad, now=59))
        self.assertIsNotNone(auth.verify_totp(self.SECRET, "287 082", now=59), "spaces are ignored")

    def test_new_secret_and_link(self):
        a, b = auth.new_totp_secret(), auth.new_totp_secret()
        self.assertNotEqual(a, b)
        self.assertEqual(len(a), 32)
        uri = auth.otpauth_uri(a, "my admin")
        self.assertTrue(uri.startswith("otpauth://totp/CP-Security:my%20admin?secret=" + a))


class Sessions(unittest.TestCase):
    def setUp(self):
        self.t = [1000.0]
        self.s = auth.SessionStore(idle=60, absolute=300, clock=lambda: self.t[0])

    def test_a_session_works_until_it_is_idle_too_long(self):
        token, csrf = self.s.create("admin", "1.2.3.4")
        self.assertEqual(self.s.get(token)["csrf"], csrf)
        self.t[0] += 50
        self.assertIsNotNone(self.s.get(token))
        self.t[0] += 61
        self.assertIsNone(self.s.get(token))

    def test_a_busy_session_still_ends_after_the_absolute_limit(self):
        token, _ = self.s.create("admin", "1.2.3.4")
        for _ in range(7):
            self.t[0] += 50
            self.s.get(token)
        self.assertIsNone(self.s.get(token))

    def test_unknown_tokens_and_destroying(self):
        self.assertIsNone(self.s.get("nope"))
        self.assertIsNone(self.s.get(None))
        a, _ = self.s.create("admin", "1.1.1.1")
        b, _ = self.s.create("admin", "2.2.2.2")
        self.s.destroy_all(except_token=a)
        self.assertIsNotNone(self.s.get(a))
        self.assertIsNone(self.s.get(b))
        self.s.destroy(a)
        self.assertIsNone(self.s.get(a))


class Limiter(unittest.TestCase):
    def setUp(self):
        self.t = [1000.0]
        self.l = auth.LoginLimiter(max_failures=3, window=100, lockout=500, clock=lambda: self.t[0])

    def test_locks_after_too_many_failures_and_frees_later(self):
        for _ in range(2):
            self.l.failed("1.1.1.1")
        self.assertEqual(self.l.seconds_locked("1.1.1.1"), 0)
        self.l.failed("1.1.1.1")
        self.assertGreater(self.l.seconds_locked("1.1.1.1"), 400)
        self.assertEqual(self.l.seconds_locked("2.2.2.2"), 0, "other addresses are not affected")
        self.t[0] += 501
        self.assertEqual(self.l.seconds_locked("1.1.1.1"), 0)

    def test_old_failures_are_forgotten_and_success_resets(self):
        self.l.failed("1.1.1.1"); self.l.failed("1.1.1.1")
        self.t[0] += 101
        self.l.failed("1.1.1.1")
        self.assertEqual(self.l.seconds_locked("1.1.1.1"), 0)
        self.l.failed("1.1.1.1"); self.l.succeeded("1.1.1.1"); self.l.failed("1.1.1.1")
        self.assertEqual(self.l.seconds_locked("1.1.1.1"), 0)
