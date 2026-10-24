"""The shared helper that runs commands: it must never crash, whatever the command prints."""
import os
import sys
import tempfile
import unittest

from cpsec import util


class RunningCommands(unittest.TestCase):
    def test_output_that_is_not_text_is_kept_with_the_odd_bytes_replaced(self):
        # found on the real server: fetching a picture (to check it still loads) made the check crash
        rc, out = util.run([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'ok \\x92\\xff\\x00 end')"])
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("ok "))
        self.assertTrue(out.endswith(" end"))
        self.assertLessEqual(len(out), 12)                   # odd bytes become one character each, never an error

    def test_the_same_for_a_command_fed_from_a_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"x")
        self.addCleanup(os.unlink, f.name)
        rc, out = util.run_with_file([sys.executable, "-c", "import sys; sys.stdin.read(); sys.stdout.buffer.write(b'\\x92 done')"], f.name)
        self.assertEqual(rc, 0)
        self.assertTrue(out.endswith(" done"))

    def test_a_missing_program_and_a_slow_one_are_answered_not_raised(self):
        self.assertEqual(util.run(["cps-no-such-program-here"])[0], 127)
        self.assertEqual(util.run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5), (124, "timed out"))

    def test_plain_text_is_unchanged(self):
        self.assertEqual(util.run([sys.executable, "-c", "print('hello')"]), (0, "hello" + ("\n")))


if __name__ == "__main__":
    unittest.main()
