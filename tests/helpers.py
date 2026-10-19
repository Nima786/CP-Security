"""Test helpers: a throw-away server folder and a fake command runner."""
import os
import tempfile
import unittest
from unittest import mock

from cpsec import config, util


class FakeRun:
    """Stands in for util.run. `table` is a list of (command prefix, result) checked in order;
    a result is (exit code, output) or a function taking the command and returning one."""

    def __init__(self, table=None):
        self.table = table or []
        self.calls = []

    def __call__(self, cmd, timeout=60):
        self.calls.append(list(cmd))
        for prefix, result in self.table:
            if list(cmd[:len(prefix)]) == list(prefix):
                return result(cmd) if callable(result) else result
        return 0, ""

    def called(self, *prefix):
        return [c for c in self.calls if c[:len(prefix)] == list(prefix)]


class EnvTestCase(unittest.TestCase):
    """Every test gets its own empty server: config.P points into a temporary folder."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        self._old_paths = config.P
        config.P = config.Paths(self.root)
        self.addCleanup(lambda: setattr(config, "P", self._old_paths))
        self.fake = FakeRun()
        patcher = mock.patch.object(util, "run", self.fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    # small conveniences
    def write(self, path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    def read(self, path):
        with open(path, encoding="utf-8") as f:
            return f.read()

    def patch(self, target, *args, **kwargs):
        p = mock.patch(target, *args, **kwargs)
        m = p.start()
        self.addCleanup(p.stop)
        return m
