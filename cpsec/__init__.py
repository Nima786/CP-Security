"""CP-Security: protection and a simple control panel for a CyberPanel / OpenLiteSpeed-Enterprise server.

The package has two halves that share one engine:

* the engine  (``access``, ``blocker``, ``waf``, ``sites``, ``updates``, ``health``) does the work
  and never prints anything: every function returns data or a ``Result``;
* the front ends (``menu`` in the terminal, ``panel`` in the browser) only show that data.
"""
import os

_here = os.path.dirname(os.path.abspath(__file__))


def _read_version():
    for candidate in (os.path.join(_here, "..", "VERSION"), os.path.join(_here, "VERSION")):
        try:
            with open(candidate, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            continue
    return "0.0.0"


__version__ = _read_version()
