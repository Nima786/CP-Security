#!/usr/bin/python3
"""
Builds a copy of the OWASP rules with only the gentlest sensitivity level (paranoia level 1).

Why this exists (learned the hard way on the production server):
the LiteSpeed rule engine stops processing the remaining rules after the first "skip to the end
of this file" instruction that the OWASP files use to hide their stricter levels. Only the first
rule file ever worked. By cutting the stricter levels out of the copy, the skip instructions are
not needed and every rule file runs.

Usage: python3 -m cpsec.crs_convert <source rules dir> <destination dir>
"""
import os
import re
import shutil
import sys

GATE = re.compile(r'^\s*SecRule\s+TX:EXECUTING_PARANOIA_LEVEL\s+"@lt\s+(\d)"')
MARKER = re.compile(r'^\s*SecMarker\s+"?END-REQUEST-')


def statements(text):
    """Split a rules file into statements, keeping backslash-continued lines together."""
    out, cur = [], []
    for line in text.split("\n"):
        cur.append(line)
        if not line.rstrip().endswith("\\"):
            out.append("\n".join(cur))
            cur = []
    if cur:
        out.append("\n".join(cur))
    return out


def convert(text, keep_skips=False):
    """Returns (new text, number of stricter-level rules cut)."""
    kept, dropping, removed = [], False, 0
    for st in statements(text):
        body = st.lstrip()
        if not keep_skips:
            if body.startswith("SecMarker"):
                continue                      # markers are only needed by the skip instructions
            if body.startswith(("SecRule", "SecAction")) and "skipAfter" in st and not GATE.match(st):
                continue                      # a standalone skip instruction (none is part of a chain)
        m = GATE.match(st)
        if m and "skipAfter" in st:
            if m.group(1) == "1":
                continue                      # level-1 gate: not needed
            dropping = True                   # first stricter-level gate: cut from here on
            removed += 1
            continue
        if MARKER.match(st):
            dropping = False                  # end of this file's rules
            continue
        if dropping:
            if body.startswith(("SecRule", "SecAction")):
                removed += 1
            continue
        kept.append(st)
    return "\n".join(kept).rstrip() + "\n", removed


def convert_dir(src, dst):
    """Convert every REQUEST-*.conf and copy the .data files. Returns {file: (rules kept, rules cut)}."""
    os.makedirs(dst, exist_ok=True)
    report = {}
    for name in sorted(os.listdir(src)):
        path = os.path.join(src, name)
        if name.endswith(".data"):
            shutil.copy2(path, os.path.join(dst, name))
        elif name.startswith("REQUEST-") and name.endswith(".conf"):
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
            # the start-up file (901) keeps its own skip instruction: it works as written
            new, removed = convert(text, keep_skips=name.startswith("REQUEST-901"))
            with open(os.path.join(dst, name), "w", encoding="utf-8", newline="\n") as f:
                f.write(new)
            report[name] = (len(re.findall(r"^\s*SecRule\b", new, re.M)), removed)
    return report


def main(argv):
    for name, (kept, cut) in convert_dir(argv[0], argv[1]).items():
        print("%-52s kept %4d rules, cut %4d stricter-level rules" % (name, kept, cut))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
