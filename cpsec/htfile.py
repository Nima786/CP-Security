"""Work on a website's .htaccess file. Changes are made AS THE WEBSITE'S OWN USER, never as root.

Why: a website's folders belong to the website, and a hacked site can plant tricks in them, for example a
link named .htaccess that points at a system file. A program running as root that follows such a link
would overwrite or leak that file. So the panel starts this module as the site's own user (see
headers.py): it can then only do what the website itself could always do.

The text handling is plain functions so it can be tested anywhere. Our own lines sit between two marker
lines and are replaced as a whole. Lines the site already had are never changed, except on request
("take over"): they are switched off by putting a marker in front, and switched back on when our block
is removed.
"""
import json
import os
import re
import stat
import sys
import tempfile

BEGIN = "# BEGIN CP-Security headers"
END = "# END CP-Security headers"
TAKEN = "#CPS-TAKEN# "
MAX_SIZE = 1024 * 1024
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)

# Header [always|onsuccess] set|append|merge|add|unset|edit|echo  NAME ...
HEADER_LINE = re.compile(r'^\s*Header\s+(?:(?:always|onsuccess)\s+)?(?:set|append|merge|add|unset|edit\*?|echo)\s+["\']?([A-Za-z0-9-]+)',
                         re.I)


class Refused(Exception):
    """Something about the file or folder is not safe or not as expected. The message is shown to the owner."""


# ----------------------------------------------------------------------------- text
def _lines(text):
    return text.splitlines(keepends=True)


def split_block(text):
    """(text before our block, our block or None, text after it). Raises Refused if the block is damaged."""
    lines = _lines(text)
    begin = [i for i, ln in enumerate(lines) if ln.strip() == BEGIN]
    end = [i for i, ln in enumerate(lines) if ln.strip() == END]
    if not begin and not end:
        return text, None, ""
    if len(begin) != 1 or len(end) != 1 or end[0] < begin[0]:
        raise Refused("The CP-Security lines in this website's .htaccess are damaged (a start or end line is missing "
                      "or repeated). Nothing was changed. Fix or delete them by hand first.")
    return "".join(lines[:begin[0]]), "".join(lines[begin[0]:end[0] + 1]), "".join(lines[end[0] + 1:])


def strip_block(text):
    before, block, after = split_block(text)
    if block is None:
        return text
    # we put one blank line between our block and the rest; take it away with the block
    if after.startswith("\n") or after.startswith("\r\n"):
        after = after.split("\n", 1)[1]
    return before + after


def header_names(text):
    """Lower-case names of the headers that active (not commented-out) lines in this text set or change."""
    names = set()
    for line in _lines(text):
        if line.lstrip().startswith("#"):
            continue
        m = HEADER_LINE.match(line)
        if m:
            names.add(m.group(1).lower())
    return names


def take_over_lines(text, names):
    """Switch off the site's own lines for these header names. Returns (new text, how many lines)."""
    names = set(n.lower() for n in names)
    out, count = [], 0
    for line in _lines(text):
        m = None if line.lstrip().startswith("#") else HEADER_LINE.match(line)
        if m and m.group(1).lower() in names and not line.rstrip().endswith("\\"):
            line = TAKEN + line
            count += 1
        out.append(line)
    return "".join(out), count


def give_back_lines(text):
    """Undo take_over_lines. Returns (new text, how many lines)."""
    out, count = [], 0
    for line in _lines(text):
        if line.startswith(TAKEN):
            line = line[len(TAKEN):]
            count += 1
        out.append(line)
    return "".join(out), count


def compose(base, block):
    """Our block at the top, then a blank line, then the site's own text."""
    if not block:
        return base
    return block.rstrip("\n") + "\n" + ("\n" + base if base.strip() else "")


# ----------------------------------------------------------------------------- reading (safe)
def path_of(docroot):
    return os.path.join(docroot, ".htaccess")


def read(docroot):
    """The file's text, or None if there is no file. Links and odd files are refused, never followed."""
    path = path_of(docroot)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise Refused("The .htaccess file cannot be looked at (%s)." % exc.strerror)
    if not stat.S_ISREG(st.st_mode):
        raise Refused("The .htaccess here is a link or not an ordinary file. For safety nothing was changed.")
    if st.st_size > MAX_SIZE:
        raise Refused("The .htaccess file is unusually large (over 1 MB). Nothing was changed.")
    try:
        fd = os.open(path, os.O_RDONLY | NOFOLLOW)
    except OSError as exc:
        raise Refused("The .htaccess file cannot be opened (%s)." % exc.strerror)
    with os.fdopen(fd, "rb") as f:
        return f.read().decode("utf-8", errors="surrogateescape")


def inspect(docroot):
    """What is in the file, without changing anything."""
    info = {"exists": False, "has_block": False, "block": "", "damaged": False, "site_names": [], "taken": 0,
            "taken_names": [], "error": ""}
    try:
        text = read(docroot)
        if text is None:
            return info
        info["exists"] = True
        try:
            before, block, after = split_block(text)
        except Refused as exc:
            info["damaged"], info["error"] = True, str(exc)
            return info
        info["has_block"] = block is not None
        info["block"] = block or ""
        rest = before + after
        info["site_names"] = sorted(header_names(rest))
        taken_lines = [ln[len(TAKEN):] for ln in _lines(rest) if ln.startswith(TAKEN)]
        info["taken"] = len(taken_lines)
        info["taken_names"] = sorted(header_names("".join(taken_lines)))
    except Refused as exc:
        info["error"] = str(exc)
    return info


# ----------------------------------------------------------------------------- writing (runs as the site's user)
def _write(docroot, text, mode, gid):
    path = path_of(docroot)
    fd, tmp = tempfile.mkstemp(prefix=".htaccess.cps-", dir=docroot)       # random name, created exclusively
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(text.encode("utf-8", errors="surrogateescape"))
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        if gid is not None and hasattr(os, "chown"):
            try:
                os.chown(tmp, -1, gid)
            except OSError:
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _check_folder(docroot):
    try:
        st = os.lstat(docroot)
    except OSError as exc:
        raise Refused("The website's folder cannot be found (%s)." % exc.strerror)
    if not stat.S_ISDIR(st.st_mode):
        raise Refused("The website's folder is a link or not a folder. For safety nothing was changed.")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise Refused("Internal safety stop: file work must never run as root.")


def apply(docroot, block, take_over=(), give_back=False):
    """Put our block (or no block) into the file. Returns what is needed to undo it.

    block      the full text of our block, or None to remove it
    take_over  header names whose lines in the site's own text get switched off
    give_back  switch the lines we took over earlier back on (used when removing)
    """
    _check_folder(docroot)
    original = read(docroot)
    text = original or ""
    base = strip_block(text)
    taken = given = 0
    if give_back:
        base, given = give_back_lines(base)
    if take_over:
        base, taken = take_over_lines(base, take_over)
    new = compose(base, block)
    if new == text:
        return {"changed": False, "existed": original is not None, "original": original, "taken": 0, "given": 0}
    path = path_of(docroot)
    if not new.strip():
        if original is not None:
            os.unlink(path)
    else:
        mode, gid = 0o644, None
        if original is not None:
            st = os.lstat(path)
            mode, gid = stat.S_IMODE(st.st_mode), st.st_gid
        _write(docroot, new, mode, gid)
    return {"changed": True, "existed": original is not None, "original": original, "taken": taken, "given": given}


def restore(docroot, original):
    """Put the file back exactly as it was (original is None when there was no file)."""
    _check_folder(docroot)
    current = read(docroot)
    if original is None:
        if current is not None:
            os.unlink(path_of(docroot))
        return {"changed": current is not None}
    mode, gid = 0o644, None
    if current is not None:
        st = os.lstat(path_of(docroot))
        mode, gid = stat.S_IMODE(st.st_mode), st.st_gid
    _write(docroot, original, mode, gid)
    return {"changed": True}


def handle(request):
    """One request from the panel: {'op': 'apply'|'restore', 'docroot': ..., ...} -> a JSON-able answer."""
    try:
        if request.get("op") == "apply":
            return {"ok": True, **apply(request["docroot"], request.get("block"), request.get("take_over") or (),
                                        bool(request.get("give_back")))}
        if request.get("op") == "restore":
            return {"ok": True, **restore(request["docroot"], request.get("original"))}
        return {"ok": False, "error": "Unknown request."}
    except Refused as exc:
        return {"ok": False, "error": str(exc)}
    except OSError as exc:
        return {"ok": False, "error": "The file could not be changed (%s)." % (exc.strerror or exc)}
    except (KeyError, TypeError, AttributeError):
        return {"ok": False, "error": "The request was not understood."}


def main():
    """Entry point when started as the site's user: one JSON request on stdin, one JSON answer on stdout."""
    try:
        request = json.loads(sys.stdin.read())
    except ValueError:
        request = {}
    sys.stdout.write(json.dumps(handle(request)))
