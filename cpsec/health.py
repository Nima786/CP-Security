"""One overall picture: is everything on, and are the websites up?"""
import time

from . import access, blocker, sites, waf


def _row(key, label, status, text):
    # status: ok | bad | off  (off = switched off or not set up, but not a problem)
    return {"key": key, "label": label, "status": status, "text": text}


def overview(site_results=None):
    rows, problems = [], 0

    st = blocker.status()
    if not st["installed"] or not st["running"]:
        rows.append(_row("blocker", "Attack blocker", "bad", "Not running. Automatic blocking is off."))
        problems += 1
    else:
        rows.append(_row("blocker", "Attack blocker", "ok", "Running, %d protections on, %d addresses blocked right now"
                         % (len(st["jails"]), st["banned_now"])))
        if not st["enabled_at_boot"]:
            rows.append(_row("blocker_boot", "Blocker at reboot", "bad", "Will NOT start again after a reboot"))
            problems += 1
        if st["recent_errors"]:
            rows.append(_row("blocker_errors", "Blocker errors", "bad", "The blocker logged an internal error in the last day"))
            problems += 1

    if st["feed_active"]:
        rows.append(_row("feed", "Login watcher", "ok", "Copying WordPress login attempts for the blocker"))
    else:
        rows.append(_row("feed", "Login watcher", "bad", "Not running: WordPress login guessing is not being blocked"))
        problems += 1

    n = len(access.list_admin())
    if access.lock_is_live():
        rows.append(_row("lock", "Admin pages", "ok", "Locked: only %d trusted addresses can open them" % n))
    else:
        rows.append(_row("lock", "Admin pages", "bad", "NOT locked (the admin lock rules are missing)"))
        problems += 1

    ok, text = waf.state()
    rows.append(_row("waf", "Web firewall", "ok" if ok else "off", text))

    summary = sites.summarize(site_results)
    if summary["new_problems"]:
        rows.append(_row("sites", "Websites", "bad", "%d website(s) have a NEW problem" % len(summary["new_problems"])))
        problems += 1
    else:
        text = "%d of %d answering normally" % (summary["normal"], summary["total"])
        if summary["old_problems"]:
            text += " (%d were already giving an error before the protection, unchanged)" % len(summary["old_problems"])
        rows.append(_row("sites", "Websites", "ok", text))

    return {
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "problems": problems,
        "rows": rows,
        "sites": summary,
        "blocked_24h": len(blocker.ban_events(1)) if st["installed"] else 0,
        "waf_mode": waf.mode(),
    }
