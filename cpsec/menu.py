"""The terminal menu (`security`). Plain-English, numbered, and every change can be undone."""
import os
import sys
import time

from . import access, blocker, config, health, sites, updates, waf

USE_COLOR = sys.stdout.isatty()


def _c(code, text):
    return "\033[%sm%s\033[0m" % (code, text) if USE_COLOR else text


def green(t):
    return _c("32", t)


def red(t):
    return _c("31;1", t)


def yellow(t):
    return _c("33", t)


def bold(t):
    return _c("1", t)


def dim(t):
    return _c("2", t)


def heading(text):
    print()
    print(bold(text))
    print("=" * min(len(text), 72))


def say(result):
    print(green(result.message) if result.ok else red(result.message))


def ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        print()
        raise SystemExit(0)


def pause():
    try:
        input(dim("\nPress Enter to go back... "))
    except EOFError:
        pass


def yes(prompt):
    return ask(prompt + " (type yes): ").lower() == "yes"


def current_ssh_ip():
    parts = os.environ.get("SSH_CLIENT", "").split()
    return parts[0] if parts and parts[0] not in ("127.0.0.1", "::1") else None


# ----------------------------------------------------------------------------- screens
def show_health():
    data = health.overview()
    heading("HEALTH CHECK  -  " + time.strftime("%d %b %Y, %H:%M"))
    for r in data["rows"]:
        tag = {"ok": green("[ OK ]"), "bad": red("[ !! ]")}.get(r["status"], dim("[ -- ]"))
        print(" %s %-18s %s" % (tag, r["label"], r["text"]))
    for p in data["sites"]["new_problems"]:
        print("        %-36s answered %s" % (p["domain"], p["code"]))
    print("\n Blocked in the last 24 hours: %d times." % data["blocked_24h"])
    print()
    if data["problems"] == 0:
        print(green(" Everything looks fine."))
    else:
        print(red(" %d thing(s) need attention (see the lines marked [ !! ]). Menu 7 explains what to do." % data["problems"]))


def menu_blocked():
    while True:
        rows = blocker.all_blocked()
        heading("BLOCKED ADDRESSES")
        if rows is None:
            print("The attack blocker is not running, so nobody is being blocked.")
            pause()
            return
        shown = rows[:30]
        if not rows:
            print("Nobody is blocked right now.")
        else:
            print("  #  address              why                                  blocked")
            for i, r in enumerate(shown, 1):
                print("%3d  %-20s %-36s %s" % (i, r["ip"], r["why"], r["until_text"]))
            if len(rows) > len(shown):
                print("     ... and %d more (showing the first %d)" % (len(rows) - len(shown), len(shown)))
        print("\nType a number to let that address back in, or an address,")
        print("or 'all' to let everybody back in. Press Enter to go back.")
        ans = ask("> ")
        if not ans:
            return
        if ans.lower() == "all":
            if rows and yes("Let ALL %d blocked addresses back in?" % len(rows)):
                say(blocker.unban_all())
            continue
        if ans.isdigit() and 1 <= int(ans) <= len(shown):
            say(blocker.unban(shown[int(ans) - 1]["ip"]))
        else:
            say(blocker.unban(ans))


def menu_access():
    while True:
        items = access.list_admin()
        heading("ADMIN ACCESS  -  who can open CyberPanel and the other admin pages")
        print("Only these addresses can open CyberPanel, the LiteSpeed admin page and the")
        print("web terminal. Everyone else is shut out. Your websites are NOT affected.\n")
        for i, it in enumerate(items, 1):
            print("  %d) %-22s %s" % (i, it["address"], it["label"]))
        ssh_ip = current_ssh_ip()
        if ssh_ip:
            print("\n  You are connected from: %s" % ssh_ip)
        print("\n  a) My home internet address changed")
        print("  b) Add another trusted address")
        print("  c) Remove an address")
        print("  0) Back")
        ans = ask("\nChoose: ").lower()
        if ans in ("0", ""):
            return
        if ans == "a":
            print("\nSearch Google for 'what is my IP' on the connection you want to use,")
            print("then type that address here.")
            if ssh_ip:
                print("(Or just press Enter to use %s, the one you are connected from.)" % ssh_ip)
            new = ask("New home address: ") or (ssh_ip or "")
            if new:
                say(access.set_home(new))
        elif ans == "b":
            new = ask("Address to add: ")
            if new:
                label = ask("A short name for it (for example 'Office'): ") or "Added from menu"
                say(access.add_admin(new, label))
        elif ans == "c":
            n = ask("Number to remove: ")
            if not n.isdigit() or not (1 <= int(n) <= len(items)):
                continue
            target = items[int(n) - 1]
            confirmed = False
            if target["address"] == ssh_ip:
                print(yellow("That is the address you are connected from right now."))
                confirmed = True
            if yes("Remove %s (%s)?" % (target["address"], target["label"])):
                say(access.remove_admin(target["address"], ssh_ip, confirmed))


def menu_recent_blocks():
    heading("WHAT HAS BEEN BLOCKED LATELY")
    s = blocker.recent_summary()
    for label, key in (("last 24 hours", "day"), ("last 7 days", "week")):
        p = s[key]
        print("\nIn the %s: %d blocks (%d different addresses)" % (label, p["blocks"], p["addresses"]))
        for r in p["by_reason"]:
            print("    %-36s %d" % (r["why"], r["count"]))
    if s["top_addresses"]:
        print("\nMost blocked addresses this week:")
        for t in s["top_addresses"]:
            print("    %-20s blocked %d time(s)" % (t["ip"], t["times"]))
    pause()


def menu_updates():
    heading("WEBSITES WITH UPDATES WAITING")
    print("This only LOOKS. It never installs anything.")
    print("It shows what each site last found out about, so a very new update may not be listed yet.\n")
    data = updates.waiting()
    waiting = 0
    for s in data:
        if s["items"]:
            waiting += len(s["items"])
            print(bold(s["site"]))
            for it in s["items"]:
                arrow = ("%s -> %s" % (it["from"], it["to"])) if it["from"] else "-> %s (%s)" % (it["to"], it["kind"].replace("core-", ""))
                print("    - %s   %s" % (it["what"], arrow))
    if not waiting:
        print(green("No updates are waiting on the sites I could check."))
    unknown = [s["site"] for s in data if not s["checked"]]
    if unknown:
        print(yellow("\nCould not check: " + ", ".join(unknown)))
    print("\nUpdate from each site's WordPress dashboard (Dashboard > Updates), one site at a time,")
    print("and look at the site afterwards. Security updates are the important ones.")
    pause()


def menu_emergency():
    heading("EMERGENCY: STOP ALL AUTOMATIC BLOCKING")
    if blocker.jails() is not None:
        print("Automatic blocking is ON.")
        print("Stopping it lets everybody back in at once. It starts again by itself after a reboot.")
        if yes("Stop it now?"):
            say(blocker.set_running(False))
    else:
        print("Automatic blocking is OFF right now.")
        if yes("Start it again?"):
            say(blocker.set_running(True))
    pause()


def menu_help():
    heading("SOMETHING IS WRONG - WHAT DO I DO?")
    print("""
A visitor or customer cannot open a website, or cannot log in to email
    -> Menu 2. If their address is in the blocked list, let it back in.
       (They can search Google for 'what is my IP' to tell you their address.)

CyberPanel will not open (the page just waits and times out)
    -> Your home internet address probably changed. Menu 3, then a.
       If you cannot reach this menu from the web terminal either, open your server's
       console on your hosting company's website, log in as root and type:  security

"403 Forbidden" when saving a page, editing in Bricks, or paying
    -> That is the web firewall. Menu 6, then 2 shows what it caught and lets you allow it.
       To switch it off for everybody at once: menu 6, then 3, then Off.

A page looks broken right after a plugin or theme update
    -> That is the update, not the security tools. Restore the site from a backup.

Not sure whether the security tools are the cause
    -> Menu 8 stops the automatic blocker completely. If the problem goes away, it was
       the blocker. Start it again from the same menu.

The server feels slow or a site is down
    -> Menu 1 (health check) tells you at once if a website is answering badly.
""")
    pause()


# ----------------------------------------------------------------------------- web firewall
def waf_summary():
    heading("WHAT THE WEB FIREWALL HAS CAUGHT")
    s = waf.summary()
    if not s["periods"]["week"]["requests"]:
        print("Nothing recorded yet. Attacks against your websites show up here as they happen.")
        return
    for label, key in (("last 24 hours", "day"), ("last 7 days", "week")):
        p = s["periods"][key]
        tail = (", %d of them blocked" % p["blocked"]) if s["mode"] == "block" else " (none blocked: watch-only)"
        print("\nIn the %s: %d suspicious requests from %d addresses%s" % (label, p["requests"], p["addresses"], tail))
        if not p["requests"]:
            continue
        print("  What they tried:")
        for r in p["rules"][:6]:
            print("    %5d  %s (rule %s)" % (r["count"], r["message"][:60], r["rule"]))
        print("  Websites targeted most:  " + ", ".join("%s (%d)" % (x["site"], x["count"]) for x in p["sites"][:4]))
    print("\nHits from your own trusted addresses: %d" % s["trusted_hits"])
    if s["trusted_hits"]:
        print("  These are usually false alarms (you or your staff working on a site). Menu 2 lets you allow them.")


def waf_recent():
    groups = waf.recent()
    heading("RECENT HITS  -  allow the ones that are false alarms")
    if not groups:
        print("Nothing recorded yet.")
        return
    print("Hits from your own trusted addresses are listed first: those are the likely false alarms.\n")
    print("  #  website / page                                  what the rule saw                 times")
    for i, g in enumerate(groups, 1):
        flag = (" (you)" if g["trusted"] else "") + (" BLOCKED" if g["blocked"] else "")
        print("%3d  %-46s %-32s %4d%s" % (i, (g["host"] + g["path"])[:46],
                                          ("%s: %s" % (g["rule"], g["message"]))[:32], g["count"], flag))
    ans = ask("\nType a number to allow it, or press Enter to go back: ")
    if not ans.isdigit() or not (1 <= int(ans) <= len(groups)):
        return
    g = groups[int(ans) - 1]
    print("\n%s%s  -  %s" % (g["host"], g["path"], g["message"]))
    print("  1) Allow this rule on %s only" % g["host"])
    print("  2) Allow this rule on ALL websites")
    print("  3) Turn the web firewall off for %s completely" % g["host"])
    print("  0) Cancel")
    c = ask("Choose: ")
    scope = {"1": "site", "2": "all", "3": "site_off"}.get(c)
    if scope:
        print("Applying (the web server restarts gracefully, visitors do not notice)...")
        say(waf.add_exception(scope, g["host"], g["rule"]))


def waf_exceptions_menu():
    while True:
        items = waf.list_exceptions()
        heading("WEB FIREWALL EXCEPTIONS")
        if not items:
            print("No exceptions. The firewall treats every website the same.")
            pause()
            return
        for i, e in enumerate(items, 1):
            what = "firewall OFF" if e["rule"] == "ALL" else "rule %s allowed" % e["rule"]
            where = "on every website" if e["site"] == "*" else "on " + e["site"]
            print("  %d) %s %s" % (i, what, where))
        ans = ask("\nType a number to remove that exception, or press Enter to go back: ")
        if not ans.isdigit() or not (1 <= int(ans) <= len(items)):
            return
        print("Applying (the web server restarts gracefully, visitors do not notice)...")
        say(waf.remove_exception(int(ans) - 1))


def menu_waf():
    while True:
        m = waf.mode()
        heading("WEB FIREWALL")
        if m is None:
            print("The web firewall is not set up on this server.")
            pause()
            return
        print("Right now:  " + bold(waf.MODE_TEXT[m]))
        if m == "block":
            print("            strictness: refuses a request at score %d or more (5 = normal, 10 = more relaxed)" % waf.threshold())
        print("""
It looks at every request that is not served from the LiteSpeed cache and
spots typical hacking attempts (SQL injection, scripts, file tricks).
Watch only is the safe way to start: it records, but never refuses anybody.

  1) What has it caught?
  2) Recent hits - allow a false alarm
  3) Change the mode (off / watch only / blocking)
  4) Exceptions I have made
  0) Back""")
        ans = ask("\nChoose: ")
        if ans == "1":
            waf_summary()
            pause()
        elif ans == "2":
            waf_recent()
        elif ans == "3":
            print("\n  1) Off\n  2) Watch only (recommended for the first week or two)\n  3) Blocking")
            c = ask("Choose: ")
            if c in ("1", "2"):
                print("Applying (the web server restarts gracefully, visitors do not notice)...")
                say(waf.set_mode("off" if c == "1" else "watch"))
            elif c == "3":
                print("\nBlocking refuses requests that look like attacks. A harmless request can sometimes")
                print("look like one (for example saving a page with code in it), and that visitor sees")
                print("'403 Forbidden'. Use menu 2 for a week first to allow the false alarms.")
                if ask("Type BLOCK to switch it on: ") == "BLOCK":
                    t = ask("Strictness: press Enter for normal (5) or type 10 for more relaxed: ")
                    print("Applying (the web server restarts gracefully, visitors do not notice)...")
                    say(waf.set_mode("block", 10 if t == "10" else 5))
            pause()
        elif ans == "4":
            waf_exceptions_menu()
        elif ans in ("0", ""):
            return


def main_menu():
    while True:
        heading("SERVER SECURITY MENU")
        print(" 1) Health check - is everything on, and are the websites up?")
        print(" 2) Blocked addresses - see who is blocked, let someone back in")
        print(" 3) Admin access - my home internet address changed")
        print(" 4) Websites with updates waiting (only looks, installs nothing)")
        print(" 5) What has been blocked lately")
        print(" 6) Web firewall (watches for hacking attempts)")
        print(" 7) Something is wrong - what do I do?")
        print(" 8) Emergency: stop all automatic blocking")
        print(" 0) Exit")
        choice = ask("\nType a number and press Enter: ")
        if choice == "1":
            show_health()
            pause()
        elif choice == "2":
            menu_blocked()
        elif choice == "3":
            menu_access()
        elif choice == "4":
            menu_updates()
        elif choice == "5":
            menu_recent_blocks()
        elif choice == "6":
            menu_waf()
        elif choice == "7":
            menu_help()
        elif choice == "8":
            menu_emergency()
        elif choice in ("0", "q", "exit"):
            return
