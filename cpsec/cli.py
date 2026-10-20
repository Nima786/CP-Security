"""Command line entry point: `security` opens the menu, `security <command>` does one thing."""
import os
import sys

from . import __version__, access, blocker, menu, provision, selfupdate, sites, waf

USAGE = """security  -  the server security menu.

Open it with:       security
Quick commands:     security status            health check
                    security blocked           see who is blocked
                    security unblock 1.2.3.4   let one address back in
                    security myip 1.2.3.4      my home internet address changed
                    security firewall watch    web firewall: off | watch | block
                    security serverfw          the server firewall: status | on | off | reload | keep | undo
                    security updates           which sites have updates waiting (only looks)
                    security advice            what to improve, and other security tools found
                    security setup             show the plan and set up what is missing (--yes: no questions)
                    security selftest          prove the web firewall sees attacks
                    security panel ...         the browser panel (see: security panel help)
                    security update            look for a newer version and install it (--check: only look)
                    security install           install the panel (asks a few questions)
                    security uninstall         take the panel away again (--purge: delete settings too)
"""


def _print(result):
    print(result.message)
    return 0 if result.ok else 1


def _update(options):
    """security update [--check] [--yes] [--force]"""
    updater = selfupdate.Updater()
    found = updater.check()
    print(found.message)
    if not found.ok or "--check" in options:
        return 0 if found.ok else 1
    state = updater.state()
    force = "--force" in options
    if not (state["available"] or force):
        return 0
    if state["notes"]:
        print("\nWhat is new:\n" + state["notes"])
    if "--yes" not in options and menu.ask("\nInstall version %s now? The panel restarts for a few seconds. (yes/no): " % state["latest"]).lower() != "yes":
        return 1
    res = updater.install(state["latest"], force=force, background=False)
    for line in updater.state()["job"]["log"]:
        print("  " + line)
    print(res.message if not res.ok else updater.state()["job"]["message"])
    return 0 if res.ok and updater.state()["job"]["status"] != "failed" else 1


def _serverfw(options):
    """security serverfw [status|on|off|reload|keep|undo|revert]  -  the server firewall (the panel has the same buttons)."""
    from . import serverfw
    action = options[0] if options else "status"
    if action == "status":
        st = serverfw.state()
        t = st["truth"]
        print("Server firewall: " + ("ON" if st["loaded"] else "off") + "  (" + t["verdict"]["text"] + ")")
        print("CyberPanel's page: " + t["cyberpanel"]["text"])
        print("%d rule%s on your list; %d in-use port%s not on it yet." % (
            len(st["rules"]), "" if len(st["rules"]) == 1 else "s", len(st["suggestions"]), "" if len(st["suggestions"]) == 1 else "s"))
        if st["pending"]:
            print("Waiting for 'keep' (%d seconds left), then it undoes itself." % st["pending"]["seconds_left"])
        return 0
    if action == "on":
        return _print(serverfw.power("on", add_in_use=True, confirmed=True))
    if action in ("off", "reload"):
        return _print(serverfw.power(action))
    if action == "keep":
        return _print(serverfw.confirm())
    if action in ("undo", "revert"):
        return _print(serverfw.revert())
    print("Use:  security serverfw status | on | off | reload | keep | undo")
    return 1


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if hasattr(os, "geteuid") and os.geteuid() != 0 and not os.environ.get("CPSEC_ROOT"):
        print("Please run this as root (log in as root, or put 'sudo' in front).")
        return 1
    if not args:
        menu.main_menu()
        return 0
    cmd = args[0]
    if cmd in ("status", "health"):
        menu.show_health()
    elif cmd == "blocked":
        rows = blocker.all_blocked()
        if rows is None:
            print("The attack blocker is not running.")
        for r in rows or []:
            print("%-20s %-36s %s" % (r["ip"], r["why"], r["until_text"]))
    elif cmd == "unblock" and len(args) == 2:
        return _print(blocker.unban(args[1]))
    elif cmd == "myip" and len(args) == 2:
        return _print(access.set_home(args[1]))
    elif cmd == "firewall" and len(args) == 2 and args[1] in ("off", "watch", "block"):
        return _print(waf.set_mode(args[1]))
    elif cmd == "firewall":
        print("Web firewall: " + waf.MODE_TEXT.get(waf.mode() or "", "not set up"))
        print("Change it with:  security firewall off|watch|block")
    elif cmd == "serverfw":
        return _serverfw(args[1:])
    elif cmd == "updates":
        menu.menu_updates()
    elif cmd == "apply":
        return _print(access.apply())
    elif cmd == "baseline":
        r = sites.save_baseline()
        print("Saved how %d websites answer today (%d answering normally)." % (r["total"], r["normal"]))
    elif cmd == "advice":
        return menu.show_advice()
    elif cmd == "setup":
        return menu.run_setup(assume_yes="--yes" in args)
    elif cmd == "selftest":
        return _print(waf.selftest())
    elif cmd == "update":
        return _update(args[1:])
    elif cmd == "post-update":
        for line in provision.refresh_after_update():
            print("refreshed: " + line)
    elif cmd == "install":
        from . import installer
        return installer.main(args[1:])
    elif cmd == "uninstall":
        from . import installer
        return installer.main_uninstall(args[1:])
    elif cmd == "panel":
        from .panel import cli as panel_cli
        return panel_cli.main(args[1:])
    elif cmd in ("--version", "version"):
        print("CP-Security " + __version__)
    else:
        print(USAGE)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
