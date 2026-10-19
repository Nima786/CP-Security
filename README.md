# CP-Security

Protection and a simple control panel for a **CyberPanel** server, on **LiteSpeed Enterprise or OpenLiteSpeed**.

It was born from a real incident (a WordPress plugin hole let an attacker take over a shared hosting
server) and packages everything that was done to clean up and harden it, so it can be repeated on any
CyberPanel server and managed from a browser without touching a terminal.

## What it does

| Layer | What it does |
|---|---|
| **Admin lock** | CyberPanel, the LiteSpeed admin page, the web terminal and (optionally) this panel only open from trusted addresses. Websites are not affected. |
| **Attack blocker** | fail2ban blocks addresses that keep guessing passwords (SSH, WordPress logins, email, FTP, the panel itself). Trusted addresses and Cloudflare are never blocked. How strict it is can be changed in the panel. |
| **Web firewall** | The OWASP rules inside the web server. Starts in *watch only* mode (records, never refuses) and can be switched to *blocking* once false alarms are handled. Every change restarts the web server gracefully and is undone automatically if a website stops answering. A built-in test proves the firewall really sees attacks. |
| **Advisor** | Looks at the whole server and tells you what to do: notices CyberPanel's own ModSecurity rules, Imunify, CSF, other fail2ban jails, Cloudflare-proxied sites, SSH passwords, open databases, missing OS updates, WordPress updates, an expiring certificate. A few safe fixes have a button. |
| **Setup** | A plan you can read first, then one button. Each step undoes itself if something goes wrong, and the whole thing is safe to run again. |

### It does not fight CyberPanel

* If CyberPanel's own ModSecurity rule pack (OWASP or Comodo) is switched on, CP-Security does **not** add its
  own rules on top (two copies use the same rule numbers and cannot run together). The Advisor tells you.
* Only one line is added to the web server's own settings file. CP-Security keeps its own settings in its own
  folder, so CyberPanel's pages keep working.
* Its fail2ban files are all named `cps-*`; protections that belong to someone else are left alone.

## Install

On the server, as root:

```
curl -fsSL https://github.com/Nima786/CP-Security/releases/latest/download/install.sh | sh
```

This installs the newest **numbered release** (never whatever happens to be on the main branch) and checks the
download against the release's published fingerprint. To install one fixed version, use that release's own
address, for example `.../releases/download/v0.2.0/install.sh`.

It asks for a **sub-domain** (for example `security.example.com`, with a DNS record pointing to the server),
a **port**, an **email address** for Let's Encrypt, a **username and password**, and which **addresses are
trusted** (your current address is offered). Then it:

1. asks CyberPanel to create the sub-domain's site and issue the Let's Encrypt certificate,
2. opens the port in firewalld/ufw if one is on,
3. sets up the admin lock, the attack blocker, the login watcher and the web firewall (watch-only),
4. starts the panel on `https://your-subdomain:port`.

Behind Cloudflare's orange cloud only a few ports work; the installer tells you which. Prefer "DNS only".

Panel login is **username + password**. By default the panel opens **only from trusted addresses**, so
strangers cannot even see the login page. If your internet address changes, run on the server:

```
security myip YOUR.NEW.ADDRESS
```

An optional authenticator-app code can be switched on in Settings. Without a question-and-answer session:
`python3 -m cpsec install --help`. To remove it again: `security uninstall`.

## Two ways to use it

* **Terminal menu** – type `security` on the server. Numbered, plain-English, everything undoable.
  `security advice`, `security setup`, `security selftest` do one thing each.
* **Browser panel** – the same things with buttons: Overview · Advisor · Blocked · Admin access ·
  Web firewall · Updates · Setup · Settings.

Try the panel on any computer with made-up data (nothing on the machine is touched):

```
python -m cpsec panel demo        # then open http://127.0.0.1:8765
```

## Status

Version 0.2. Tested on **LiteSpeed Enterprise** on Ubuntu 22.04. **OpenLiteSpeed** support follows CyberPanel's
own file layout and is covered by tests against pretend file trees, but has **not been run on a live
OpenLiteSpeed server yet**: the web firewall step checks itself (a test attack must show up in the log, a
website must still answer) and undoes itself if it does not. See [ROADMAP.md](ROADMAP.md) and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development

Python 3.10+, standard library only (no packages to install on the server).

```
python -m unittest discover -s tests -t .
```

Tests run anywhere (including Windows): they point the tools at a temporary folder and replace every
system command with a fake.
