# CP-Security

Protection and a simple control panel for a **CyberPanel + LiteSpeed Enterprise** web server.

It was born from a real incident (a WordPress plugin hole let an attacker take over a shared hosting
server) and packages everything that was done to clean up and harden it, so it can be repeated on any
similar server and managed without touching a terminal.

## What it protects

| Layer | What it does |
|---|---|
| **Admin lock** | CyberPanel, the LiteSpeed admin page and the web terminal only open from trusted addresses. Websites are not affected. |
| **Attack blocker** | fail2ban blocks addresses that keep guessing passwords (SSH, WordPress logins, email, FTP, the panel itself). Trusted addresses and Cloudflare are never blocked. |
| **Web firewall** | The OWASP rules inside LiteSpeed. Starts in *watch only* mode (records, never refuses) and can be switched to *blocking* once false alarms are handled. Every change restarts the web server gracefully and is undone automatically if a website stops answering. |

## Two ways to use it

* **Terminal menu** – type `security` on the server. Numbered, plain-English, everything undoable.
* **Browser panel** – the same things with buttons, on your own sub-domain and port with a Let's Encrypt
  certificate, protected by a password and a 6-digit code. The panel itself is finished; the installer that
  sets up the sub-domain, certificate and service is the next step (see [ROADMAP.md](ROADMAP.md)).

Try the panel on any computer with made-up data (nothing on the machine is touched):

```
python -m cpsec panel demo        # then open http://127.0.0.1:8765
```

## Status

Early development. See [ROADMAP.md](ROADMAP.md) for what is done and what is next, and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how it is built.

## Development

Python 3.10+, standard library only (no packages to install on the server).

```
python -m unittest discover -s tests -t .
```

Tests run anywhere (including Windows): they point the tools at a temporary folder and replace every
system command with a fake.
