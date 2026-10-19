"""The websites on this server and whether they are answering."""
import glob
import os
from concurrent.futures import ThreadPoolExecutor

from . import config, util


def list_sites():
    return sorted(os.path.basename(os.path.dirname(p)) for p in glob.glob(config.P.home_dir + "/*/public_html"))


def check_site(domain):
    """Ask the local web server for the home page. Returns (domain, 'HTTP status' or '000')."""
    rc, out = util.run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                        "--resolve", "%s:443:127.0.0.1" % domain, "https://%s/" % domain,
                        "--max-time", "15"], timeout=25)
    code = out.strip()[-3:] if rc == 0 else "000"
    return domain, code


def check_sites(domains=None):
    domains = list_sites() if domains is None else domains
    with ThreadPoolExecutor(max_workers=6) as ex:
        return list(ex.map(check_site, domains))


def is_ok(code):
    return code[:1] in ("2", "3")


def load_baseline():
    return util.read_json(config.P.baseline, {})


def save_baseline(results=None):
    """Remember how every website answers today, so later problems can be told apart from old ones."""
    results = check_sites() if results is None else results
    util.write_json(config.P.baseline, dict(results))
    good = sum(1 for _, c in results if is_ok(c))
    return {"total": len(results), "normal": good}


def summarize(results=None):
    """{'total', 'normal', 'new_problems', 'old_problems'} comparing today with the saved baseline."""
    results = check_sites() if results is None else results
    base = load_baseline()
    new_bad, old_bad = [], []
    for domain, code in results:
        if is_ok(code):
            continue
        (old_bad if base.get(domain) == code else new_bad).append({"domain": domain, "code": code})
    return {"total": len(results), "normal": len(results) - len(new_bad) - len(old_bad),
            "new_problems": new_bad, "old_problems": old_bad,
            "sites": [{"domain": d, "code": c, "ok": is_ok(c)} for d, c in results]}


def sample_for_check(limit=8):
    """A few websites that normally answer, used to confirm a change did not break anything."""
    base = load_baseline()
    good = [d for d, c in sorted(base.items()) if is_ok(c)]
    return (good or list_sites())[:limit]
