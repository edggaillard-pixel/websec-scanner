websec-scanner
==============

I put this together as a portfolio project while learning cybersecurity. It's a
small command-line tool that points at a website and tells you how well it's
locked down: missing security headers, a sloppy TLS config, files that really
shouldn't be public, and so on. It never does anything destructive, it just
sends normal GET requests and reads what comes back.

Honestly the idea came from redoing the same manual checks over and over
(curl -I, poking at /.git/, squinting at the CSP by hand) and wanting something
that does the boring part for me and spits out a clean report.

A screenshot of the HTML report is in docs/report_screenshot.png.


What it actually checks
-----------------------

- Security headers: HSTS (and whether the policy is any good), X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- The CSP, a bit more thoroughly than just "is it there": unsafe-inline,
  unsafe-eval, wildcard sources, missing default-src / base-uri.
- Cookie flags: Secure, HttpOnly, SameSite.
- TLS: certificate expiry, trust chain, hostname match, and whether the server
  still accepts ancient TLS 1.0 / 1.1.
- robots.txt: disallowed paths that basically point a finger at the sensitive
  areas.
- Exposed files: /.git/, .env, backups, wp-config.php and the usual suspects. It
  first learns how the site answers for pages that don't exist (soft-404
  calibration) so it doesn't scream about false positives on sites that return
  200 for everything.
- Leaky banners: Server / X-Powered-By headers giving away version numbers.

Each finding is tagged with an OWASP Top 10 (2021) category and a CWE, and comes
with a short "here's how to fix it" line.


Getting it running
------------------

    git clone https://github.com/edggaillard-pixel/websec-scanner.git
    cd websec-scanner
    python -m venv .venv
    .venv\Scripts\activate          (Windows)
    source .venv/bin/activate       (macOS / Linux)
    pip install -e .

Needs Python 3.11+.

One important thing: only run this against things you own or are allowed to
test. Scanning random sites without permission is illegal in France (and most
places), so the tool flatly refuses to start unless you pass --authorized.
That's deliberate.

    # the basics
    websec-scan https://example.com --authorized

    # save reports, in French
    websec-scan https://example.com --authorized --json report.json --html report.html --lang fr

    # a bunch of targets from a file, being polite about it
    websec-scan --authorized -f targets.txt --rate-limit 0.5

    # just some checks
    websec-scan https://example.com --authorized --only security_headers,csp,tls

    # what checks exist?
    websec-scan --list-checks

Exit codes are handy for CI: 0 = low risk, 1 = medium, 2 = high, 3 = you forgot
--authorized.


Want to try it without a real target?
-------------------------------------

There's a deliberately broken little server in examples/ so you can see the
scanner light up without touching anything you don't own:

    python examples/vulnerable_server.py --port 8099
    # then, in another terminal:
    websec-scan http://127.0.0.1:8099 --authorized --html report.html

You can also throw it at OWASP Juice Shop with the docker-compose.yml in there if
you'd rather test against something more realistic. There are sample reports in
examples/ too (JSON + HTML, English and French) from a real run against the
broken server.


How the score works
-------------------

I kept this dead simple on purpose, mostly so I can explain it out loud in an
interview. Every finding has a weight (info 0, low 3, medium 8, high 20,
critical 40). They get added up, and the total lands in Low / Medium / High. The
one twist: a single critical finding (an exposed .git, say) drags the whole
thing to High no matter what else is going on. The thresholds live in
core/scoring.py if you want to tweak them.


How it's put together
---------------------

The core library (core/) doesn't know anything about the CLI, so you can just
import it and use it in your own code:

    from websec_scanner.core import Scanner, ScanConfig
    from websec_scanner.reporting import render_json

    result = Scanner(ScanConfig(authorized=True)).scan(["https://example.com"])
    print(render_json(result))

Checks live in checks/, one file each, and they register themselves
automatically, so adding a new one is genuinely a one-file job. There's a
walkthrough in docs/EXTENDING.md.


What it won't do
----------------

It's a posture / attack-surface scanner, not a pentest framework. No crawling,
no logging in, no payloads, so don't expect it to find SQL injection or XSS. The
output is a prioritised hardening checklist, not a certificate that says you're
safe.


Dev stuff
---------

    pip install -e ".[dev]"
    pytest -q          (30 tests, all mocked, runs offline)
    ruff check src tests

GitHub Actions runs ruff + pytest on 3.11 and 3.12 on every push.


License
-------

MIT.

# GROGNON
