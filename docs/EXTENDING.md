# Extending the scanner

Adding a new detection module is a **one-file operation**. Drop a module in
`src/websec_scanner/checks/`, subclass `Check`, decorate it with `@register`, and
it is discovered automatically the next time the scanner runs. No central list to
edit.

## 1. Declare your findings in the catalogue

All user-facing wording and all security metadata (severity, OWASP category, CWE)
live in **one** place: `src/websec_scanner/core/catalog.py`. A check never
hard-codes a sentence — it references a catalogue entry by id. This keeps the
knowledge base auditable and makes bilingual (fr/en) output automatic.

Add an entry to the `CATALOG` dict:

```python
"missing_coep": _d(
    id="missing_coep",
    severity=Severity.LOW,
    owasp="A05:2021",
    cwe="CWE-693",
    title={"en": "No Cross-Origin-Embedder-Policy", "fr": "Cross-Origin-Embedder-Policy absent"},
    description={
        "en": "COEP is not set, so the page cannot use cross-origin isolation.",
        "fr": "COEP n'est pas défini : la page ne peut pas bénéficier de l'isolation cross-origin.",
    },
    recommendation={
        "en": "Send 'Cross-Origin-Embedder-Policy: require-corp'.",
        "fr": "Envoyez 'Cross-Origin-Embedder-Policy: require-corp'.",
    },
),
```

Templates may contain `{placeholders}`; you fill them when creating the finding
(see below). Severity drives the default scoring weight — see
`core/models.py::Severity` and `core/scoring.py`.

## 2. Write the check

Create `src/websec_scanner/checks/coep.py`:

```python
from ..core.catalog import make_finding
from ..core.context import ScanContext
from ..core.models import Finding
from ..core.registry import Check, register


@register
class CoepCheck(Check):
    id = "coep"                      # unique; used by --only/--skip and reports
    name = "Cross-Origin-Embedder-Policy"
    description = "Checks for the COEP response header."

    def run(self, ctx: ScanContext) -> list[Finding]:
        resp = ctx.base_response
        if resp is None:
            return []
        if "cross-origin-embedder-policy" in resp.headers:
            return []
        return [make_finding("missing_coep", check=self.id, lang=ctx.lang)]
```

That's it. Run `websec-scan --list-checks` and `coep` will be listed.

## What the context gives you

A `ScanContext` (see `core/context.py`) carries everything a check needs:

| Attribute            | Description                                                        |
| -------------------- | ----------------------------------------------------------------- |
| `ctx.target`         | Normalised target URL.                                             |
| `ctx.base_response`  | The home-page GET, fetched **once** and shared. May be `None`.     |
| `ctx.client`         | A polite `HttpClient` (timeout, User-Agent, rate-limit, redirects).|
| `ctx.config`         | The `ScanConfig` (lang, threads, wordlist, verify_tls, …).         |
| `ctx.host` / `port`  | Parsed host and port.                                              |
| `ctx.is_https`       | Whether the target is HTTPS.                                       |
| `ctx.lang`           | `"en"` or `"fr"` — pass it to `make_finding`.                      |
| `ctx.errors`         | Append non-fatal messages here; they surface in the report.       |

### Making your own HTTP requests

Use `ctx.client` so your requests inherit the timeout, identifiable User-Agent
and per-host rate limiting:

```python
resp = ctx.client.safe_get("/.well-known/security.txt")  # returns None on error
if resp and resp.status_code == 200:
    ...
```

`safe_get` never raises; use `ctx.client.get(...)` if you want to handle
`HttpClientError` yourself.

## `make_finding` reference

```python
make_finding(
    finding_id,            # key in CATALOG
    *,
    check=self.id,         # your check id
    lang=ctx.lang,         # 'en' | 'fr'
    severity=None,         # optional: override the catalogue default
    weight=None,           # optional: override the scoring weight
    evidence={...},        # machine-readable details (stored verbatim)
    **params,              # values for {placeholders} in the templates
)
```

Put raw, structured data (header values, matched paths, status codes) in
`evidence` — it is rendered in the report's collapsible "Evidence" section and is
invaluable when triaging.

## Conventions & tips

- **Isolation.** A check that raises is caught by the scanner: the failure is
  recorded on the target's `errors` and the other checks still run. Still, prefer
  returning `[]` over raising for "nothing to report".
- **One concern per module.** CSP lives in `csp.py`, cookies in `cookies.py`,
  etc. It keeps modules short and testable.
- **Aggregate noisy findings.** If a check can fire many times (e.g. per cookie),
  aggregate into one finding listing all affected items (see `cookies.py`).
- **Stay non-destructive.** Only safe GETs. No crawling, no form submission, no
  payload injection — that is out of scope by design.
- **Severity & weight.** Reserve `CRITICAL` for findings that justify forcing the
  whole target to HIGH risk (a single critical does so — see the scoring rules).

## 3. Test it

Add a test under `tests/`. Header-based checks can use the `ctx_factory` fixture
(synthetic responses); checks that make their own requests can use `respx` to
mock the transport. See `tests/test_header_checks.py` and
`tests/test_network_checks.py` for patterns.

```python
def test_missing_coep(ctx_factory):
    ctx = ctx_factory(headers={})
    findings = CoepCheck().run(ctx)
    assert {f.id for f in findings} == {"missing_coep"}
```

Run the suite:

```bash
pytest -q
```
