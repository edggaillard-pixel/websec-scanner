"""Optional Streamlit dashboard.

Run with::

    pip install "websec-scanner[dashboard]"
    streamlit run -m websec_scanner.dashboard
    # or: streamlit run src/websec_scanner/dashboard.py

It is a thin front-end over the same core library: it never bypasses the
authorisation gate. Streamlit is an optional dependency, so importing this
module without it raises a clear error.
"""

from __future__ import annotations

try:
    import streamlit as st
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit(
        "Streamlit is not installed. Install the optional dependency with:\n"
        '    pip install "websec-scanner[dashboard]"'
    ) from exc

from .core import ScanConfig, Scanner, registered_ids
from .core.context import DEFAULT_USER_AGENT
from .reporting import render_html

_RISK_COLOR = {"low": "#2ea043", "medium": "#c9a227", "high": "#b4232a"}


def _run() -> None:
    st.set_page_config(page_title="websec-scanner", page_icon="🛡️", layout="wide")
    st.title("🛡️ websec-scanner")
    st.caption("Non-destructive web security posture scanner")

    with st.sidebar:
        st.header("Scan configuration")
        raw_targets = st.text_area("Targets (one per line)", "https://example.com")
        lang = st.selectbox("Report language", ["en", "fr"], index=0)
        timeout = st.slider("Timeout (s)", 1.0, 30.0, 10.0)
        rate_limit = st.slider("Rate limit between requests (s)", 0.0, 2.0, 0.0, 0.1)
        threads = st.slider("Threads", 1, 16, 8)
        checks = st.multiselect("Checks", registered_ids(), default=registered_ids())
        verify_tls = not st.checkbox("Disable TLS verification (--insecure)", value=False)
        authorized = st.checkbox(
            "I am authorised to scan these targets", value=False
        )
        run = st.button("Run scan", type="primary", disabled=not authorized)

    if not authorized:
        st.info("Tick the authorisation box in the sidebar to enable scanning.")
        return
    if not run:
        return

    targets = [t.strip() for t in raw_targets.splitlines() if t.strip()]
    if not targets:
        st.warning("Provide at least one target.")
        return

    config = ScanConfig(
        authorized=True,
        timeout=timeout,
        rate_limit_delay=rate_limit,
        threads=threads,
        user_agent=DEFAULT_USER_AGENT,
        verify_tls=verify_tls,
        lang=lang,
        enabled_checks=checks or None,
    )
    with st.spinner(f"Scanning {len(targets)} target(s)…"):
        result = Scanner(config).scan(targets)

    for t in result.targets:
        level = t.score.level.value if t.score else "low"
        color = _RISK_COLOR.get(level, "#888")
        st.markdown(
            f"### {t.target} "
            f"<span style='background:{color};color:#fff;padding:2px 10px;"
            f"border-radius:10px;font-size:0.7em'>{level.upper()}</span>",
            unsafe_allow_html=True,
        )
        if t.score:
            cols = st.columns(6)
            cols[0].metric("Score", f"{t.score.score_0_100}/100")
            for i, (sev, n) in enumerate(t.score.counts.items(), start=1):
                cols[i].metric(sev.capitalize(), n)
        if t.errors:
            for e in t.errors:
                st.warning(e)
        if t.findings:
            st.dataframe(
                [
                    {
                        "Severity": f.severity.label.upper(),
                        "Finding": f.title,
                        "OWASP": f.owasp,
                        "CWE": f.cwe,
                        "Recommendation": f.recommendation,
                    }
                    for f in t.findings
                ],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.success("No findings.")

    st.download_button(
        "Download HTML report",
        data=render_html(result, lang=lang),
        file_name="websec-report.html",
        mime="text/html",
    )


# Streamlit executes the module top-to-bottom.
_run()

# GROGNON
