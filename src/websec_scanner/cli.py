"""Command-line interface (Typer + Rich).

Design notes:
* The ``--authorized`` flag is mandatory. Scanning a system without permission is
  illegal in most jurisdictions; the tool refuses to run without an explicit
  acknowledgement, printed prominently.
* Targets come from positional arguments and/or a ``--targets-file``.
* Output goes to the terminal (a coloured Rich table) and, optionally, to JSON
  and/or HTML files.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from . import __version__
from .core import ScanConfig, Scanner, registered_ids
from .core.context import DEFAULT_USER_AGENT
from .core.models import RiskLevel, ScanResult
from .reporting import write_html, write_json

app = typer.Typer(
    add_completion=False,
    help="Non-destructive web security posture scanner.",
    rich_markup_mode="rich",
)
console = Console()
err_console = Console(stderr=True)

_RISK_STYLE = {
    RiskLevel.LOW.value: "bold green",
    RiskLevel.MEDIUM.value: "bold yellow",
    RiskLevel.HIGH.value: "bold red",
}
_SEV_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"websec-scanner {__version__}")
        raise typer.Exit()


def _collect_targets(targets: list[str], targets_file: Path | None) -> list[str]:
    collected = list(targets)
    if targets_file:
        for line in targets_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                collected.append(line)
    # De-duplicate, keep order.
    seen: set[str] = set()
    unique = []
    for t in collected:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


@app.command()
def scan(
    targets: list[str] = typer.Argument(None, help="Target URLs or hostnames."),
    authorized: bool = typer.Option(
        False, "--authorized", help="Confirm you are authorised to scan the targets. REQUIRED."
    ),
    targets_file: Path = typer.Option(
        None, "--targets-file", "-f", help="File with one target per line (# comments allowed)."
    ),
    json_out: Path = typer.Option(None, "--json", help="Write a JSON report to this path."),
    html_out: Path = typer.Option(None, "--html", help="Write an HTML report to this path."),
    lang: str = typer.Option("en", "--lang", help="Report language: en or fr."),
    timeout: float = typer.Option(10.0, "--timeout", help="Per-request timeout in seconds."),
    rate_limit: float = typer.Option(
        0.0, "--rate-limit", help="Minimum delay (s) between requests to a host."
    ),
    threads: int = typer.Option(8, "--threads", help="Max concurrent workers."),
    user_agent: str = typer.Option(DEFAULT_USER_AGENT, "--user-agent", help="User-Agent header."),
    insecure: bool = typer.Option(
        False, "--insecure", help="Do not verify TLS when fetching pages (TLS check still runs)."
    ),
    wordlist: Path = typer.Option(
        None, "--wordlist", help="Extra wordlist for exposed-files (path category per line)."
    ),
    only: str = typer.Option(None, "--only", help="Comma-separated check ids to run exclusively."),
    skip: str = typer.Option(None, "--skip", help="Comma-separated check ids to skip."),
    list_checks: bool = typer.Option(False, "--list-checks", help="List available checks and exit."),
    version: bool = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """Scan one or more web targets and report their security posture."""
    if list_checks:
        _print_checks()
        raise typer.Exit()

    all_targets = _collect_targets(targets or [], targets_file)
    if not all_targets:
        err_console.print("[red]No targets provided.[/red] Pass URLs or --targets-file.")
        raise typer.Exit(code=2)

    if not authorized:
        err_console.print(
            Panel.fit(
                "[bold red]Refusing to scan without authorisation.[/bold red]\n"
                "Only scan systems you own or are explicitly permitted to test.\n"
                "Re-run with [bold]--authorized[/bold] to confirm.",
                title="Authorisation required",
                border_style="red",
            )
        )
        raise typer.Exit(code=3)

    enabled = _resolve_enabled(only, skip)

    config = ScanConfig(
        authorized=authorized,
        timeout=timeout,
        rate_limit_delay=rate_limit,
        threads=threads,
        user_agent=user_agent,
        verify_tls=not insecure,
        lang=lang if lang in ("en", "fr") else "en",
        wordlist=str(wordlist) if wordlist else None,
        enabled_checks=enabled,
    )

    scanner = Scanner(config)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(f"Scanning {len(all_targets)} target(s)…", total=None)
        result = scanner.scan(all_targets)

    _print_result(result)

    if json_out:
        write_json(result, json_out)
        console.print(f"[green]JSON report written to[/green] {json_out}")
    if html_out:
        write_html(result, html_out, lang=config.lang)
        console.print(f"[green]HTML report written to[/green] {html_out}")

    # Exit code reflects worst risk level: 0 low, 1 medium, 2 high.
    raise typer.Exit(code=_exit_code(result))


# -- rendering helpers ------------------------------------------------------
def _resolve_enabled(only: str | None, skip: str | None) -> list[str] | None:
    ids = registered_ids()
    if only:
        wanted = [c.strip() for c in only.split(",") if c.strip()]
        return [c for c in ids if c in wanted]
    if skip:
        drop = {c.strip() for c in skip.split(",")}
        return [c for c in ids if c not in drop]
    return None


def _print_checks() -> None:
    from .core.registry import get_checks

    table = Table(title="Available checks")
    table.add_column("id", style="cyan")
    table.add_column("name")
    table.add_column("description", style="dim")
    for check in get_checks():
        table.add_row(check.id, check.name, check.description)
    console.print(table)


def _print_result(result: ScanResult) -> None:
    for t in result.targets:
        level = t.score.level.value if t.score else "low"
        style = _RISK_STYLE.get(level, "white")
        header = (
            f"[bold]{t.target}[/bold]  "
            f"[{style}]{level.upper()}[/{style}]  "
            f"(score {t.score.score_0_100 if t.score else 0}/100)"
        )
        console.print()
        console.print(header)
        if t.errors:
            for e in t.errors:
                console.print(f"  [yellow]! {e}[/yellow]")
        if not t.findings:
            console.print("  [green]No findings.[/green]")
            continue
        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
        table.add_column("Severity", width=10)
        table.add_column("Finding")
        table.add_column("Refs", style="dim")
        for f in t.findings:
            sev_style = _SEV_STYLE.get(f.severity.label, "white")
            refs = " ".join(x for x in (f.owasp, f.cwe) if x)
            table.add_row(
                f"[{sev_style}]{f.severity.label.upper()}[/{sev_style}]",
                f.title,
                refs,
            )
        console.print(table)


def _exit_code(result: ScanResult) -> int:
    worst = RiskLevel.LOW
    order = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2}
    for t in result.targets:
        if t.score and order[t.score.level] > order[worst]:
            worst = t.score.level
    return order[worst]


def main() -> None:  # console-script friendly entrypoint
    app()


if __name__ == "__main__":
    sys.exit(app())  # pragma: no cover

# GROGNON
