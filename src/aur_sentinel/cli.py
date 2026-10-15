"""Command-line interface for AUR Sentinel."""

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Annotated

import typer

from aur_sentinel.analyzer import RiskLevel, ScanReport, analyze_pkgbuild

AUR_PLAIN_URL = "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={pkgname}"
USER_AGENT = "aur-sentinel/0.2.0 (Security Scanner for Arch Linux)"
HTTP_NOT_FOUND = 404

app = typer.Typer(add_completion=False, no_args_is_help=True)


def _fetch_pkgbuild(pkgname: str, timeout: float = 10.0) -> str:
    url = AUR_PLAIN_URL.format(pkgname=pkgname)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 # pyright: ignore[reportAny]
            raw: object = resp.read()  # pyright: ignore[reportAny]
            if isinstance(raw, bytes):
                return raw.decode("utf-8", errors="replace")
            return str(raw)
    except urllib.error.HTTPError as e:
        if e.code == HTTP_NOT_FOUND:
            typer.secho(
                f"Error: Package '{pkgname}' not found on AUR (HTTP 404)",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=2) from e
        typer.secho(f"Error fetching '{pkgname}' from AUR: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from e
    except Exception as e:
        typer.secho(f"Network error fetching '{pkgname}': {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from e


def _format_report(report: ScanReport, source_name: str, *, as_json: bool = False) -> None:
    if as_json:
        payload = {
            "target": source_name,
            "risk": report.risk.value,
            "score": report.score,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "description": f.description,
                    "score": f.score,
                    "line": f.line,
                    "evidence": f.evidence,
                }
                for f in report.findings
            ],
        }
        typer.echo(json.dumps(payload, indent=2))
        return

    color_map = {
        RiskLevel.CLEAN: typer.colors.GREEN,
        RiskLevel.LOW: typer.colors.BLUE,
        RiskLevel.MEDIUM: typer.colors.YELLOW,
        RiskLevel.HIGH: typer.colors.MAGENTA,
        RiskLevel.CRITICAL: typer.colors.RED,
    }
    color = color_map.get(report.risk, typer.colors.WHITE)

    typer.secho(f"🛡️ Target: {source_name}", bold=True)
    typer.secho(
        f"Risk: {report.risk.value.upper()} | Score: {report.score}/100",
        fg=color,
        bold=True,
    )

    if not report.findings:
        typer.secho("✅ No security threats detected.", fg=typer.colors.GREEN)
        return

    typer.echo("\nFindings:")
    for finding in report.findings:
        typer.secho(
            f"  • L{finding.line} [{finding.rule_id}] (+{finding.score})",
            fg=color,
            bold=True,
        )
        typer.echo(f"    {finding.description}")
        if finding.evidence:
            typer.echo(f"    Evidence: {finding.evidence.strip()}")


RISK_ORDER = {
    RiskLevel.CLEAN: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


@app.command()
def scan(
    pkgbuild: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, help="Path to PKGBUILD file"),
    ],
    max_risk: Annotated[
        RiskLevel | None,
        typer.Option(
            "--max-risk",
            "-m",
            help="Maximum acceptable risk. Exits with code 1 if exceeded.",
        ),
    ] = None,
    json_output: Annotated[  # noqa: FBT002
        bool,
        typer.Option("--json", help="Output report in JSON format"),
    ] = False,
) -> None:
    """Scan a local PKGBUILD and print its security risk report."""
    content = pkgbuild.read_text(encoding="utf-8")
    report = analyze_pkgbuild(content)
    _format_report(report, str(pkgbuild), as_json=json_output)

    if max_risk is not None and RISK_ORDER[report.risk] > RISK_ORDER[max_risk]:
        raise typer.Exit(code=1)


@app.command()
def check(
    pkgname: Annotated[str, typer.Argument(help="Name of AUR package to download and scan")],
    max_risk: Annotated[
        RiskLevel | None,
        typer.Option(
            "--max-risk",
            "-m",
            help="Maximum acceptable risk. Exits with code 1 if exceeded.",
        ),
    ] = None,
    json_output: Annotated[  # noqa: FBT002
        bool,
        typer.Option("--json", help="Output report in JSON format"),
    ] = False,
) -> None:
    """Download a PKGBUILD from the AUR and scan it in one step."""
    content = _fetch_pkgbuild(pkgname)
    report = analyze_pkgbuild(content)
    _format_report(report, f"AUR:{pkgname}", as_json=json_output)

    if max_risk is not None and RISK_ORDER[report.risk] > RISK_ORDER[max_risk]:
        raise typer.Exit(code=1)


@app.command()
def fetch(
    pkgname: Annotated[str, typer.Argument(help="Name of AUR package to download")],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="File path to save the PKGBUILD"),
    ] = None,
) -> None:
    """Download a PKGBUILD directly from the AUR without cloning."""
    content = _fetch_pkgbuild(pkgname)
    target = output or Path(f"PKGBUILD.{pkgname}")
    _ = target.write_text(content, encoding="utf-8")
    typer.echo(f"Saved PKGBUILD for '{pkgname}' to {target}")


@app.command()
def hook() -> None:
    """Display instructions and helper scripts to integrate AUR Sentinel into yay or paru."""
    typer.echo(
        """
🛡️ AUR Sentinel - AUR Helper Integration Guide:

1. As a pre-build validator for yay / paru:
   In your ~/.config/paru/paru.conf:
   [options]
   # Set makepkg wrapper or review command:
   # aur-sentinel check <pkg> --max-risk medium

2. Automated makepkg wrapper script:
   Save this script as ~/bin/aur-sentinel-makepkg:
   -------------------------------------------------
   #!/bin/bash
   if [ -f PKGBUILD ]; then
       aur-sentinel scan PKGBUILD --max-risk medium || {
           echo "🚨 AUR Sentinel: High risk detected in PKGBUILD! Aborting build."
           exit 1
       }
   fi
   exec makepkg "$@"
   -------------------------------------------------
   Make it executable: chmod +x ~/bin/aur-sentinel-makepkg
        """.strip()
    )
