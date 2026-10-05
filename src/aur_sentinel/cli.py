"""Command-line interface for AUR Sentinel."""

from pathlib import Path
from typing import Annotated

import typer

from aur_sentinel.analyzer import analyze_pkgbuild

app = typer.Typer(add_completion=False, no_args_is_help=True)


@app.command()
def scan(pkgbuild: Annotated[Path, typer.Argument(exists=True, dir_okay=False)]) -> None:
    """Scan a local PKGBUILD and print its risk report."""
    report = analyze_pkgbuild(pkgbuild.read_text(encoding="utf-8"))
    typer.echo(f"risk={report.risk.value} score={report.score}/100")
    for finding in report.findings:
        typer.echo(f"L{finding.line} [{finding.rule_id}] {finding.description}")
