from datetime import datetime
from pathlib import Path
from typing import List

import typer

from . import __version__
from .models import (
    ReportModel,
    FindingAssessment,
)
from .parsing.nmap_xml import parse_nmap_xml
from .parsing.nmap_xml import extract_nmap_hostnames
from .analysis.confidence import merge_assessments
from .dns_resolution import (
    extract_targets_from_args,
    resolve_targets,
    append_dns_confidence_rationale,
)
from .report.jsonout import render_json
from .report.markdown import render_markdown
from .config import Policy


app = typer.Typer(help="Portsense — Port scan analysis tool (scaffold)")


@app.callback()
def version_callback(
    version: bool = typer.Option(
        False, "--version", help="Show version and exit.", is_eager=True
    )
):
    if version:
        typer.echo(__version__)
        raise typer.Exit(0)


@app.command()
def analyze(
    input: List[Path] = typer.Option(
        ..., "--input", "-i", exists=True, readable=True, help="Input scan file(s) (e.g., nmap XML). Can be provided multiple times.")
    ,
    env_name: List[str] = typer.Option(
        [], "--env-name", help="Environment name for each input (provide in the same order as --input)."),
    top_n: int = typer.Option(10, "--top-n", help="Top N risky findings to include in Markdown report."),
    outdir: Path = typer.Option(Path("./out"), "--outdir", help="Output directory for reports."),
    dns: bool = typer.Option(False, "--dns", help="Enable DNS resolution for targets."),
    dns_timeout: float = typer.Option(2.0, "--dns-timeout", help="DNS resolution timeout in seconds."),
):
    """Analyze one or more local scan files and write JSON and Markdown reports."""
    if env_name and len(env_name) != len(input):
        typer.echo("The number of --env-name values must match the number of --input files.", err=True)
        raise typer.Exit(2)

    generated_at = datetime.now()

    # Parse each input into normalized host results
    env_results = [parse_nmap_xml(p) for p in input]

    # Merge and assess per finding using the built-in logic
    assessments: List[FindingAssessment] = merge_assessments(env_results, Policy())
    dns_resolution = None
    # Usage: python -m portsense.cli analyze --input scan.xml --outdir out --dns
    if dns:
        targets: List[str] = []
        for env in env_results:
            targets.extend(extract_targets_from_args(env.meta.args))
        for path in input:
            targets.extend(extract_nmap_hostnames(path))
        dns_resolution = resolve_targets(targets, dns_timeout)
        append_dns_confidence_rationale(assessments, dns_resolution)

    target = ", ".join(str(p) for p in input)
    report = ReportModel(
        target=target,
        generated_at=generated_at,
        summary_hosts=len({a.finding.host for a in assessments}),
        summary_open_ports=sum(1 for a in assessments if (a.finding.state or "").lower() == "open"),
        summary_findings=len(assessments),
        assessments=assessments,
        dns_resolution=dns_resolution,
    )

    # Ensure output directory
    outdir.mkdir(parents=True, exist_ok=True)
    json_path = outdir / "report.json"
    md_path = outdir / "report.md"

    json_path.write_text(render_json(report), encoding="utf-8")
    md_path.write_text(render_markdown(report, top_n=top_n), encoding="utf-8")

    typer.echo(f"Written: {json_path}")
    typer.echo(f"Written: {md_path}")


def main():
    app()


if __name__ == "__main__":
    main()
