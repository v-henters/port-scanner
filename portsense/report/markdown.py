from __future__ import annotations

from io import StringIO
from collections import defaultdict
from typing import List, Dict, Tuple

from ..models import (
    ScanResult,
    RiskAssessment,
    ConfidenceAssessment,
    ReportModel,
)


def render_markdown(*args, top_n: int = 10) -> str:
    """Render Markdown.

    Backward compatible:
    - New: render_markdown(report: ReportModel)
    - Legacy: render_markdown(scan: ScanResult, risk: RiskAssessment, confidence: ConfidenceAssessment)
    """
    buf = StringIO()

    if len(args) == 1 and isinstance(args[0], ReportModel):
        report: ReportModel = args[0]
        buf.write("# Portsense Report\n\n")
        # Executive summary
        buf.write("## Executive Summary\n")
        buf.write(f"- Target: {report.target}\n")
        buf.write(f"- Generated: {report.generated_at}\n")
        buf.write(f"- Hosts scanned: {report.summary_hosts}\n")
        buf.write(f"- Open ports detected: {report.summary_open_ports}\n")
        buf.write(f"- Total findings: {report.summary_findings}\n")

        # Risk counts by level
        counts: Dict[str, int] = {k: 0 for k in ["Critical", "High", "Medium", "Low", "Info"]}
        for a in report.assessments:
            counts[a.risk.level] = counts.get(a.risk.level, 0) + 1
        buf.write("- Findings by risk level:\n")
        buf.write(
            f"  - Critical: {counts.get('Critical', 0)} | High: {counts.get('High', 0)} | "
            f"Medium: {counts.get('Medium', 0)} | Low: {counts.get('Low', 0)} | Info: {counts.get('Info', 0)}\n\n"
        )

        if report.dns_resolution:
            buf.write("## DNS Resolution\n\n")
            for entry in report.dns_resolution:
                if entry.status == "ok":
                    a_val = ", ".join(entry.a) if entry.a else "none"
                    aaaa_val = ", ".join(entry.aaaa) if entry.aaaa else "none"
                    buf.write(
                        f"- {entry.target} ({entry.type}): A={a_val} | AAAA={aaaa_val} | "
                        f"Resolved: {entry.resolved_at} | Method: {entry.method}\n"
                    )
                elif entry.status == "skipped":
                    buf.write(f"- {entry.target} ({entry.type}): skipped (IP target)\n")
                else:
                    err = entry.error or "unknown error"
                    buf.write(f"- {entry.target} ({entry.type}): failed ({err})\n")
            buf.write("\n")

        if not report.assessments:
            buf.write("No findings.\n")
            return buf.getvalue()

        # Top N risky findings
        buf.write(f"## Top {min(top_n, len(report.assessments))} Risky Findings\n\n")
        severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        conf_rank = {"High": 2, "Medium": 1, "Low": 0}
        def sort_key(a) -> Tuple[int, int, int]:
            return (
                severity_rank.get(a.risk.level, 0),
                conf_rank.get(a.confidence.level, 0),
                1 if a.finding.state == "open" else 0,
            )
        top_list = sorted(report.assessments, key=sort_key, reverse=True)[:top_n]

        def recommend(a) -> str:
            lvl = a.risk.level
            if lvl not in {"High", "Critical"}:
                return ""
            sname = (a.finding.service or "").lower()
            p = a.finding.port
            reasons = " ".join(a.risk.reasons).lower()
            admin_names = {"ssh", "rdp", "winrm", "vnc", "telnet", "smb"}
            db_ports = {3306, 5432, 1433, 1521, 27017}
            web_ports = {80, 443, 8080, 8081, 8000, 8443}
            if sname in admin_names or p in {22, 3389, 5985, 5986, 5900, 139, 445}:
                return "Restrict to trusted IPs, enforce strong auth/MFA, and disable if not required."
            if p in db_ports or any(x in sname for x in ["mysql", "postgres", "redis", "mongo", "mssql"]):
                return "Bind to private networks, require authentication/TLS, and avoid internet exposure."
            if p in web_ports or "http" in sname:
                return "Harden/patch the web service, require authentication, and place behind a WAF if public."
            if "high-risk" in reasons:
                return "Validate necessity; apply vendor hardening or close the port if unnecessary."
            return "Review service necessity, restrict ingress, patch regularly."

        for a in top_list:
            f = a.finding
            rec = recommend(a)
            line = (
                f"- {f.host}: `{f.port}/{f.protocol}` {f.service or ''} — Risk: {a.risk.level} "
                f"(Confidence: {a.confidence.level})"
            )
            buf.write(line + "\n")
            if rec:
                buf.write(f"  - Recommended action: {rec}\n")
            # Evidence (if any)
            ev = getattr(a, "evidence", None)
            if ev:
                url = ev.url or ""
                path = ev.screenshot_path or ""
                ts = ev.captured_at
                status = ev.status or ""
                err = f"; error: {ev.error}" if ev and ev.error else ""
                buf.write(
                    f"  - Evidence: URL: {url} | Screenshot: {path} | captured_at: {ts} | status: {status}{err}\n"
                )
        buf.write("\n")

        # Per-host tables
        buf.write("## Findings by Host\n\n")
        by_host: Dict[str, List] = defaultdict(list)
        for a in report.assessments:
            by_host[a.finding.host].append(a)

        for host, items in sorted(by_host.items(), key=lambda kv: kv[0]):
            buf.write(f"### {host}\n\n")
            buf.write("| Port | Proto | Service | State | Risk | Confidence |\n")
            buf.write("|----:|:-----:|:--------|:-----:|:-----:|:----------:|\n")
            for a in sorted(items, key=lambda x: (severity_rank.get(x.risk.level, 0), x.finding.port), reverse=True):
                f = a.finding
                buf.write(
                    f"| {f.port} | {f.protocol} | {f.service or ''} | {f.state} | {a.risk.level} | {a.confidence.level} |\n"
                )
                ev = getattr(a, "evidence", None)
                if ev:
                    url = ev.url or ""
                    path = ev.screenshot_path or ""
                    ts = ev.captured_at
                    status = ev.status or ""
                    err = f"; error: {ev.error}" if ev and ev.error else ""
                    buf.write(
                        f"  - Evidence: URL: {url} | Screenshot: {path} | captured_at: {ts} | status: {status}{err}\n"
                    )
            buf.write("\n")
        return buf.getvalue()

    if len(args) == 3 and isinstance(args[0], ScanResult):
        scan: ScanResult = args[0]
        risk: RiskAssessment = args[1]
        confidence: ConfidenceAssessment = args[2]
        buf.write("# Portsense Report\n\n")

        # Summary
        buf.write("## Summary\n")
        buf.write(f"- Tool: {scan.metadata.tool}\n")
        buf.write(f"- Started: {scan.metadata.started}\n")
        buf.write(f"- Finished: {scan.metadata.finished}\n")
        buf.write(f"- Hosts: {len(scan.hosts)}\n")
        buf.write(f"- Risk: {risk.level} ({risk.score:.1f})\n")
        buf.write(
            f"- Breakdown: high={risk.breakdown.high}, medium={risk.breakdown.medium}, low={risk.breakdown.low}\n"
        )
        buf.write(f"- Confidence: {confidence.score:.2f}\n")
        buf.write(f"- Rationale: {confidence.rationale}\n\n")

        # Hosts and ports
        buf.write("## Hosts\n\n")
        for host in scan.hosts:
            buf.write(f"### {host.address}\n\n")
            if host.hostname:
                buf.write(f"Hostname: `{host.hostname}`\n\n")
            if not host.ports:
                buf.write("No ports recorded.\n\n")
                continue
            buf.write("| Port | Proto | State | Service | Product | Version |\n")
            buf.write("|---:|:-----:|:-----:|:--------|:--------|:--------|\n")
            for p in host.ports:
                name = p.service.name if p.service else ""
                product = p.service.product if p.service else ""
                version = p.service.version if p.service else ""
                buf.write(
                    f"| {p.portid} | {p.protocol} | {p.state} | {name} | {product} | {version} |\n"
                )
            buf.write("\n")

        return buf.getvalue()

    raise TypeError("render_markdown expects (ReportModel) or (ScanResult, RiskAssessment, ConfidenceAssessment)")
