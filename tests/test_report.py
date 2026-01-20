from datetime import datetime

from portsense.models import ReportModel, FindingAssessment, PortFinding, RiskRating, ConfidenceRating
from portsense.report.jsonout import render_json
from portsense.report.markdown import render_markdown


def _assessment(host: str, port: int, risk: str, conf: str) -> FindingAssessment:
    finding = PortFinding(host=host, ip="10.0.0.1", port=port, protocol="tcp", state="open", service="svc")
    return FindingAssessment(
        finding=finding,
        risk=RiskRating(level=risk, reasons=["test reason"]),
        confidence=ConfidenceRating(level=conf, rationale=["rationale"], env_count=1, open_count=1),
    )


def test_report_renderers_json_and_markdown():
    report = ReportModel(
        target="test-target",
        generated_at=datetime(2024, 1, 1, 0, 0, 0),
        summary_hosts=1,
        summary_open_ports=2,
        summary_findings=2,
        assessments=[
            _assessment("h1", 22, "High", "High"),
            _assessment("h1", 443, "Low", "Low"),
        ],
    )

    js = render_json(report)
    # Basic JSON structure
    assert js.strip().startswith("{") and "\"summary_findings\"" in js and "\"assessments\"" in js

    md = render_markdown(report, top_n=5)
    # Basic Markdown content checks (flexible formatting)
    assert "Portsense Report" in md
    assert "Findings by risk level" in md
    assert "Top" in md and "Risky Findings" in md
    # Table section and rows contain port and risk level
    assert "Findings by Host" in md
    assert "| Port |" in md
    assert "22" in md and "High" in md
