from pathlib import Path
import tempfile
from datetime import datetime

from typer.testing import CliRunner

from portsense.cli import app
from portsense.models import FindingAssessment, PortFinding, RiskRating, ConfidenceRating, ReportModel


SAMPLE_XML = """
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX scan.xml 192.0.2.10" start="1704067200" startstr="Wed Jan  1 00:00:00 2024" version="7.94" xmloutputversion="1.05">
  <host>
    <status state="up" reason="syn-ack" reason_ttl="0"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class FakeDriver:
    def __init__(self):
        self.calls = []

    def get(self, url: str):
        self.calls.append(url)

    def save_screenshot(self, path: str):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"PNG\x00dummy")
        return True

    def quit(self):
        pass


def _fa(host: str, port: int, state: str, service: str, risk: str):
    return FindingAssessment(
        finding=PortFinding(host=host, port=port, protocol="tcp", state=state, service=service),
        risk=RiskRating(level=risk, reasons=[]),
        confidence=ConfidenceRating(level="High", rationale=[], env_count=1, open_count=1),
    )


def test_cli_screenshots_smoke(tmp_path: Path, monkeypatch):
    # Monkeypatch merge_assessments to produce two eligible web items
    def fake_merge(env_results, policy):
        return [
            _fa("192.0.2.10", 80, "open", "http", "High"),
            _fa("192.0.2.10", 443, "open", "https", "Critical"),
            _fa("192.0.2.10", 22, "open", "ssh", "High"),
        ]

    import portsense.analysis.confidence as conf
    monkeypatch.setattr(conf, "merge_assessments", fake_merge)

    # Monkeypatch default driver factory to avoid Selenium dependency
    import portsense.evidence.screenshots as shots
    monkeypatch.setattr(shots, "_default_driver_factory", lambda timeout: FakeDriver())

    runner = CliRunner()
    xml_path = tmp_path / "scan.xml"
    xml_path.write_text(SAMPLE_XML.strip(), encoding="utf-8")

    outdir = tmp_path / "out"
    shotdir = tmp_path / "shots"
    result = runner.invoke(
        app,
        [
            "analyze",
            "-i",
            str(xml_path),
            "--outdir",
            str(outdir),
            "--screenshots",
            "--screenshot-dir",
            str(shotdir),
            "--overwrite",
        ],
    )

    assert result.exit_code == 0, result.output
    assert (outdir / "report.json").exists()
    assert (outdir / "report.md").exists()
    # Screens for 80 and 443 should exist under provided dir
    assert (shotdir / "192.0.2.10" / "80.png").exists()
    assert (shotdir / "192.0.2.10" / "443.png").exists()
