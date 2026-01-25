from pathlib import Path
from datetime import datetime

from portsense.models import ReportModel, FindingAssessment, PortFinding, RiskRating, ConfidenceRating
from portsense.evidence.screenshots import collect_web_screenshots


class FakeDriver:
    def __init__(self, calls: list[str], save_ok: bool = True):
        self.calls = calls
        self.save_ok = save_ok
        self.quit_called = False

    def get(self, url: str):
        self.calls.append(url)

    def save_screenshot(self, path: str):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        # create small dummy file
        p.write_bytes(b"PNG\x00dummy")
        return self.save_ok

    def quit(self):
        self.quit_called = True


def _fa(host: str, port: int, state: str, service: str, risk: str):
    return FindingAssessment(
        finding=PortFinding(host=host, port=port, protocol="tcp", state=state, service=service),
        risk=RiskRating(level=risk, reasons=[]),
        confidence=ConfidenceRating(level="High", rationale=[], env_count=1, open_count=1),
    )


def test_collect_web_screenshots_eligibility_and_outputs(tmp_path: Path):
    # Build report with four assessments
    assessments = [
        _fa("alpha.local", 80, "open", "http", "High"),        # eligible
        _fa("alpha.local", 443, "open", "https", "Critical"),   # eligible
        _fa("alpha.local", 8080, "open", "http", "Medium"),     # not eligible (risk medium)
        _fa("alpha.local", 22, "open", "ssh", "High"),          # not eligible (non-web)
    ]
    report = ReportModel(
        target="dummy",
        generated_at=datetime.now(),
        summary_hosts=1,
        summary_open_ports=3,
        summary_findings=len(assessments),
        assessments=assessments,
    )

    calls: list[str] = []

    def factory():
        return FakeDriver(calls)

    outdir = tmp_path / "out"
    outdir.mkdir()
    shotdir = outdir / "assets" / "screens"

    report2 = collect_web_screenshots(
        report,
        outdir=outdir,
        screenshot_dir=shotdir,
        top_n=5,
        timeout=5,
        driver_factory=factory,
    )

    # Evidence should exist for web-like open findings (80,443,8080)
    with_ev = [a for a in report2.assessments if a.evidence is not None]
    assert len(with_ev) == 3

    # URLs recorded and scheme correct
    assert f"http://alpha.local:80" in calls
    assert f"https://alpha.local:443" in calls

    # Files created in expected paths (host/port.png) and paths are relative to outdir
    # Two selected eligible items should be ok and have files
    ok_items = [a for a in report2.assessments if (a.evidence and a.evidence.status == "ok")]
    assert len(ok_items) == 2
    for a in ok_items:
        assert a.evidence.status == "ok"
        assert a.evidence.url is not None
        rel = a.evidence.screenshot_path
        assert rel is not None
        # ensure it is relative (no absolute prefix)
        assert not rel.startswith("/")
        assert Path(outdir / rel).exists()

    # Non-selected web item should be marked skipped
    skipped = [a for a in report2.assessments if (a.evidence and a.evidence.status == "skipped")]
    assert len(skipped) == 1
    assert skipped[0].finding.port == 8080


def test_collect_web_screenshots_below_threshold_skips(tmp_path: Path):
    # Only Medium risk web port while min_risk is High by default
    assessments = [
        _fa("alpha.local", 8080, "open", "http", "Medium"),
    ]
    report = ReportModel(
        target="dummy",
        generated_at=datetime.now(),
        summary_hosts=1,
        summary_open_ports=1,
        summary_findings=1,
        assessments=assessments,
    )

    outdir = tmp_path / "out"
    outdir.mkdir()
    shotdir = outdir / "assets" / "shots"

    res = collect_web_screenshots(report, outdir=outdir, screenshot_dir=shotdir, top_n=3, timeout=5)
    ev = res.assessments[0].evidence
    assert ev is not None
    assert ev.status == "skipped"
    assert ev.error == "below risk threshold"


def test_collect_web_screenshots_selenium_absent_skips(tmp_path: Path, monkeypatch):
    from portsense.evidence import screenshots as sc

    # Replace default driver factory to simulate missing selenium
    def failing_factory(timeout=5):
        raise ImportError("Selenium not installed")

    monkeypatch.setattr(sc, "_default_driver_factory", lambda timeout: failing_factory(timeout))

    assessments = [
        _fa("target", 443, "open", "https", "High"),
    ]
    report = ReportModel(
        target="dummy",
        generated_at=datetime.now(),
        summary_hosts=1,
        summary_open_ports=1,
        summary_findings=1,
        assessments=assessments,
    )

    outdir = tmp_path / "out"
    outdir.mkdir()
    shotdir = outdir / "assets" / "shots"
    res = collect_web_screenshots(report, outdir=outdir, screenshot_dir=shotdir, top_n=3, timeout=5)
    ev = res.assessments[0].evidence
    assert ev is not None
    assert ev.status == "skipped"
    assert ev.url == "https://target:443"