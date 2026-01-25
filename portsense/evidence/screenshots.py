from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional, Literal

from ..models import ReportModel, FindingAssessment


WebDriverFactory = Callable[[], object]


def _sanitize(s: str) -> str:
    bad = ":/\\?*<>|# \t\n\r"
    out = []
    for ch in s:
        if ch in bad:
            out.append("_")
        else:
            out.append(ch)
    res = "".join(out)
    if not res:
        return "unknown"
    return res[:100]


def _is_web_like(assessment: FindingAssessment) -> bool:
    sname = (assessment.finding.service or "").lower()
    p = assessment.finding.port
    return ("http" in sname) or (p in {80, 443, 8080, 8443})


RiskLevel = Literal["Critical", "High", "Medium", "Low", "Info"]


def _eligible(assessment: FindingAssessment, *, min_level: RiskLevel = "High") -> bool:
    # Compare using ordered severity
    order = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    a_level = assessment.risk.level
    return (
        (assessment.finding.state or "").lower() == "open"
        and _is_web_like(assessment)
        and order.get(a_level, 0) >= order.get(min_level, 3)
    )


def _sort_key(a: FindingAssessment):
    sev = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}.get(a.risk.level, 0)
    return (-sev, a.finding.port, a.finding.host)


def _build_url(host: str, port: int, service: Optional[str]) -> str:
    sname = (service or "").lower()
    if "https" in sname or port in {443, 8443}:
        scheme = "https"
    else:
        scheme = "http"
    return f"{scheme}://{host}:{port}"


def _default_driver_factory(timeout: int) -> object:
    # Import selenium lazily and handle absence
    try:
        from selenium import webdriver  # type: ignore
        from selenium.webdriver.chrome.options import Options  # type: ignore
    except Exception as e:  # ImportError or other
        raise ImportError(f"Selenium not available: {e}")

    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--ignore-certificate-errors")
    driver = webdriver.Chrome(options=opts)
    try:
        driver.set_page_load_timeout(timeout)
    except Exception:
        pass
    return driver


def collect_web_screenshots(
    report_model: ReportModel,
    outdir: Path,
    screenshot_dir: Path,
    top_n: int,
    timeout: int,
    driver_factory: Optional[Callable[[], object]] = None,
    *,
    min_risk: RiskLevel = "High",
) -> ReportModel:
    """Capture screenshots for eligible web findings.

    Returns the same report_model (mutated with evidence fields).
    """
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    # Select eligible items based on minimum risk threshold
    elig: List[FindingAssessment] = [
        a for a in report_model.assessments if _eligible(a, min_level=min_risk)
    ]
    elig_sorted = sorted(elig, key=_sort_key)[: max(0, int(top_n or 0))]
    # Determine candidates that are web-like and open but not selected for capture
    candidates: List[FindingAssessment] = [
        a
        for a in report_model.assessments
        if (a.finding.state or "").lower() == "open" and _is_web_like(a)
    ]

    # Prepare driver
    driver: Optional[object] = None
    driver_error: Optional[str] = None

    if elig_sorted:
        try:
            factory: WebDriverFactory
            if driver_factory is not None:
                factory = driver_factory  # type: ignore
                driver = factory()
            else:
                driver = _default_driver_factory(timeout)
        except Exception as e:
            driver_error = str(e)

    def set_evidence(
        a: FindingAssessment,
        *,
        status: str,
        url: str,
        path_rel: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        a.evidence = FindingAssessment.Evidence(
            url=url,
            screenshot_path=path_rel,
            captured_at=datetime.now(),
            status=status,  # type: ignore[arg-type]
            error=error,
        )

    try:
        # Mark all non-selected web-like open candidates as skipped (either below threshold or not in top_n)
        for a in candidates:
            f = a.finding
            url = _build_url(f.host, f.port, f.service)
            if a not in elig_sorted:
                reason = "below risk threshold" if a not in elig else "not in top_n"
                set_evidence(a, status="skipped", url=url, error=reason)

        # Proceed with actual capture for selected items
        for a in elig_sorted:
            f = a.finding
            url = _build_url(f.host, f.port, f.service)

            if driver_error is not None or driver is None:
                set_evidence(a, status="skipped", url=url, error=driver_error or "driver unavailable")
                continue

            # Compute file path
            host_dir = screenshot_dir / _sanitize(f.host)
            host_dir.mkdir(parents=True, exist_ok=True)
            img_path = host_dir / f"{f.port}.png"

            try:
                # Navigate and capture
                # Basic attribute access to avoid typing selenium
                getattr(driver, "get")(url)
                ok = getattr(driver, "save_screenshot")(str(img_path))
                if not ok:
                    raise RuntimeError("save_screenshot returned False")
                rel_path = str(img_path.relative_to(outdir)) if img_path.is_relative_to(outdir) else str(img_path)
                set_evidence(a, status="ok", url=url, path_rel=rel_path)
            except Exception as e:
                # Do not let failures break overall processing
                rel_path = str(img_path.relative_to(outdir)) if img_path.exists() and img_path.is_relative_to(outdir) else None
                set_evidence(a, status="failed", url=url, path_rel=rel_path, error=str(e))
    finally:
        try:
            if driver is not None:
                getattr(driver, "quit")()
        except Exception:
            pass

    return report_model
