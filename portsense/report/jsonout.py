from __future__ import annotations

import json
from typing import Any, Dict, Optional

from ..models import (
    ScanResult,
    RiskAssessment,
    ConfidenceAssessment,
    ReportModel,
)


def render_json(*args) -> str:
    """Render JSON.

    Backward compatible:
    - New: render_json(report: ReportModel)
    - Legacy: render_json(scan: ScanResult, risk: RiskAssessment, confidence: ConfidenceAssessment)
    """
    if len(args) == 1 and isinstance(args[0], ReportModel):
        report: ReportModel = args[0]
        data = report.model_dump(mode="python")
        if report.dns_resolution is None:
            data.pop("dns_resolution", None)
        return json.dumps(data, indent=2, default=str)

    if len(args) == 3 and isinstance(args[0], ScanResult):
        scan: ScanResult = args[0]
        risk: RiskAssessment = args[1]
        confidence: ConfidenceAssessment = args[2]
        payload: Dict[str, Any] = {
            "scan": scan.model_dump(mode="python"),
            "risk": risk.model_dump(mode="python"),
            "confidence": confidence.model_dump(mode="python"),
        }
        return json.dumps(payload, indent=2, default=str)

    raise TypeError("render_json expects (ReportModel) or (ScanResult, RiskAssessment, ConfidenceAssessment)")
