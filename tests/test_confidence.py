from datetime import datetime

from portsense.models import (
    HostScanResult,
    ScanMeta,
    ScanEnv,
    PortFinding,
)
from portsense.analysis.confidence import compute_env_confidence, merge_assessments
from portsense.config import Policy


def _env(name: str, findings: list[PortFinding]) -> HostScanResult:
    meta = ScanMeta(scan_id=name, timestamp=datetime.now(), scan_env=ScanEnv(name=name))
    return HostScanResult(meta=meta, findings=findings)


def test_env_confidence_levels_high_medium_low():
    # Three environments for the same host 10.0.0.1
    f1 = [
        PortFinding(host="h1", ip="10.0.0.1", port=22, protocol="tcp", state="open", service="ssh"),
        PortFinding(host="h1", ip="10.0.0.1", port=80, protocol="tcp", state="open", service="http"),
        PortFinding(host="h1", ip="10.0.0.1", port=443, protocol="tcp", state="open", service="https"),
    ]
    f2 = [
        PortFinding(host="h1", ip="10.0.0.1", port=22, protocol="tcp", state="open", service="ssh"),
        PortFinding(host="h1", ip="10.0.0.1", port=80, protocol="tcp", state="closed", service="http"),
        PortFinding(host="h1", ip="10.0.0.1", port=443, protocol="tcp", state="open", service="https"),
    ]
    f3 = [
        PortFinding(host="h1", ip="10.0.0.1", port=22, protocol="tcp", state="open", service="ssh"),
        PortFinding(host="h1", ip="10.0.0.1", port=80, protocol="tcp", state="closed", service="http"),
        PortFinding(host="h1", ip="10.0.0.1", port=443, protocol="tcp", state="closed", service="https"),
    ]

    envs = [_env("env1", f1), _env("env2", f2), _env("env3", f3)]
    conf_map = compute_env_confidence(envs)

    key_22 = ("10.0.0.1", 22, "tcp")
    key_80 = ("10.0.0.1", 80, "tcp")
    key_443 = ("10.0.0.1", 443, "tcp")

    assert conf_map[key_22].level == "High"
    assert conf_map[key_22].open_count == 3 and conf_map[key_22].env_count == 3

    assert conf_map[key_443].level == "Medium"  # open in 2 out of 3
    assert conf_map[key_443].open_count == 2 and conf_map[key_443].env_count == 3

    assert conf_map[key_80].level == "Low"  # open only once
    assert conf_map[key_80].open_count == 1 and conf_map[key_80].env_count == 3


def test_merge_assessments_outputs_confidence_and_risk():
    envs = [
        _env("e1", [PortFinding(host="h", ip="1.2.3.4", port=22, protocol="tcp", state="open", service="ssh")]),
        _env("e2", [PortFinding(host="h", ip="1.2.3.4", port=22, protocol="tcp", state="open", service="ssh")]),
        _env("e3", [PortFinding(host="h", ip="1.2.3.4", port=22, protocol="tcp", state="open", service="ssh")]),
    ]
    assessments = merge_assessments(envs, Policy())
    assert len(assessments) == 1
    a = assessments[0]
    assert a.finding.port == 22 and a.finding.state == "open"
    assert a.confidence.level == "High"
    # Risk for SSH open with default policy should be High or Critical depending on policy
    assert a.risk.level in ("High", "Critical")
