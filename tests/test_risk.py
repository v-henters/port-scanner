from portsense.models import PortFinding
from portsense.config import Policy
from portsense.analysis.risk import assess_port_risk


def test_non_open_state_is_info():
    finding = PortFinding(host="host", port=22, state="closed", service="ssh")
    policy = Policy()
    rating = assess_port_risk(finding, policy)
    assert rating.level == "Info"
    assert any("not considered attack surface" in r for r in rating.reasons)


def test_allowed_web_port_is_info_due_to_penalty():
    finding = PortFinding(host="host", port=80, state="open", service="http")
    policy = Policy(allowed_ports=[80, 443])
    rating = assess_port_risk(finding, policy)
    # base 25 - 20 penalty = 5 -> Info
    assert rating.level == "Info"
    assert any("allowed_ports" in r for r in rating.reasons)


def test_dangerous_admin_port_high_without_version():
    finding = PortFinding(host="host", port=22, state="open", service="ssh")
    policy = Policy(dangerous_ports=[22])
    rating = assess_port_risk(finding, policy)
    # 50 + 25 = 75 -> High
    assert rating.level in ("High", "Critical")
    assert any("dangerous_ports" in r for r in rating.reasons)


def test_dangerous_admin_port_critical_with_version():
    finding = PortFinding(host="host", port=22, state="open", service="ssh", version="9.6")
    policy = Policy(dangerous_ports=[22], version_exposure_weight=10)
    rating = assess_port_risk(finding, policy)
    # 50 + 10 + 25 = 85 -> Critical
    assert rating.level == "Critical"


def test_db_port_with_version_is_critical():
    finding = PortFinding(host="host", port=5432, state="open", service="postgresql", version="15")
    policy = Policy(dangerous_ports=[5432], version_exposure_weight=10)
    rating = assess_port_risk(finding, policy)
    # 45 + 10 + 25 = 80 -> Critical
    assert rating.level == "Critical"


def test_unknown_high_port_is_info():
    finding = PortFinding(host="host", port=50000, state="open", service=None)
    policy = Policy()
    rating = assess_port_risk(finding, policy)
    # 15 -> Info
    assert rating.level == "Info"


def test_internal_service_low():
    finding = PortFinding(host="host", port=389, state="open", service="ldap")
    policy = Policy()
    rating = assess_port_risk(finding, policy)
    # 35 -> Low
    assert rating.level == "Low"
