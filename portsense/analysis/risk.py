from __future__ import annotations

from typing import Dict, Set, Tuple

from ..models import (
    ScanResult,
    RiskAssessment,
    RiskBreakdown,
    PortFinding,
    RiskRating,
)
from ..config import Policy


HIGH_RISK_PORTS: Set[int] = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 445, 512,
    513, 514, 873, 1433, 1521, 2049, 2375, 2380, 3306, 3389, 5432, 5900,
    5985, 5986, 6379, 7001, 7002, 8080, 8081, 9000, 9200, 11211, 27017,
}


def assess_risk(scan: ScanResult) -> RiskAssessment:
    """Very simple risk scoring based on open ports.

    - Each open port contributes to score.
    - Known high-risk ports weigh more.
    - Score is capped to 100 and mapped to level.
    """
    breakdown = RiskBreakdown()
    score = 0.0

    for host in scan.hosts:
        for p in host.ports:
            if p.state != "open":
                continue
            base = 2.0
            if p.portid in HIGH_RISK_PORTS:
                base = 5.0
                breakdown.high += 1
            elif p.portid < 1024:
                base = 3.0
                breakdown.medium += 1
            else:
                breakdown.low += 1
            score += base

    # Normalize roughly: 0..100
    score = min(100.0, score)

    if score >= 70:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    return RiskAssessment(score=score, level=level, breakdown=breakdown)


# ==============================
# Rule-based per-port risk model
# ==============================

ServiceCategory = str  # one of: admin/db/internal/web/unknown


def _categorize_service(port: int, service_name: str | None) -> ServiceCategory:
    s = (service_name or "").lower()
    # Heuristics by service name
    admin_names = {
        "ssh", "rdp", "winrm", "vnc", "telnet", "smb", "netbios-ssn",
    }
    db_names = {
        "mysql", "postgresql", "postgres", "redis", "mongodb", "mssql",
        "oracle", "db2",
    }
    web_names = {"http", "https", "http-alt", "http-proxy"}
    internal_names = {"nfs", "rpcbind", "ldap", "zookeeper", "jmx", "jenkins"}

    if s in admin_names:
        return "admin"
    if s in db_names:
        return "db"
    if s in web_names:
        return "web"
    if s in internal_names:
        return "internal"

    # Heuristics by port number
    if port in {22, 23, 3389, 5985, 5986, 5900, 139, 445}:
        return "admin"
    if port in {3306, 5432, 6379, 1433, 1521, 27017}:
        return "db"
    if port in {80, 443, 8080, 8081, 8000, 8443}:
        return "web"
    if port in {111, 2049, 389, 7001, 7002, 9000, 9200}:
        return "internal"
    return "unknown"


def _map_level(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Info"


def assess_port_risk(finding: PortFinding, policy: Policy) -> RiskRating:
    """Assess risk for a single PortFinding using policy rules.

    Rules:
    - Only open state is evaluated; otherwise return Info.
    - Score from base category weight + version exposure + list bonuses/penalties.
    - Map score to level per thresholds and provide reasons.
    """
    reasons: list[str] = []

    if finding.state.lower() != "open":
        reasons.append(f"Port state is '{finding.state}', not considered attack surface")
        return RiskRating(level="Info", reasons=reasons)

    # Defaults and mappings
    weights: Dict[str, float] = {
        "admin": 50.0,
        "db": 45.0,
        "internal": 35.0,
        "web": 25.0,
        "unknown": 15.0,
    }
    # Override with policy values if provided
    if policy.service_weights:
        for k, v in policy.service_weights.items():
            if k in weights and isinstance(v, (int, float)):
                weights[k] = float(v)

    version_weight = float(policy.version_exposure_weight or 0.0)

    category = _categorize_service(finding.port, finding.service)
    score = weights.get(category, weights["unknown"])
    reasons.append(f"Service categorized as '{category}' (base {score:g})")

    # Version/product exposure
    if (finding.version or finding.product):
        score += version_weight
        reasons.append(
            f"Version/product info exposed (+{version_weight:g})"
        )

    # Dangerous ports bonus
    if finding.port in set(policy.dangerous_ports or []):
        bonus = 25.0
        score += bonus
        reasons.append(f"Port {finding.port} is in dangerous_ports (+{bonus:g})")

    # Allowed ports penalty
    if finding.port in set(policy.allowed_ports or []):
        penalty = 20.0
        score -= penalty
        reasons.append(f"Port {finding.port} is in allowed_ports (-{penalty:g})")

    # Clamp to 0..100
    score = max(0.0, min(100.0, score))
    level = _map_level(score)
    # If ended up Info for an open port due to penalties, clarify
    if level == "Info":
        reasons.append("Overall risk below threshold")

    return RiskRating(level=level, reasons=reasons)
