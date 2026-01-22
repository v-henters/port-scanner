from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

from ..models import (
    ScanResult,
    ConfidenceAssessment,
    HostScanResult,
    ConfidenceRating,
    FindingAssessment,
    PortFinding,
)
from ..config import Policy
from .risk import assess_port_risk
from .osint import compare_ports



def assess_confidence(scan: ScanResult) -> ConfidenceAssessment:
    """Heuristic confidence score based on data richness.

    - More hosts and more open ports generally increase confidence (up to 1.0).
    - Empty scans result in low confidence.
    """
    host_count = len(scan.hosts)
    open_ports = sum(
        1 for h in scan.hosts for p in h.ports if p.state == "open"
    )

    # Simple heuristic: scale by hosts (0..0.6) and open ports (0..0.4)
    host_component = min(0.6, host_count * 0.1)
    port_component = min(0.4, open_ports * 0.02)
    score = round(host_component + port_component, 3)

    rationale = (
        f"hosts={host_count}, open_ports={open_ports}, "
        f"host_component={host_component:.2f}, port_component={port_component:.2f}"
    )
    return ConfidenceAssessment(score=score, rationale=rationale)


# ==============================
# Environment consistency scoring
# ==============================

Key = Tuple[str, int, str]  # (host_or_ip, port, protocol)


def _key_for_finding(f: PortFinding) -> Key:
    host_id = (f.ip or f.host or "").lower()
    proto = (f.protocol or "tcp").lower()
    return host_id, int(f.port), proto


def compute_env_confidence(env_results: Iterable[HostScanResult]) -> Dict[Key, ConfidenceRating]:
    """Compute confidence per (host/ip, port, protocol) across multiple environments.

    Rules:
    - env_count = number of environments provided
    - open_count = number of environments where the same port is open
    - If open_count == env_count and env_count >= 2 => High
    - If open_count >= 2 and open_count < env_count => Medium
    - If open_count == 1 => Low
    - If open_count == 0 => Low
    """
    envs: List[HostScanResult] = list(env_results)
    env_count = len(envs)
    # Collect all keys first
    all_keys: set[Key] = set()
    for env in envs:
        for f in env.findings:
            all_keys.add(_key_for_finding(f))

    results: Dict[Key, ConfidenceRating] = {}
    for key in all_keys:
        open_count = 0
        seen_in_env = 0
        for env in envs:
            # For each env, check if the key exists and whether any is open
            matches = [f for f in env.findings if _key_for_finding(f) == key]
            if matches:
                seen_in_env += 1
                if any((f.state or "").lower() == "open" for f in matches):
                    open_count += 1

        # Determine level
        if env_count >= 2 and open_count == env_count:
            level = "High"
        elif open_count >= 2 and open_count < env_count:
            level = "Medium"
        elif open_count == 1:
            level = "Low"
        else:
            # open_count == 0 (either not found or never open)
            level = "Low"

        rationale: List[str] = []
        rationale.append(
            f"Observed open in {open_count}/{env_count} environments; present in {seen_in_env}/{env_count}"
        )
        if level == "High":
            rationale.append("Consistent open state across all environments")
        elif level == "Medium":
            rationale.append("Open in multiple environments but not all")
        elif open_count == 1:
            rationale.append("Observed open only once across environments")
        else:
            rationale.append("No open observation across environments")

        results[key] = ConfidenceRating(
            level=level,
            rationale=rationale,
            env_count=env_count,
            open_count=open_count,
        )

    return results

def merge_assessments(env_results, policy, shodan_ports=None):
    envs = list(env_results)
    conf_map = compute_env_confidence(envs)

    reps = {}
    for env in envs:
        for f in env.findings:
            key = _key_for_finding(f)
            if key not in reps:
                reps[key] = f

    assessments = []

    for key, finding in reps.items():
        risk = assess_port_risk(finding, policy)
        conf = conf_map.get(key)

        if conf is None:
            conf = ConfidenceRating(
                level="Low",
                rationale=["No data"],
                env_count=len(envs),
                open_count=0,
            )

        # --- Shodan evidence 추가 ---
        if shodan_ports is not None:
            result = compare_ports([finding.port], shodan_ports)

            if finding.port in result and result[finding.port] == "high":
                conf.rationale.append("Also observed via Shodan (external OSINT)")
            else:
                conf.rationale.append("Not observed via Shodan")

        assessments.append(
            FindingAssessment(
                finding=finding,
                risk=risk,
                confidence=conf,
            )
        )

    return assessments


