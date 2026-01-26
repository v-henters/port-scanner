import re
import json
import logging
from pathlib import Path
from typing import List, Set, Optional, Dict, Any

from ..models import VulnerabilityFinding, CveData

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

def extract_cves(text: str) -> List[str]:
    if not text:
        return []
    return [cve.upper() for cve in CVE_PATTERN.findall(text)]

def parse_nuclei_findings(results_path: Path) -> List[VulnerabilityFinding]:
    findings = []
    if not results_path.exists():
        return findings

    try:
        with open(results_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    findings.append(map_nuclei_to_finding(data))
                except Exception as e:
                    logger.warning(f"Failed to parse Nuclei line: {e}")
    except Exception as e:
        logger.error(f"Failed to read Nuclei results: {e}")

    return findings

def map_nuclei_to_finding(data: Dict[str, Any]) -> VulnerabilityFinding:
    info = data.get("info", {})
    
    # Extract CVE from multiple places
    cve_ids = set()
    
    # 1. info.cve
    if "cve" in info:
        if isinstance(info["cve"], list):
            for c in info["cve"]:
                cve_ids.update(extract_cves(str(c)))
        else:
            cve_ids.update(extract_cves(str(info["cve"])))
            
    # 2. info.reference
    if "reference" in info:
        if isinstance(info["reference"], list):
            for r in info["reference"]:
                cve_ids.update(extract_cves(str(r)))
        else:
            cve_ids.update(extract_cves(str(info["reference"])))

    # 3. extracted-results
    if "extracted-results" in data:
        for er in data["extracted-results"]:
            cve_ids.update(extract_cves(str(er)))

    # Use the first CVE ID found for primary association
    primary_cve = None
    if cve_ids:
        # Sort to be deterministic
        sorted_cves = sorted(list(cve_ids))
        primary_cve = CveData(id=sorted_cves[0])

    return VulnerabilityFinding(
        template_id=data.get("template-id", "unknown"),
        name=info.get("name", "Unknown"),
        severity=info.get("severity", "info"),
        host=data.get("host", ""),
        matched_at=data.get("matched-at", ""),
        cve=primary_cve,
        info=data
    )
