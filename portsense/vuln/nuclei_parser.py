import re
import json
import logging
from pathlib import Path
from typing import List, Set, Optional, Dict, Any

from ..models import NucleiFinding, CveData

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

def extract_cves(text: str) -> List[str]:
    if not text:
        return []
    return [cve.upper() for cve in CVE_PATTERN.findall(text)]

def parse_nuclei_findings(results_path: Path) -> List[NucleiFinding]:
    findings = []
    if not results_path.exists():
        return findings

    try:
        with open(results_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    findings.append(map_nuclei_to_finding(data))
                except Exception as e:
                    logger.warning(f"Failed to parse Nuclei line: {e}")
    except Exception as e:
        logger.error(f"Failed to read Nuclei results: {e}")

    return findings

def map_nuclei_to_finding(data: Dict[str, Any]) -> NucleiFinding:
    info = data.get("info", {})
    
    # Extract CVE from multiple places
    cve_ids = set()
    
    # 1. info.classification.cve-id
    classification = info.get("classification", {})
    cve_id = classification.get("cve-id")
    if cve_id:
        if isinstance(cve_id, list):
            for c in cve_id:
                cve_ids.update(extract_cves(str(c)))
        else:
            cve_ids.update(extract_cves(str(cve_id)))

    # 2. info.cve (older templates)
    if "cve" in info:
        if isinstance(info["cve"], list):
            for c in info["cve"]:
                cve_ids.update(extract_cves(str(c)))
        else:
            cve_ids.update(extract_cves(str(info["cve"])))
            
    # 3. info.reference
    references = info.get("reference") or []
    if isinstance(references, str):
        references = [references]
    for r in references:
        cve_ids.update(extract_cves(str(r)))

    # Add all found CVEs to reference if not already there
    final_references = list(references)
    for cid in cve_ids:
        if cid not in final_references:
            # Check if it's already in as part of a URL or something
            if not any(cid in ref for ref in final_references):
                final_references.append(cid)

    # 4. extracted-results
    for er in data.get("extracted-results") or []:
        cve_ids.update(extract_cves(str(er)))

    # Use the first CVE ID found for primary association
    primary_cve = None
    if cve_ids:
        # Sort to be deterministic
        sorted_cves = sorted(list(cve_ids))
        primary_cve = CveData(id=sorted_cves[0])

    return NucleiFinding(
        template_id=data.get("template-id", "unknown"),
        name=info.get("name", "Unknown"),
        severity=info.get("severity", "info"),
        host=data.get("host", ""),
        matched_at=data.get("matched-at", ""),
        extracted_results=data.get("extracted-results") or [],
        reference=final_references,
        cve=primary_cve
    )
