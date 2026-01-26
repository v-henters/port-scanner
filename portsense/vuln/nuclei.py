import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set

from ..models import FindingAssessment, NucleiFinding, NucleiSummary


from .nuclei_parser import parse_nuclei_findings


def extract_nuclei_urls(assessments: List[FindingAssessment]) -> List[str]:
    """
    Extracts deduplicated URLs from findings for Nuclei scanning.
    Logic:
    - only state=open
    - only service in {http, https} or ports in common web ports (80,443,8080,8443,8000,3000,5000,9000)
    - scheme selection: https for 443/8443 or if service suggests https; otherwise http
    """
    urls: Set[str] = set()
    web_ports = {80, 443, 8080, 8443, 8000, 3000, 5000, 9000}
    
    for assessment in assessments:
        finding = assessment.finding
        if (finding.state or "").lower() != "open":
            continue
            
        port = finding.port
        service = (finding.service or "").lower()
        
        is_web = service in {"http", "https"} or port in web_ports
        if not is_web:
            continue
            
        scheme = "http"
        if port in {443, 8443} or "https" in service or "ssl" in (finding.extrainfo or "").lower():
            scheme = "https"
            
        # Use host (could be hostname or IP)
        host = finding.host
        url = f"{scheme}://{host}:{port}"
        # Cleanup: if it's default port, we can simplify, but keeping it explicit is safer for nuclei
        urls.add(url)
        
    return sorted(list(urls))


def run_nuclei(
    urls: List[str],
    output_jsonl: Path,
    bin_path: str = "nuclei",
    severity: str = "critical,high,medium",
    timeout: int = 120,
    templates: Optional[Path] = None,
    tags: Optional[str] = None,
    rate_limit: Optional[int] = None,
) -> NucleiSummary:
    summary = NucleiSummary(
        enabled=True,
        url_count=len(urls),
        results_path=str(output_jsonl),
        started_at=datetime.now(),
    )
    
    if not urls:
        summary.finished_at = datetime.now()
        summary.error = "No target URLs identified."
        return summary

    # Create output directory
    output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    
    # Build command
    cmd = [
        bin_path,
        "-severity", severity,
        "-jsonl",
        "-o", str(output_jsonl),
        "-timeout", str(timeout),
    ]
    
    if templates:
        cmd.extend(["-t", str(templates)])
    if tags:
        cmd.extend(["-tags", tags])
    if rate_limit:
        cmd.extend(["-rl", str(rate_limit)])
        
    # Input URLs via stdin to avoid command line length limits
    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(input="\n".join(urls))
        
        summary.exit_code = process.returncode
        if process.returncode != 0:
            summary.error = stderr.strip() or f"Nuclei exited with code {process.returncode}"
            
    except Exception as e:
        summary.error = str(e)
        
    summary.finished_at = datetime.now()
    return summary


def parse_nuclei_jsonl(path: Path) -> List[NucleiFinding]:
    return parse_nuclei_findings(path)
