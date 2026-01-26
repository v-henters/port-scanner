import json
from pathlib import Path
from portsense.vuln.nuclei import extract_nuclei_urls, parse_nuclei_jsonl
from portsense.models import FindingAssessment, PortFinding, RiskRating, ConfidenceRating

def test_extract_nuclei_urls():
    assessments = [
        FindingAssessment(
            finding=PortFinding(host="1.1.1.1", port=80, state="open", service="http"),
            risk=RiskRating(level="Low"),
            confidence=ConfidenceRating(level="High")
        ),
        FindingAssessment(
            finding=PortFinding(host="example.com", port=443, state="open", service="https"),
            risk=RiskRating(level="Low"),
            confidence=ConfidenceRating(level="High")
        ),
        FindingAssessment(
            finding=PortFinding(host="2.2.2.2", port=8080, state="open", service="http-proxy"),
            risk=RiskRating(level="Low"),
            confidence=ConfidenceRating(level="High")
        ),
        FindingAssessment(
            finding=PortFinding(host="3.3.3.3", port=22, state="open", service="ssh"),
            risk=RiskRating(level="Low"),
            confidence=ConfidenceRating(level="High")
        ),
        FindingAssessment(
            finding=PortFinding(host="4.4.4.4", port=80, state="closed", service="http"),
            risk=RiskRating(level="Low"),
            confidence=ConfidenceRating(level="High")
        ),
        FindingAssessment(
            finding=PortFinding(host="5.5.5.5", port=8443, state="open", service="unknown"),
            risk=RiskRating(level="Low"),
            confidence=ConfidenceRating(level="High")
        ),
    ]
    
    urls = extract_nuclei_urls(assessments)
    
    assert "http://1.1.1.1:80" in urls
    assert "https://example.com:443" in urls
    assert "http://2.2.2.2:8080" in urls
    assert "https://5.5.5.5:8443" in urls
    assert len(urls) == 4
    assert "http://3.3.3.3:22" not in urls
    assert "http://4.4.4.4:80" not in urls

def test_parse_nuclei_jsonl(tmp_path):
    jsonl_file = tmp_path / "results.jsonl"
    results = [
        {
            "template-id": "exposed-git-dir",
            "info": {
                "name": "Exposed Git Directory",
                "severity": "medium",
                "classification": {"cve-id": "CVE-2021-1234"}
            },
            "matched-at": "http://example.com/.git/",
            "host": "example.com"
        },
        {
            "template-id": "tech-detect",
            "info": {
                "name": "Technology Detection",
                "severity": "info",
                "reference": ["https://reference.com"]
            },
            "matched-at": "http://example.com/",
            "host": "example.com",
            "extracted-results": ["nginx/1.18.0"]
        }
    ]
    
    with open(jsonl_file, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
            
    findings = parse_nuclei_jsonl(jsonl_file)
    
    assert len(findings) == 2
    assert findings[0].template_id == "exposed-git-dir"
    assert findings[0].severity == "medium"
    assert "CVE-2021-1234" in findings[0].reference
    
    assert findings[1].template_id == "tech-detect"
    assert "nginx/1.18.0" in findings[1].extracted_results
    assert "https://reference.com" in findings[1].reference
