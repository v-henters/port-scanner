import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

# Try to mock requests if it's not installed to allow tests to be collected
try:
    import requests
except ImportError:
    import sys
    from unittest.mock import Mock
    mock_requests = Mock()
    sys.modules["requests"] = mock_requests

from portsense.vuln.nuclei_parser import extract_cves, parse_nuclei_findings, map_nuclei_to_finding
from portsense.vuln.nvd import NVDClient
from portsense.models import CvssData

def test_extract_cves():
    text = "Find CVE-2021-44228 and cve-2020-1234. Ignore CVE-99."
    cves = extract_cves(text)
    assert "CVE-2021-44228" in cves
    assert "CVE-2020-1234" in cves
    assert "CVE-99" not in cves

def test_map_nuclei_to_finding():
    data = {
        "template-id": "cves-2021-44228",
        "info": {
            "name": "Apache Log4j2 JNDI RCE",
            "severity": "critical",
            "cve": "CVE-2021-44228",
            "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
        },
        "host": "http://example.com",
        "matched-at": "http://example.com/",
        "extracted-results": ["Result with CVE-2021-44229"]
    }
    finding = map_nuclei_to_finding(data)
    assert finding.template_id == "cves-2021-44228"
    assert finding.cve.id == "CVE-2021-44228" # sorted, 44228 comes before 44229? Wait.
    # Actually, 44228 < 44229.
    
    # Test deduplication and normalization
    data_multi = {
        "template-id": "test",
        "info": {
            "cve": ["CVE-2021-0001", "cve-2021-0001"],
            "reference": "See CVE-2021-0002"
        },
        "host": "host"
    }
    finding_multi = map_nuclei_to_finding(data_multi)
    # sorted: 0001, 0002. primary is 0001.
    assert finding_multi.cve.id == "CVE-2021-0001"

@patch("requests.get")
def test_nvd_client_parsing(mock_get):
    # Mock NVD API response for CVE-2021-44228
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL"
                                }
                            }
                        ]
                    }
                }
            }
        ]
    }
    mock_get.return_value = mock_response

    client = NVDClient()
    cvss = client.get_cve_data("CVE-2021-44228")
    assert cvss.version == "3.1"
    assert cvss.score == 10.0
    assert cvss.severity == "CRITICAL"
    assert cvss.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

@patch("requests.get")
def test_nvd_client_fallback(mock_get):
    # Mock NVD API response with only CVSS v2
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-TEST",
                    "metrics": {
                        "cvssMetricV2": [
                            {
                                "source": "nvd@nist.gov",
                                "cvssData": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                    "baseScore": 7.5
                                },
                                "baseSeverity": "HIGH"
                            }
                        ]
                    }
                }
            }
        ]
    }
    mock_get.return_value = mock_response

    client = NVDClient()
    cvss = client.get_cve_data("CVE-TEST")
    assert cvss.version == "2.0"
    assert cvss.score == 7.5
    assert cvss.severity == "HIGH"
