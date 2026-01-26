import json
import logging
import time
from pathlib import Path
from typing import Optional, Dict, Any

try:
    import requests
except ImportError:
    requests = None

from ..models import CvssData

logger = logging.getLogger(__name__)

class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, cache_dir: Optional[Path] = None, timeout: int = 10):
        self.cache_dir = cache_dir
        self.timeout = timeout
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get_cve_data(self, cve_id: str) -> Optional[CvssData]:
        # 1. Try cache
        if self.cache_dir:
            cache_file = self.cache_dir / f"{cve_id}.json"
            if cache_file.exists():
                try:
                    data = json.loads(cache_file.read_text(encoding="utf-8"))
                    return self._parse_nvd_response(data)
                except Exception as e:
                    logger.warning(f"Failed to read cache for {cve_id}: {e}")

        # 2. Fetch from NVD
        if requests is None:
            logger.error("requests library is not installed. Cannot fetch from NVD.")
            return CvssData(status="unavailable")

        try:
            # NVD API rate limits: 5 requests per 30 seconds without API key
            # We'll implement a simple retry with backoff if needed, but for now just one retry
            response = requests.get(
                f"{self.BASE_URL}?cveId={cve_id}",
                timeout=self.timeout
            )
            
            if response.status_code == 403 or response.status_code == 429:
                logger.warning(f"NVD API rate limited (status {response.status_code}). Waiting 6 seconds...")
                time.sleep(6)
                response = requests.get(
                    f"{self.BASE_URL}?cveId={cve_id}",
                    timeout=self.timeout
                )

            if response.status_code == 200:
                data = response.json()
                if self.cache_dir:
                    cache_file = self.cache_dir / f"{cve_id}.json"
                    cache_file.write_text(json.dumps(data), encoding="utf-8")
                return self._parse_nvd_response(data)
            else:
                logger.error(f"Failed to fetch {cve_id} from NVD: HTTP {response.status_code}")
        except Exception as e:
            logger.error(f"Error fetching {cve_id} from NVD: {e}")

        return CvssData(status="unavailable")

    def _parse_nvd_response(self, data: Dict[str, Any]) -> Optional[CvssData]:
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return CvssData(status="unavailable")

        cve = vulnerabilities[0].get("cve", {})
        metrics = cve.get("metrics", {})

        # Priority: CVSS v3.1 > v3.0 > v2
        
        # CVSS v3.1
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            return self._extract_cvss_metric(cvss_v31[0], "3.1")

        # CVSS v3.0
        cvss_v30 = metrics.get("cvssMetricV30", [])
        if cvss_v30:
            return self._extract_cvss_metric(cvss_v30[0], "3.0")

        # CVSS v2
        cvss_v2 = metrics.get("cvssMetricV2", [])
        if cvss_v2:
            return self._extract_cvss_metric(cvss_v2[0], "2.0")

        return CvssData(status="unavailable")

    def _extract_cvss_metric(self, metric: Dict[str, Any], version: str) -> CvssData:
        cvss_data = metric.get("cvssData", {})
        return CvssData(
            version=version,
            score=cvss_data.get("baseScore"),
            severity=cvss_data.get("baseSeverity") or metric.get("baseSeverity"),
            vector=cvss_data.get("vectorString"),
            source=metric.get("source"),
        )
