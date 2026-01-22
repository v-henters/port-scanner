import requests
from typing import Dict, Any

def lookup_ip(ip: str) -> Dict[str, Any]:
    url = f"https://internetdb.shodan.io/{ip}"
    resp = requests.get(url, timeout=5)

    if resp.status_code != 200:
        raise RuntimeError(f"Shodan request failed: {resp.status_code}")

    raw = resp.json()

    services = {}
    for port in raw.get("ports", []):
        services[port] = {
            "product": None,
            "version": None
        }

    return {
        "ip": raw.get("ip"),
        "ports": raw.get("ports", []),
        "services": services,
        "org": raw.get("org"),
        "last_seen": raw.get("last_update")
    }

