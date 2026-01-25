from __future__ import annotations

from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET

import shlex

from ..models import (
    HostScanResult,
    PortFinding,
    ScanMeta,
)


def _get_attr(elem, name, default=None):
    return elem.attrib.get(name, default)


def parse_nmap_xml(path: Path) -> HostScanResult:
    """Parse a local Nmap XML file produced by `nmap -oX` into normalized HostScanResult.

    Extracts:
    - nmaprun args (preserved into ScanMeta.args)
    - timestamp from nmaprun start (epoch seconds) or current time if missing
    - host IPv4 address if present (else first address)
    - per-port number, protocol, state, and service fields (name/product/version/extrainfo)
    """
    tree = ET.parse(str(path))
    root = tree.getroot()

    # Meta
    now = datetime.now()
    start_ts = None
    args_list = []
    if root is not None:
        start_str = _get_attr(root, "start")
        if start_str and start_str.isdigit():
            start_ts = int(start_str)
        args_attr = _get_attr(root, "args")
        if args_attr:
            try:
                args_list = shlex.split(args_attr)
            except Exception:
                # Fallback: naive split
                args_list = args_attr.split()

    timestamp = datetime.fromtimestamp(start_ts) if start_ts is not None else now
    scan_id = f"nmap:{int(start_ts) if start_ts is not None else int(now.timestamp())}:{path.name}"
    meta = ScanMeta(scan_id=scan_id, timestamp=timestamp, args=args_list)

    findings: list[PortFinding] = []

    # Iterate hosts
    for host_elem in root.findall("host"):
        # Prefer IPv4 address; fallback to first address
        ipv4 = None
        first_addr = None
        for addr_elem in host_elem.findall("address"):
            addrtype = _get_attr(addr_elem, "addrtype", "")
            addrval = _get_attr(addr_elem, "addr")
            if not first_addr and addrval:
                first_addr = addrval
            if addrtype.lower() == "ipv4" and addrval:
                ipv4 = addrval
                break
        host_addr = ipv4 or first_addr
        if not host_addr:
            continue

        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            continue
        for p in ports_elem.findall("port"):
            portid = _get_attr(p, "portid")
            proto = _get_attr(p, "protocol", "tcp") or "tcp"
            if not portid or not portid.isdigit():
                continue
            state_val = "unknown"
            st = p.find("state")
            if st is not None:
                state_val = _get_attr(st, "state", state_val) or state_val

            svc = p.find("service")
            svc_name = svc_product = svc_version = svc_extrainfo = None
            if svc is not None:
                svc_name = _get_attr(svc, "name")
                svc_product = _get_attr(svc, "product")
                svc_version = _get_attr(svc, "version")
                svc_extrainfo = _get_attr(svc, "extrainfo")

            findings.append(
                PortFinding(
                    host=host_addr,
                    ip=host_addr,
                    port=int(portid),
                    protocol=proto,  # type: ignore[arg-type]
                    state=state_val,
                    service=svc_name,
                    product=svc_product,
                    version=svc_version,
                    extrainfo=svc_extrainfo,
                )
            )

    return HostScanResult(meta=meta, findings=findings)


def extract_nmap_hostnames(path: Path) -> list[str]:
    """Extract hostnames from Nmap XML hostnames entries."""
    tree = ET.parse(str(path))
    root = tree.getroot()
    hostnames: list[str] = []
    for host_elem in root.findall("host"):
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is None:
            continue
        for hostname_elem in hostnames_elem.findall("hostname"):
            name = _get_attr(hostname_elem, "name")
            if name:
                hostnames.append(name)
    return hostnames
