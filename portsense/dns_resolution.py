from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import ipaddress
import socket
from typing import Iterable, List, Sequence

from .models import DnsResolutionEntry, FindingAssessment
from .utils.time import now_utc


_VALUE_OPTS = {
    "-oX",
    "-oN",
    "-oA",
    "-oG",
    "-iL",
    "-iR",
    "-p",
    "-S",
    "-e",
    "-g",
    "-T",
    "--source-port",
    "--scan-delay",
    "--max-rate",
    "--min-rate",
    "--min-parallelism",
    "--max-parallelism",
    "--exclude",
    "--exclude-file",
    "--top-ports",
    "--script",
    "--script-args",
    "--script-args-file",
    "--stylesheet",
}


def extract_targets_from_args(args: Sequence[str]) -> List[str]:
    targets: List[str] = []
    skip_next = False
    for token in args:
        if skip_next:
            skip_next = False
            continue
        if token == "nmap":
            continue
        if token.startswith("-"):
            if token in _VALUE_OPTS:
                skip_next = True
            continue
        targets.append(token)
    return targets


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _classify_target(target: str) -> str:
    if _is_ip_address(target) or "/" in target:
        return "ip"
    return "domain"


def _getaddrinfo_with_timeout(target: str, timeout: float) -> list[tuple]:
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(socket.getaddrinfo, target, None)
        return future.result(timeout=timeout)


def resolve_target(target: str, timeout: float) -> DnsResolutionEntry:
    target_type = _classify_target(target)
    resolved_at = now_utc().isoformat()
    method = "socket.getaddrinfo"

    if target_type == "ip":
        return DnsResolutionEntry(
            target=target,
            type="ip",
            status="skipped",
            resolved_at=resolved_at,
            method=method,
        )

    try:
        records = _getaddrinfo_with_timeout(target, timeout)
        a_records = set()
        aaaa_records = set()
        for family, _, _, _, sockaddr in records:
            if family == socket.AF_INET and sockaddr:
                a_records.add(sockaddr[0])
            elif family == socket.AF_INET6 and sockaddr:
                aaaa_records.add(sockaddr[0])
        a_list = sorted(a_records)
        aaaa_list = sorted(aaaa_records)
        if not a_list and not aaaa_list:
            raise socket.gaierror("no records")
        return DnsResolutionEntry(
            target=target,
            type="domain",
            a=a_list,
            aaaa=aaaa_list,
            status="ok",
            resolved_at=resolved_at,
            method=method,
        )
    except FutureTimeout:
        return DnsResolutionEntry(
            target=target,
            type="domain",
            status="failed",
            error="timeout",
            resolved_at=resolved_at,
            method=method,
        )
    except Exception as exc:
        return DnsResolutionEntry(
            target=target,
            type="domain",
            status="failed",
            error=str(exc),
            resolved_at=resolved_at,
            method=method,
        )


def resolve_targets(targets: Iterable[str], timeout: float) -> List[DnsResolutionEntry]:
    seen: set[str] = set()
    entries: List[DnsResolutionEntry] = []
    for target in targets:
        normalized = target.strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        entries.append(resolve_target(normalized, timeout))
    return entries


def append_dns_confidence_rationale(
    assessments: List[FindingAssessment],
    dns_entries: Iterable[DnsResolutionEntry],
) -> None:
    lines: List[str] = []
    for entry in dns_entries:
        if entry.type != "domain":
            continue
        if entry.status == "ok":
            total = len(entry.a) + len(entry.aaaa)
            if total > 1:
                lines.append(
                    f"DNS resolution for {entry.target} returned {total} IPs; "
                    "scan results may vary across IPs (round-robin/CDN)."
                )
        elif entry.status == "failed":
            lines.append(
                f"DNS resolution failed for {entry.target}; scan reliability may be reduced."
            )
    if not lines:
        return
    for assessment in assessments:
        for line in lines:
            if line not in assessment.confidence.rationale:
                assessment.confidence.rationale.append(line)
