from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Literal

from pydantic import BaseModel, Field


class Service(BaseModel):
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


class Port(BaseModel):
    portid: int
    protocol: str = Field(default="tcp")
    state: str = Field(default="unknown")  # e.g., open/closed/filtered
    service: Optional[Service] = None


class Host(BaseModel):
    address: str
    hostname: Optional[str] = None
    ports: List[Port] = Field(default_factory=list)


class ScanMetadata(BaseModel):
    tool: str = Field(default="nmap")
    started: Optional[datetime] = None
    finished: Optional[datetime] = None


class ScanResult(BaseModel):
    metadata: ScanMetadata = Field(default_factory=ScanMetadata)
    hosts: List[Host] = Field(default_factory=list)


class RiskBreakdown(BaseModel):
    high: int = 0
    medium: int = 0
    low: int = 0


class RiskAssessment(BaseModel):
    score: float = 0.0  # 0-100
    level: str = "low"  # low/medium/high
    breakdown: RiskBreakdown = Field(default_factory=RiskBreakdown)


class ConfidenceAssessment(BaseModel):
    score: float = 0.0  # 0-1
    rationale: str = ""


# =====================
# Normalized data models
# =====================

class ScanEnv(BaseModel):
    name: str
    description: Optional[str] = None


class ScanMeta(BaseModel):
    scan_id: str
    tool: Literal["nmap"] = "nmap"
    timestamp: datetime
    scan_env: Optional[ScanEnv] = None
    args: List[str] = Field(default_factory=list)


class PortFinding(BaseModel):
    host: str
    ip: Optional[str] = None
    port: int
    protocol: Literal["tcp", "udp"] = "tcp"
    state: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None


class HostScanResult(BaseModel):
    meta: ScanMeta
    findings: List[PortFinding] = Field(default_factory=list)


class RiskRating(BaseModel):
    level: Literal["Critical", "High", "Medium", "Low", "Info"]
    reasons: List[str] = Field(default_factory=list)


class ConfidenceRating(BaseModel):
    level: Literal["High", "Medium", "Low"]
    rationale: List[str] = Field(default_factory=list)
    env_count: int = 0
    open_count: int = 0


class FindingAssessment(BaseModel):
    finding: PortFinding
    risk: RiskRating
    confidence: ConfidenceRating
    # Optional evidence for this finding (e.g., web screenshots)
    class Evidence(BaseModel):
        url: Optional[str] = None
        screenshot_path: Optional[str] = None  # prefer relative to outdir
        captured_at: Optional[datetime] = None
        status: Optional[Literal["ok", "failed", "skipped"]] = None
        error: Optional[str] = None

    evidence: Optional[Evidence] = None


class DnsResolutionEntry(BaseModel):
    target: str
    type: Literal["domain", "ip"]
    a: List[str] = Field(default_factory=list)
    aaaa: List[str] = Field(default_factory=list)
    status: Literal["ok", "failed", "skipped"]
    error: Optional[str] = None
    resolved_at: Optional[str] = None
    method: Optional[str] = None


class ReportModel(BaseModel):
    target: str
    generated_at: datetime
    summary_hosts: int
    summary_open_ports: int
    summary_findings: int
    assessments: List[FindingAssessment] = Field(default_factory=list)
    dns_resolution: Optional[List[DnsResolutionEntry]] = None
