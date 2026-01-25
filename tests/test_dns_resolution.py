import json
import socket
from pathlib import Path

from typer.testing import CliRunner

from portsense.cli import app


SAMPLE_XML_DOMAIN = """
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX scan.xml example.com" start="1704067200" startstr="Wed Jan  1 00:00:00 2024" version="7.94" xmloutputversion="1.05">
  <host>
    <status state="up" reason="syn-ack" reason_ttl="0"/>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="example.com" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _run_cli_with_dns(tmp_path: Path) -> dict:
    runner = CliRunner()
    xml_path = tmp_path / "scan.xml"
    xml_path.write_text(SAMPLE_XML_DOMAIN.strip(), encoding="utf-8")
    outdir = tmp_path / "out"
    result = runner.invoke(app, ["analyze", "-i", str(xml_path), "--outdir", str(outdir), "--dns"])
    assert result.exit_code == 0, result.output
    return json.loads((outdir / "report.json").read_text(encoding="utf-8"))


def test_dns_resolution_attached(monkeypatch, tmp_path: Path):
    calls: list[str] = []

    def fake_getaddrinfo(host, *_args, **_kwargs):
        calls.append(host)
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    data = _run_cli_with_dns(tmp_path)

    assert calls == ["example.com"]
    assert data["dns_resolution"][0]["target"] == "example.com"
    assert data["dns_resolution"][0]["status"] == "ok"


def test_dns_multiple_ips_appends_rationale(monkeypatch, tmp_path: Path):
    def fake_getaddrinfo(host, *_args, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.35", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    data = _run_cli_with_dns(tmp_path)

    rationale = data["assessments"][0]["confidence"]["rationale"]
    assert any("DNS resolution for example.com returned 2 IPs" in line for line in rationale)


def test_dns_failure_records_failed_status(monkeypatch, tmp_path: Path):
    def fake_getaddrinfo(host, *_args, **_kwargs):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    data = _run_cli_with_dns(tmp_path)

    assert data["dns_resolution"][0]["status"] == "failed"
