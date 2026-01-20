from pathlib import Path
import tempfile

from typer.testing import CliRunner

from portsense.cli import app


SAMPLE_XML = """
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX scan.xml 192.0.2.10" start="1704067200" startstr="Wed Jan  1 00:00:00 2024" version="7.94" xmloutputversion="1.05">
  <host>
    <status state="up" reason="syn-ack" reason_ttl="0"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="ssh" product="OpenSSH" version="8.9" extrainfo="protocol 2.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset" reason_ttl="0"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_cli_analyze_smoke_writes_reports():
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        xml_path = td_path / "scan.xml"
        xml_path.write_text(SAMPLE_XML.strip(), encoding="utf-8")

        outdir = td_path / "out"
        result = runner.invoke(app, ["analyze", "-i", str(xml_path), "--outdir", str(outdir)])

        assert result.exit_code == 0, result.output
        assert (outdir / "report.json").exists()
        assert (outdir / "report.md").exists()
