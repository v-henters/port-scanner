import json
from pathlib import Path
import tempfile
from unittest.mock import patch, MagicMock

from typer.testing import CliRunner
from portsense.cli import app

SAMPLE_XML = """
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX scan.xml 127.0.0.1" start="1704067200" startstr="Wed Jan  1 00:00:00 2024" version="7.94" xmloutputversion="1.05">
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

@patch("portsense.vuln.nuclei.subprocess.Popen")
def test_cli_nuclei_integration(mock_popen):
    # Setup mock Popen
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.communicate.return_value = ("stdout", "stderr")
    mock_popen.return_value = mock_process
    
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        xml_path = td_path / "scan.xml"
        xml_path.write_text(SAMPLE_XML.strip(), encoding="utf-8")
        
        outdir = td_path / "out"
        n_jsonl = outdir / "nuclei" / "results.jsonl"
        
        # We need to ensure the directory exists so the mock can "write" to it or we write a dummy file
        n_jsonl.parent.mkdir(parents=True, exist_ok=True)
        dummy_finding = {
            "template-id": "test-template",
            "info": {"name": "Test Finding", "severity": "high"},
            "matched-at": "http://127.0.0.1:80",
            "host": "127.0.0.1"
        }
        with open(n_jsonl, "w") as f:
            f.write(json.dumps(dummy_finding) + "\n")
            
        result = runner.invoke(app, [
            "analyze", 
            "-i", str(xml_path), 
            "--outdir", str(outdir),
            "--nuclei"
        ])
        
        assert result.exit_code == 0
        assert "[nuclei] starting vulnerability scan..." in result.output
        assert "[nuclei] finished: 1 findings" in result.output
        
        # Verify JSON report
        report_json = json.loads((outdir / "report.json").read_text())
        assert "nuclei" in report_json
        assert report_json["nuclei"]["enabled"] is True
        assert report_json["nuclei"]["finding_count"] == 1
        assert len(report_json["vulnerability_findings"]) == 1
        assert report_json["vulnerability_findings"][0]["template_id"] == "test-template"
        
        # Verify MD report
        report_md = (outdir / "report.md").read_text()
        assert "## Vulnerability Findings (Nuclei)" in report_md
        assert "test-template" in report_md
        assert "Test Finding" in report_md
