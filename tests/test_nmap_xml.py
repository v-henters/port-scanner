from pathlib import Path
from datetime import datetime
import tempfile

from portsense.parsing.nmap_xml import parse_nmap_xml


SAMPLE_XML = """
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX scan.xml 192.0.2.10" start="1704067200" startstr="Wed Jan  1 00:00:00 2024" version="7.94" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="2" services="22,80"/>
  <host>
    <status state="up" reason="syn-ack" reason_ttl="0"/>
    <address addr="2001:db8::1" addrtype="ipv6"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="example.test" type="user"/>
    </hostnames>
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
  <runstats>
    <finished time="1704067210" timestr="Wed Jan  1 00:00:10 2024"/>
  </runstats>
</nmaprun>
"""


def test_parse_nmap_xml_basic():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "scan.xml"
        p.write_text(SAMPLE_XML.strip(), encoding="utf-8")

        result = parse_nmap_xml(p)

        # Meta
        assert result.meta.tool == "nmap"
        assert result.meta.args[:3] == ["nmap", "-sV", "-oX"]
        assert result.meta.scan_id.startswith("nmap:")
        # Timestamp should be from start attribute
        assert isinstance(result.meta.timestamp, datetime)
        assert int(result.meta.timestamp.timestamp()) == 1704067200

        # Findings
        assert len(result.findings) == 2
        f22 = next(f for f in result.findings if f.port == 22)
        f80 = next(f for f in result.findings if f.port == 80)

        # Prefer IPv4
        assert f22.ip == "192.0.2.10"
        assert f22.host == "192.0.2.10"

        # Port/service fields
        assert f22.protocol == "tcp"
        assert f22.state == "open"
        assert f22.service == "ssh"
        assert f22.product == "OpenSSH"
        assert f22.version == "8.9"
        assert f22.extrainfo == "protocol 2.0"

        assert f80.state == "closed"
        assert f80.service == "http"
