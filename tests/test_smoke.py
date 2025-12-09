from pathlib import Path
from honeypot_mil.core import scan, is_bogon, fingerprint_tool, to_stix_bundle, to_cisa_ais
D = Path(__file__).parent.parent / "demos"
def test_bogon():
    assert is_bogon("10.0.0.1")
    assert not is_bogon("8.8.8.8")
def test_fingerprint():
    assert fingerprint_tool("User-Agent: Mozilla/5.0 (compatible; Nmap") == "nmap"
    assert fingerprint_tool("User-Agent: ZmEu") == "zmeu-scanner"
def test_scan():
    r = scan(str(D))
    ids = {f.id for f in r.findings}
    assert any("PORTSCAN" in i for i in ids)
    assert any("TOOL" in i for i in ids)
def test_stix():
    r = scan(str(D))
    stix = to_stix_bundle(r)
    assert '"type": "bundle"' in stix or '"type":"bundle"' in stix
def test_cisa():
    r = scan(str(D))
    assert "indicator,type" in to_cisa_ais(r)
