"""honeypot-mil — enrich honeypot events with attribution + IOC export.

Pairs with T-Pot / Cowrie / Honeyd / Dionaea. We don't ship the honeypot
itself — we ship the analysis layer.
"""
from __future__ import annotations
import json, csv, ipaddress, time
from pathlib import Path
from collections import defaultdict
from cognis_mil import ScanResult, Finding, Severity

# Public bogon / hostile-AS prefixes (placeholders, operator updates with current feed)
KNOWN_BAD_PREFIXES = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10",     # bogons (RFC 6890)
    "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4",
]
# Common-tool fingerprints (public)
TOOL_SIGNATURES = {
    "User-Agent: Mozilla/5.0 (compatible; Nmap": "nmap",
    "User-Agent: () { :;};":                     "shellshock-scanner",
    "User-Agent: Hello, world":                  "masscan",
    "User-Agent: ZmEu":                          "zmeu-scanner",
    "SSH-2.0-libssh":                            "libssh-based-scanner",
}

def is_bogon(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(p) for p in KNOWN_BAD_PREFIXES)
    except: return False

def fingerprint_tool(payload: str) -> str:
    for sig, tool in TOOL_SIGNATURES.items():
        if sig in payload: return tool
    return ""

def parse_events(path: Path) -> list[dict]:
    """Accept JSONL with at least: ts, src_ip, dst_port, protocol, payload."""
    if path.suffix == ".jsonl":
        out = []
        for line in path.read_text().splitlines():
            try: out.append(json.loads(line))
            except: pass
        return out
    return []

def scan(target=".", **opts):
    r = ScanResult(tool_name="honeypot-mil", tool_version="0.1.0")
    p = Path(target)
    files = list(p.glob("*.jsonl")) if p.is_dir() else [p]
    events = []
    for f in files:
        if f.is_file(): events.extend(parse_events(f))
    r.items_scanned = len(events)
    # Aggregate by IP
    by_ip = defaultdict(list)
    for e in events: by_ip[e.get("src_ip","?")].append(e)
    for ip, ev_list in by_ip.items():
        tools = {fingerprint_tool(e.get("payload","")) for e in ev_list} - {""}
        ports = {e.get("dst_port") for e in ev_list}
        ports.discard(None)
        if is_bogon(ip):
            r.add(Finding(f"HP-BOGON-{ip[:15]}", Severity.LOW,
                          f"Bogon source IP: {ip}",
                          remediation="Likely spoofed; check upstream firewall."))
        if len(ports) >= 5:
            r.add(Finding(f"HP-PORTSCAN-{ip[:15]}", Severity.HIGH,
                          f"Port-scan from {ip} ({len(ports)} ports in {len(ev_list)} events)",
                          location=ip,
                          mitre_attack="T1046",
                          remediation="Add to block list; submit IOC to CISA AIS / ISAC."))
        if tools:
            r.add(Finding(f"HP-TOOL-{ip[:15]}", Severity.MODERATE,
                          f"{ip} fingerprinted as: {','.join(tools)}",
                          mitre_attack="T1595.002",
                          remediation="Tag in IOC feed; share via STIX/TAXII."))
    r.finalize(); return r

# STIX 2.1 export (minimal Indicator + Identity)
def to_stix_bundle(result: ScanResult, identity_name="Cognis Honeypot") -> str:
    import uuid
    identity_id = f"identity--{uuid.uuid4()}"
    objects = [{
        "type":"identity","spec_version":"2.1","id":identity_id,
        "created": "2026-01-01T00:00:00Z","modified":"2026-01-01T00:00:00Z",
        "name": identity_name, "identity_class":"organization"
    }]
    for f in result.findings:
        # Extract IP from finding title
        ip = f.location or f.title.split(": ")[-1].split()[0]
        objects.append({
            "type":"indicator","spec_version":"2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created":"2026-01-01T00:00:00Z","modified":"2026-01-01T00:00:00Z",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00Z",
            "labels": ["malicious-activity"],
            "description": f.title,
            "external_references":[{"source_name":"mitre-attack","external_id":f.mitre_attack}] if f.mitre_attack else [],
        })
    return json.dumps({"type":"bundle","id": f"bundle--{uuid.uuid4()}", "objects": objects}, indent=2)

def to_cisa_ais(result: ScanResult) -> str:
    """Minimal CISA Automated Indicator Sharing payload (TAXII-friendly CSV)."""
    rows = [["indicator","type","first_seen","confidence","comment"]]
    for f in result.findings:
        if f.id.startswith("HP-PORTSCAN") or f.id.startswith("HP-TOOL"):
            rows.append([f.location, "ipv4-addr", time.strftime("%Y-%m-%dT%H:%M:%SZ"), "high", f.title])
    import io
    buf = io.StringIO(); csv.writer(buf).writerows(rows)
    return buf.getvalue()
