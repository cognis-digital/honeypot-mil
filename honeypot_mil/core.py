"""honeypot-mil — enrich honeypot events with attribution + IOC export.

Pairs with T-Pot / Cowrie / Honeyd / Dionaea. We don't ship the honeypot
itself — we ship the analysis layer.
"""
from __future__ import annotations
import csv
import ipaddress
import io
import json
import sys
import time
import uuid
from collections import defaultdict
from pathlib import Path

from cognis_mil import Finding, ScanResult, Severity

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
    """Return True if *ip* falls within a known bogon/RFC-reserved prefix."""
    if not ip or not isinstance(ip, str):
        return False
    try:
        addr = ipaddress.ip_address(ip.strip())
        return any(addr in ipaddress.ip_network(p) for p in KNOWN_BAD_PREFIXES)
    except ValueError:
        return False


def fingerprint_tool(payload: str) -> str:
    """Return tool name if *payload* matches a known scanner signature, else ''."""
    if not payload or not isinstance(payload, str):
        return ""
    for sig, tool in TOOL_SIGNATURES.items():
        if sig in payload:
            return tool
    return ""


def parse_events(path: Path) -> list[dict]:
    """Accept JSONL with at least: ts, src_ip, dst_port, protocol, payload.

    Returns a (possibly empty) list of dicts. Skips malformed lines with a
    warning to stderr rather than silently discarding them.
    """
    path = Path(path)
    if path.suffix != ".jsonl":
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"[honeypot-mil] warning: cannot read {path}: {exc}", file=sys.stderr)
        return []
    out: list[dict] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            print(
                f"[honeypot-mil] warning: malformed JSON"
                f" on line {lineno} of {path}: {exc}",
                file=sys.stderr,
            )
            continue
        if not isinstance(obj, dict):
            print(
                f"[honeypot-mil] warning: non-object JSON"
                f" on line {lineno} of {path}",
                file=sys.stderr,
            )
            continue
        out.append(obj)
    return out


def scan(target=".", **opts):
    """Scan *target* (file or directory) and return a :class:`ScanResult`."""
    r = ScanResult(tool_name="honeypot-mil", tool_version="0.1.0")
    p = Path(target)

    if not p.exists():
        print(
            f"[honeypot-mil] error: target does not exist: {target}",
            file=sys.stderr,
        )
        r.finalize()
        return r

    files: list[Path]
    if p.is_dir():
        files = list(p.glob("*.jsonl"))
    else:
        if not p.is_file():
            print(
                f"[honeypot-mil] error: target is not a file or directory: {target}",
                file=sys.stderr,
            )
            r.finalize()
            return r
        files = [p]

    events: list[dict] = []
    for f in files:
        events.extend(parse_events(f))

    r.items_scanned = len(events)

    if not events:
        r.finalize()
        return r

    # Aggregate by IP
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        src = e.get("src_ip")
        if not src or not isinstance(src, str):
            continue
        by_ip[src].append(e)

    for ip, ev_list in by_ip.items():
        tools = {fingerprint_tool(e.get("payload", "")) for e in ev_list} - {""}
        ports: set = {e.get("dst_port") for e in ev_list}
        ports.discard(None)
        if is_bogon(ip):
            r.add(Finding(
                f"HP-BOGON-{ip[:15]}", Severity.LOW,
                f"Bogon source IP: {ip}",
                remediation="Likely spoofed; check upstream firewall.",
            ))
        if len(ports) >= 5:
            r.add(Finding(
                f"HP-PORTSCAN-{ip[:15]}", Severity.HIGH,
                f"Port-scan from {ip} ({len(ports)} ports in {len(ev_list)} events)",
                location=ip,
                mitre_attack="T1046",
                remediation="Add to block list; submit IOC to CISA AIS / ISAC.",
            ))
        if tools:
            r.add(Finding(
                f"HP-TOOL-{ip[:15]}", Severity.MODERATE,
                f"{ip} fingerprinted as: {','.join(sorted(tools))}",
                mitre_attack="T1595.002",
                remediation="Tag in IOC feed; share via STIX/TAXII.",
            ))

    r.finalize()
    return r


# STIX 2.1 export (minimal Indicator + Identity)
def to_stix_bundle(result: ScanResult, identity_name: str = "Cognis Honeypot") -> str:
    """Return a STIX 2.1 bundle JSON string for all findings in *result*."""
    if not isinstance(identity_name, str) or not identity_name.strip():
        identity_name = "Cognis Honeypot"

    identity_id = f"identity--{uuid.uuid4()}"
    objects: list[dict] = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": "2026-01-01T00:00:00Z", "modified": "2026-01-01T00:00:00Z",
        "name": identity_name, "identity_class": "organization",
    }]

    for f in result.findings:
        # Prefer an explicit location; fall back to parsing the title safely.
        ip = f.location or ""
        if not ip:
            parts = f.title.split(": ", 1)
            if len(parts) > 1:
                candidate = parts[1].split()[0] if parts[1].split() else ""
                ip = candidate if candidate else "unknown"
            else:
                ip = "unknown"

        objects.append({
            "type": "indicator", "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": "2026-01-01T00:00:00Z", "modified": "2026-01-01T00:00:00Z",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00Z",
            "labels": ["malicious-activity"],
            "description": f.title,
            "external_references": (
                [{"source_name": "mitre-attack", "external_id": f.mitre_attack}]
                if f.mitre_attack else []
            ),
        })

    return json.dumps(
        {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects},
        indent=2,
    )


def to_cisa_ais(result: ScanResult) -> str:
    """Minimal CISA Automated Indicator Sharing payload (TAXII-friendly CSV)."""
    rows = [["indicator", "type", "first_seen", "confidence", "comment"]]
    for f in result.findings:
        if f.id.startswith("HP-PORTSCAN") or f.id.startswith("HP-TOOL"):
            indicator = f.location or "unknown"
            rows.append([
                indicator, "ipv4-addr",
                time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "high",
                f.title,
            ])
    buf = io.StringIO()
    csv.writer(buf).writerows(rows)
    return buf.getvalue()
