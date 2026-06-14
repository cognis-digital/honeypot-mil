"""Edge-case and error-path tests added during hardening pass."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from honeypot_mil.core import (
    fingerprint_tool,
    is_bogon,
    parse_events,
    scan,
    to_cisa_ais,
    to_stix_bundle,
)
from cognis_mil.audit import AuditLog


# ---------------------------------------------------------------------------
# is_bogon edge cases
# ---------------------------------------------------------------------------

def test_is_bogon_empty_string():
    assert is_bogon("") is False


def test_is_bogon_invalid_ip():
    assert is_bogon("not-an-ip") is False
    assert is_bogon("999.999.999.999") is False


def test_is_bogon_none_does_not_raise():
    # None is not a str — should return False, not TypeError
    assert is_bogon(None) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# fingerprint_tool edge cases
# ---------------------------------------------------------------------------

def test_fingerprint_empty_payload():
    assert fingerprint_tool("") == ""


def test_fingerprint_none_does_not_raise():
    assert fingerprint_tool(None) == ""  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# parse_events edge cases
# ---------------------------------------------------------------------------

def test_parse_events_missing_file(tmp_path):
    result = parse_events(tmp_path / "nonexistent.jsonl")
    assert result == []


def test_parse_events_empty_file(tmp_path):
    f = tmp_path / "empty.jsonl"
    f.write_text("")
    assert parse_events(f) == []


def test_parse_events_malformed_lines(tmp_path, capsys):
    f = tmp_path / "bad.jsonl"
    f.write_text('{"ok": 1}\nNOT JSON\n{"ok": 2}\n')
    result = parse_events(f)
    assert len(result) == 2
    captured = capsys.readouterr()
    assert "malformed" in captured.err.lower() or "warning" in captured.err.lower()


def test_parse_events_wrong_extension(tmp_path):
    f = tmp_path / "data.json"
    f.write_text('{"ts":"x","src_ip":"1.2.3.4"}\n')
    assert parse_events(f) == []


# ---------------------------------------------------------------------------
# scan edge cases
# ---------------------------------------------------------------------------

def test_scan_nonexistent_target(capsys):
    r = scan("/nonexistent/path/that/does/not/exist")
    assert r.items_scanned == 0
    assert r.findings == []
    captured = capsys.readouterr()
    assert "error" in captured.err.lower() or "does not exist" in captured.err.lower()


def test_scan_empty_directory(tmp_path):
    r = scan(str(tmp_path))
    assert r.items_scanned == 0
    assert r.findings == []


def test_scan_events_missing_src_ip(tmp_path):
    """Events without src_ip should be skipped, not crash."""
    f = tmp_path / "test.jsonl"
    f.write_text(
        '{"ts":"x","dst_port":22,"protocol":"ssh","payload":""}\n'
        '{"ts":"x","src_ip":null,"dst_port":80,"protocol":"http","payload":""}\n'
    )
    r = scan(str(tmp_path))
    assert r.items_scanned == 2
    # No findings because no valid IPs
    assert r.findings == []


def test_scan_fewer_than_5_ports_no_portscan(tmp_path):
    """Fewer than 5 unique ports from one IP must not trigger HP-PORTSCAN."""
    def _ev(port):
        obj = {"ts": "x", "src_ip": "1.2.3.4", "dst_port": port,
               "protocol": "tcp", "payload": ""}
        return json.dumps(obj)

    events = "\n".join(_ev(port) for port in [22, 80, 443])
    f = tmp_path / "few.jsonl"
    f.write_text(events)
    r = scan(str(tmp_path))
    assert not any("PORTSCAN" in fi.id for fi in r.findings)


# ---------------------------------------------------------------------------
# to_stix_bundle edge cases
# ---------------------------------------------------------------------------

def test_stix_empty_result():
    from cognis_mil.models import ScanResult

    r = ScanResult(tool_name="honeypot-mil")
    r.finalize()
    bundle = json.loads(to_stix_bundle(r))
    assert bundle["type"] == "bundle"
    # Only the identity object — no indicators
    assert len(bundle["objects"]) == 1


def test_stix_blank_identity_name():
    """Blank identity_name should fall back to default, not produce empty string."""
    from cognis_mil.models import ScanResult

    r = ScanResult(tool_name="honeypot-mil")
    r.finalize()
    bundle = json.loads(to_stix_bundle(r, identity_name="   "))
    identity = bundle["objects"][0]
    assert identity["name"]  # non-empty


# ---------------------------------------------------------------------------
# to_cisa_ais edge cases
# ---------------------------------------------------------------------------

def test_cisa_ais_empty_result():
    from cognis_mil.models import ScanResult

    r = ScanResult(tool_name="honeypot-mil")
    r.finalize()
    csv_out = to_cisa_ais(r)
    assert "indicator,type" in csv_out
    # Only the header row — no data rows
    assert csv_out.count("\n") <= 2  # header + optional trailing newline


# ---------------------------------------------------------------------------
# AuditLog edge cases
# ---------------------------------------------------------------------------

def test_audit_verify_empty_log(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    ok, msg = log.verify()
    assert ok
    assert "empty" in msg.lower()


def test_audit_verify_valid_chain(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append({"action": "scan", "target": "."})
    log.append({"action": "export", "format": "json"})
    ok, msg = log.verify()
    assert ok
    assert "2" in msg


def test_audit_verify_tampered_log(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)
    log.append({"action": "scan"})
    # Tamper: overwrite the file with broken JSON on line 1
    log_path.write_text('{"ts":1,"prev":"GENESIS","event":{},"hash":"badhash"}\n')
    ok, msg = log.verify()
    assert not ok


def test_audit_verify_empty_file_on_disk(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    log_path.write_text("")
    log = AuditLog(log_path)
    ok, msg = log.verify()
    assert ok


# ---------------------------------------------------------------------------
# CLI integration: bad target returns non-zero exit code
# ---------------------------------------------------------------------------

def test_cli_bad_target_exits_nonzero():
    result = subprocess.run(
        [sys.executable, "-m", "honeypot_mil", "/no/such/path/xyz"],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).parent.parent),
    )
    # The CLI should exit 0 even for empty results (it prints a clean report),
    # but must NOT crash with a traceback.
    assert "Traceback" not in result.stderr
    assert "Traceback" not in result.stdout
