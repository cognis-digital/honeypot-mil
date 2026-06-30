# honeypot-mil — Honeypot event enrichment + IOC export

[![CI](https://github.com/cognis-digital/honeypot-mil/workflows/CI/badge.svg)](https://github.com/cognis-digital/honeypot-mil/actions)
[![Classification](https://img.shields.io/badge/classification-UNCLASSIFIED-green.svg)](./UPSTREAM.md)

> Ingest honeypot events (T-Pot/Cowrie/Honeyd), enrich with ATT&CK + tool fingerprints, export to STIX/CISA AIS.


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ honeypot-mil-emit --version
honeypot-mil 0.1.0
```

```console
$ honeypot-mil-emit --help
usage: honeypot-mil [-h] [--format {console,json,markdown,sarif,oscal}]
                    [--out OUT] [--fail-on {very_high,high,moderate,low,none}]
                    [--classification CLASSIFICATION] [-v]
                    [target]

honeypot-mil — Cognis Digital · Military/IC ecosystem

positional arguments:
  target                Path/target

options:
  -h, --help            show this help message and exit
  --format {console,json,markdown,sarif,oscal}
  --out OUT             Write output to file
  --fail-on {very_high,high,moderate,low,none}
  --classification CLASSIFICATION
                        Operator-supplied banner. PLACEHOLDER. Tool does not
                        interpret.
  -v, --version         show program's version number and exit
```

> Blocks above are real `honeypot-mil` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
"timestamp": "2023-02-15T14:30:00Z",
"findings": [
  {
    "id": "1234567890",
    "title": "Suspicious Connection",
    "description": "A honeypot detected a suspicious connection from IP address 192.168.1.100.",
    "tlp": "WHITE",
    "labels": ["Honeypot", "Network"],
    "observed_data": {
      "connection": {
        "src_ip": "192.168.1.100",
        "dst_ip": "honeypot-mil.local"
      }
    }
  },
  {
    "id": "2345678900",
    "title": "Malware Download",
    "description": "A honeypot detected a malware download from IP address 192.168.1.200.",
    "tlp": "GREEN",
    "labels": ["Honeypot", "Network"],
    "observed_data": {
      "download": {
        "src_ip": "192.168.1.200",
        "dst_ip": "honeypot-mil.local"
      }
    }
  }
]
}
```

<!-- cognis:example:end -->

## Usage — step by step

`honeypot-mil` enriches honeypot event logs (attribution + IOC extraction) and exports indicators in a TAXII-friendly form.

1. **Install:**

   ```bash
   pip install cognis-honeypot-mil      # or: pip install -e .
   honeypot-mil --version
   ```

2. **Run a scan** over honeypot events — supply a directory containing JSONL with at least `ts, src_ip, dst_port, protocol, payload` (`target` defaults to `.`):

   ```bash
   honeypot-mil ./events --format console
   ```

3. **Emit JSON** and save it (formats: `console`, `json`, `markdown`, `sarif`, `oscal`):

   ```bash
   honeypot-mil ./events --format json --out honeypot-findings.json
   ```

4. **Read the result** — findings include bogon sources (`HP-BOGON-*`), port-scans (`HP-PORTSCAN-*`), and known-tool fingerprints (`HP-TOOL-*`):

   ```bash
   jq '.findings[] | {id, severity, message}' honeypot-findings.json
   ```

5. **Gate it in CI** — alert (non-zero exit) when high-severity attacker activity is enriched:

   ```bash
   honeypot-mil ./events --format sarif --out honeypot.sarif --fail-on high
   ```

## Upstream

Forks / wraps **https://github.com/telekom-security/tpotce**. See [`UPSTREAM.md`](./UPSTREAM.md) for the
licensing posture, supported commits, and how to upgrade.

## What this adds for military / IC use

- Port-scan detector
- Common-tool fingerprint library
- Bogon source-IP detector
- STIX 2.1 + CISA AIS exporters

## Install

```bash
# Shared library (only once for the whole ecosystem):
pip install -e ../../shared

# This tool:
pip install -e .
```

## Demo

```bash
honeypot-mil demos/events.jsonl
```

Outputs are available in five formats — all respect an operator-supplied
classification banner (passed via `--classification`):

```bash
honeypot-mil <target> --format=console     # default
honeypot-mil <target> --format=json
honeypot-mil <target> --format=sarif       # for code-scanning pipelines
honeypot-mil <target> --format=markdown    # for PRs / briefings
honeypot-mil <target> --format=oscal       # OSCAL Assessment Results skeleton
```

## Classification banner

All output is wrapped with an operator-supplied classification banner.
**Default**: `UNCLASSIFIED//FOR PUBLIC RELEASE`.

> ⚠️ This tool **does not** generate or validate the *content* of higher
> classifications. Operators on cleared systems supply real markings at runtime.
> See [`../shared/cognis_mil/classmark.py`](../../shared/cognis_mil/classmark.py).

## Compliance crosswalks (built in)

Every finding can carry references to:
- **NIST 800-53 Rev 5** controls (e.g. `AC-2(1)`)
- **DISA STIG** rule IDs (e.g. `V-242414`)
- **MITRE ATT&CK** technique IDs (e.g. `T1078`)
- **CCI** (Control Correlation Identifier)

These are emitted in JSON, SARIF, and the OSCAL skeleton.

## CI / RMF integration

```yaml
- name: honeypot-mil scan
  run: |
    pip install cognis-honeypot-mil
    honeypot-mil . --format=oscal --out=assessment-results.json --fail-on=high
- name: Upload to eMASS/Xacta
  run: cognis-rmf-package import assessment-results.json
```

## Part of the Cognis Digital military / IC ecosystem

12 repos. All MIT/COCL (Cognis Open Collaboration License)/GPL-3 (per upstream). Cognis additions are
COCL (Cognis Open Collaboration License) unless stated otherwise.

See [the master index](../../MASTER-INDEX.md).

## Interoperability

`honeypot-mil` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## Integrations

Forward `honeypot-mil`'s findings to STIX/MISP/Sigma/Splunk/Elastic/Slack/webhooks via
[`cognis-connect`](https://github.com/cognis-digital/cognis-connect). See **[INTEGRATIONS.md](INTEGRATIONS.md)**.
