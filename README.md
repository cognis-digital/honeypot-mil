# honeypot-mil — Honeypot event enrichment + IOC export

[![CI](https://github.com/cognis-digital/honeypot-mil/workflows/CI/badge.svg)](https://github.com/cognis-digital/honeypot-mil/actions)
[![Classification](https://img.shields.io/badge/classification-UNCLASSIFIED-green.svg)](./UPSTREAM.md)

> Ingest honeypot events (T-Pot/Cowrie/Honeyd), enrich with ATT&CK + tool fingerprints, export to STIX/CISA AIS.

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

12 repos. All MIT/Apache-2.0/GPL-3 (per upstream). Cognis additions are
Apache-2.0 unless stated otherwise.

See [the master index](../../MASTER-INDEX.md).
