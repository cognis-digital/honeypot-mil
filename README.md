# honeypot-mil — Honeypot event enrichment + IOC export

[![CI](https://github.com/cognis-digital/honeypot-mil/workflows/CI/badge.svg)](https://github.com/cognis-digital/honeypot-mil/actions)
[![Classification](https://img.shields.io/badge/classification-UNCLASSIFIED-green.svg)](./UPSTREAM.md)

> Ingest honeypot events (T-Pot/Cowrie/Honeyd), enrich with ATT&CK + tool fingerprints, export to STIX/CISA AIS.

<!-- cognis:layman:start -->
## What is this?

honeypot-mil reads activity logs from network honeypots -- decoy servers set up to attract and record malicious traffic -- and tells you who is probing your network and how. It automatically flags suspicious IP addresses, identifies the hacking tools attackers are using (such as Nmap or Masscan), and marks traffic coming from spoofed or internal addresses that should never appear on public internet. Security teams and government network defenders can use it to export those findings in standard formats (STIX, CISA AIS) so the threat intelligence can be shared with partner agencies or fed into automated blocking systems.
<!-- cognis:layman:end -->

## Upstream

Forks / wraps **https://github.com/telekom-security/tpotce**. See [`UPSTREAM.md`](./UPSTREAM.md) for the
licensing posture, supported commits, and how to upgrade.

## What this adds for military / IC use

- Port-scan detector
- Common-tool fingerprint library
- Bogon source-IP detector
- STIX 2.1 + CISA AIS exporters

<!-- cognis:domains:start -->
## Domains

**Primary domain:** Cyber & Security  ·  **JTF MERIDIAN division:** NULLBYTE · SPECTER

**Topics:** `cognis` `security` `infosec` `cybersecurity` `blue-team` `threat-intel`

Part of the **Cognis Neural Suite** — 300+ source-available tools organized across 12 domains under the JTF MERIDIAN command structure. See the [suite on GitHub](https://github.com/cognis-digital) and [jtf-meridian](https://github.com/cognis-digital/jtf-meridian) for how the pieces fit together.
<!-- cognis:domains:end -->

<!-- cognis:install:start -->
## Install

`honeypot-mil` is source-available (not published to PyPI) — every method below installs
straight from GitHub. Pick whichever you prefer; the one-line scripts auto-detect
the best tool available on your machine.

**One-liner (Linux / macOS):**
```sh
curl -fsSL https://raw.githubusercontent.com/cognis-digital/honeypot-mil/HEAD/install.sh | sh
```

**One-liner (Windows PowerShell):**
```powershell
irm https://raw.githubusercontent.com/cognis-digital/honeypot-mil/HEAD/install.ps1 | iex
```

**Or install manually — any one of:**
```sh
pipx install "git+https://github.com/cognis-digital/honeypot-mil.git"     # isolated (recommended)
uv tool install "git+https://github.com/cognis-digital/honeypot-mil.git"  # uv
pip install "git+https://github.com/cognis-digital/honeypot-mil.git"      # pip
```

**From source:**
```sh
git clone https://github.com/cognis-digital/honeypot-mil.git
cd honeypot-mil && pip install .
```

Then run:
```sh
honeypot-mil --help
```
<!-- cognis:install:end -->

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
    pip install "git+https://github.com/cognis-digital/honeypot-mil.git"
    honeypot-mil . --format=oscal --out=assessment-results.json --fail-on=high
- name: Upload to eMASS/Xacta
  run: cognis-rmf-package import assessment-results.json
```

## Part of the Cognis Digital military / IC ecosystem

12 repos. All MIT/Apache-2.0/GPL-3 (per upstream). Cognis additions are
Apache-2.0 unless stated otherwise.

See [the master index](../../MASTER-INDEX.md).
