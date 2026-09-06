# AI Alert Triage Agent

A Tier-1 SOC triage agent that receives SIEM alerts and performs the first-pass
investigation automatically: it **correlates** events across sources, checks
**threat intelligence**, queries **user/asset context**, and produces an
**auditable investigative report** — verdict, severity, confidence, evidence
timeline, MITRE ATT&CK mapping, IoCs, and recommended containment actions.

Built on the architecture pattern used by production AI-SOC systems (CORTEX,
WARDEN, Aegis): deterministic machinery does the cheap work, the LLM only runs
where judgment is actually needed, and every decision is traceable to raw events.

```
synthetic telemetry        normalize ─▶ correlate ─▶ pre-filter ─▶ investigate ─▶ verdict + report
(4 sources, 20 scenarios)           (event      (tier 0:      (Claude agent       (dashboard,
                                     clustering   auto-close    with typed         reports)
                                     → cases)     noise, FREE)   tools)
```

## Why this design

| Tier | What it does | Cost |
|---|---|---|
| Pre-filter | Deterministic rules auto-resolve obvious noise (scheduled vuln scan, EICAR test file, backup service account, VPN roaming). Suppression requires a *positive reason*; an always-escalate ATT&CK list overrides any suppression. | 0 LLM tokens |
| Correlation | Windowed union-find clusters events by shared user/IP/host, transitive closure stitches an attacker's pivots into one campaign case. | 0 |
| Agent (LLM) | Claude investigates via typed tools only, and must commit a strict-schema verdict through `submit_verdict` — it cannot finish any other way. | tokens, but only for escalated/ambiguous cases |
| Fail-safe | No API key, an API error, or a step-limit miss? The deterministic engine produces a clearly-labeled fallback verdict. The queue never stalls. | 0 |

Everything the agent did — every tool call, every query, every lookup — is
persisted as an **audit trail** shown on the case page and in the markdown report.

## Quickstart

```bash
cd "Project 1"
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env            # optional: set ANTHROPIC_API_KEY
.venv/bin/python run.py generate     # build demo telemetry + cases
.venv/bin/python run.py serve        # dashboard at http://127.0.0.1:8000
```

Without an `ANTHROPIC_API_KEY` the agent runs entirely on the deterministic
fail-safe tier (fully functional, 0 tokens). Set the key to run real Claude
tool-use investigations:

```bash
.venv/bin/python run.py triage                 # LLM triage of all open cases
.venv/bin/python run.py triage --case case-003 # single case
.venv/bin/python run.py triage --dry-run       # deterministic only (no LLM)
.venv/bin/python run.py report                 # list reports
.venv/bin/python run.py report --case case-003 # print a full report
.venv/bin/python run.py status                 # dataset stats
```

## The dashboard

- `/` — alert queue: severity, status, verdict, confidence, triage buttons.
- `/case/{id}` — the full investigation: correlated alerts, entities with live
  threat-intel scores, evidence timeline, MITRE mapping, IoCs, recommended
  actions (destructive ones flagged for **human approval**), and the collapsible
  **agent tool trace**.
- `/api/cases`, `/api/case/{id}` — JSON API.

## The synthetic data

20 scenarios balanced across true positives / false positives / ambiguous,
spanning MITRE tactics: SSH brute force, impossible travel, phishing→C2 beacon,
MFA fatigue, PowerShell persistence, data exfiltration, LSASS dumping, PsExec
lateral movement, log clearing, crypto mining, web shell, plus benign noise
(vulnerability scanner, EICAR test, backup service, VPN travellers).

The headline demo is a **5-alert campaign**: Alice clicks a phishing email →
MFA fatigue prompts → sign-in from a Tor exit → scheduled-task persistence →
2.2 GB exfiltration. Correlation (via transitive closure) merges all five
detections from four log sources into a single critical incident.

## Wiring in real infrastructure

The LLM-facing surface is just **six typed tools**. Swapping the demo data for a
real stack means implementing those tool bodies against your SIEM/data lake:

| Tool | Demo backing | Swap for |
|---|---|---|
| `query_logs` | bundled SQLite event store | OpenSearch/Elasticsearch, Splunk, DuckDB lake |
| `get_user_context` | `context.py` dict | Identity provider / HR feed |
| `get_asset_context` | `context.py` dict | CMDB / asset inventory |
| `lookup_ip_reputation` | `intel/reputation.py` local table | set `ABUSEIPDB_API_KEY`, or GreyNoise/VirusTotal |
| `get_mitre_technique` | local ATT&CK KB | ATT&CK STIX feed |
| `submit_verdict` | store + report writer | TheHive/SOAR case API |

That mirrors how the tier-2 homelab stack (Wazuh / MISP / TheHive / Shuffle)
would plug into the same agent: Wazuh as `query_logs`, MISP as reputation,
TheHive as the verdict target.

## Testing

```bash
.venv/bin/python -m pytest tests/ -q
```

Covers dataset integrity, correlation behavior (campaign merge, no cross-case
pollution), pre-filter suppression rules, and schema-valid deterministic
verdicts — no API key required.

## Project layout

```
run.py                        CLI (generate / triage / report / serve / status)
src/triage/
  settings.py                 config via .env
  models.py                   Event, Alert, Case, Verdict schemas
  ingest/                     synthethic telemetry + normalizers
  correlate/engine.py         windowed union-find correlation
  agents/prefilter.py         deterministic tier-0 rules
  agents/tools.py             6 typed tools + submit_verdict schema
  agents/investigator.py      Claude tool-use loop with audit trace
  agents/deterministic.py     fail-safe rule-based investigator
  agents/orchestrator.py      end-to-end pipeline
  agents/context.py           org user/asset/ATT&CK context
  intel/reputation.py         threat-intel lookups (local + AbuseIPDB)
  report/builder.py           markdown + JSON reports
  store/storage.py            SQLite persistence
app/                          FastAPI dashboard (Jinja2 + static)
tests/                        pytest suite
```

## Limitations (intentional)

- Verdicts from the deterministic tier are low-depth by design; it exists as a
  safety net, not a replacement for the LLM.
- Synthetic data proves architecture, not recall. Real telemetry brings
  malformed timestamps, delayed delivery, and volume.
- Containment actions are **recommended only** — nothing is ever executed.# AI-Alert-Triage-Agent
