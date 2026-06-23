# Aegis Latent Core — Hermes Agent Plugin

AI governance & threat detection for Hermes Agent. Scans every prompt and LLM
response for jailbreaks, prompt injection, malware, credential leaks, and
adversarial patterns — then visualises everything in a Threat Lab dashboard tab.

**Zero configuration.** No API keys, no environment variables, no proxy setup.
Plug and play.
 
<img width="2539" height="917" alt="{26B69DCD-278D-4D2D-8768-66E18CDBC771}" src="https://github.com/user-attachments/assets/1231ac3a-a34a-4c49-9265-94a387b03fd2" />
 
---

## What it does

### 🔍 Pre-tool-call hook (prompt scanning)
Every user message is intercepted *before* it reaches the LLM and scanned by
8 detection engines. If a critical threat is found, it's logged and displayed
in the dashboard — the agent continues uninterrupted (read-only inspection).

### 🔬 Post-tool-call hook (response analysis)
LLM responses are scanned for unsafe content before being shown to the user.

### 📊 Dashboard tab — Threat Lab
A real-time visualiser showing:

| Card | What it shows |
|------|---------------|
| **Total scans** | Number of prompts + responses analysed |
| **Clean** | Messages with no threats detected |
| **Flagged** | Messages with low–medium risk patterns |
| **Blocked** | Messages with high–critical severity patterns |
| **Avg duration** | Average scan time in milliseconds |
| **Severity bars** | Distribution across clean / low / medium / high / critical |
| **Engine hit rates** | Which detection engines fire most often |
| **Threat categories** | Breakdown by attack type |
| **Recent alerts** | Live feed of every high/critical detection |

### ⌨️ CLI commands
```bash
hermes aegis scan   <text>    # On-demand scan of any text
hermes aegis status           # Quick summary of current stats
hermes aegis stats            # Detailed aggregated statistics
hermes aegis sanity           # Run detector self-test
```

### 🧰 Agent tool
The agent can call `aegis_scan(text)` at any time during a conversation.

---

## Detection engines

| Engine | Category | Method |
|--------|----------|--------|
| **WAF · critical patterns** | prompt-injection | Critical system-override / template-injection / control-token patterns |
| **WAF · high-confidence** | prompt-injection | Guardrail bypass / info-leak / explicit exploit terminology |
| **Jailbreak detector** | prompt-injection | Ignore-previous, DAN mode, persona-switch, system-prompt extraction |
| **Context-escape detector** | indirect-injection | RAG frame escapes, role-boundary injection, END markers |
| **Adversarial-suffix detector** | prompt-injection | Structured evasion / 3-sentence suffix signal |
| **Exfiltration detector** | data-exfiltration | Data-send instructions, webhook URLs in prompts |
| **Malware-signature pass** | malware-signature | EICAR, PowerShell encoded, pipe-to-shell, Log4Shell, SQLi, XSS |
| **Secret-leak pass** | credential-leak | Private keys, API keys (OpenAI/AWS/GitHub/Slack), hard-coded credentials |

All engines are pure-Python regex — no ML model, no external API needed.

---

## Architecture

```
~/.hermes/plugins/aegis-latent/
├── plugin.yaml              # Hermes plugin manifest
├── __init__.py              # Hook registration, CLI commands, stats store
├── engine/
│   ├── __init__.py
│   ├── detectors.py         # Scan pipeline: runs all engines → verdict
│   └── rules.py             # Regex pattern collections (ported from Aegis)
├── dashboard/
│   ├── manifest.json        # Dashboard tab config
│   ├── plugin_api.py        # FastAPI backend (mounted at /api/plugins/aegis-latent/)
│   ├── data/
│   │   └── stats.json       # Runtime stats (auto-created)
│   └── dist/
│       ├── index.js         # React Threat Lab UI bundle
│       └── style.css        # Dashboard styles
└── README.md
```

### Data flow

```
User input → Hermes pre_tool_call hook → aegis-latent scans text
                                              │
                                    ┌─────────┴──────────┐
                                    ▼                    ▼
                              In-memory store    dashboard/data/stats.json
                              (fast, hot path)    (persistent, for dashboard)
                                                      │
                                                      ▼
                                              Dashboard tab polls
                                              /api/plugins/aegis-latent/*
```

---

## Port status

This plugin is a port of **Aegis Latent Core v2.4.0**
(https://github.com/juanlunaia/aegis-latent-core).

### Ported from Aegis
- ✅ WAF pattern matching (critical + high-confidence layers)
- ✅ Jailbreak / direct-injection detection
- ✅ RAG context-escape detection
- ✅ Adversarial-suffix detection
- ✅ Malware / exploit signature pass
- ✅ Secret / credential-leak pass
- ✅ Data-exfiltration detection
- ✅ Severity scoring and verdict pipeline
- ✅ Threat Lab visualizer (as dashboard tab)

### Not ported (Hermes-native)
- ❌ No standalone FastAPI proxy — uses Hermes' native LLM pipeline instead
- ❌ No HSM / Vault integration — secrets are managed by Hermes
- ❌ No YARA engine — requires native `yara-python` binary
- ❌ No SimHash / IOC correlator — requires external threat feed
- ❌ No OT/SCADA protocol scanner — niche hardware-protocol dependency
- ❌ No Rust-accelerated components — the regex engines are fast enough for
  real-time scanning at Hermes' scale

---

## Requirements

- **Hermes Agent** (any recent version with dashboard plugin support)
- No additional Python packages — all dependencies are pure stdlib
- The dashboard tab requires the Hermes web dashboard to be running

## License

AGPLv3 / Commercial — see the
[original repository](https://github.com/juanlunaia/aegis-latent-core) for details.
