"""
aegis-latent — Hermes Agent plugin: AI governance & threat detection.

Registers:
- pre_tool_call hook to scan user input for prompt injection / malware / etc.
- post_tool_call hook to analyse LLM responses.
- CLI command: ``hermes aegis scan <text>`` — on-demand scanning.
- CLI command: ``hermes aegis status`` — current threat stats.
- CLI command: ``hermes aegis stats`` — aggregated stats.

Detection results are held in an in-memory store and periodically written
to ``dashboard/data/stats.json`` for the dashboard tab to pick up.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure plugin root is on sys.path so absolute imports of engine/ work
_PLUGIN_DIR = Path(__file__).resolve().parent
if str(_PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_DIR))

from engine.detectors import scan_text, sanity_check

# ── Plugin metadata ─────────────────────────────────────────────────────────────

PLUGIN_VERSION = "2.4.0"
PLUGIN_DIR = _PLUGIN_DIR
DATA_DIR = PLUGIN_DIR / "dashboard" / "data"

# ── In-memory threat store ──────────────────────────────────────────────────────

_lock = threading.Lock()
_store: dict[str, Any] = {
    "scans_total": 0,
    "scans_clean": 0,
    "scans_flagged": 0,
    "scans_blocked": 0,
    "alerts": [],
    "engine_hit_counts": {},
    "category_counts": {},
    "severity_counts": {"clean": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
    "total_duration_ms": 0.0,
    "last_scan_at": None,
    "version": PLUGIN_VERSION,
}

MAX_ALERTS = 500
_PERSIST_INTERVAL = 5.0  # seconds between flushing to disk
_last_persist = time.monotonic()


def _update_store(result: dict[str, Any]) -> None:
    """Thread-safe update of in-memory stats with a ScanResult dict."""
    global _last_persist
    with _lock:
        _store["scans_total"] += 1
        _store["total_duration_ms"] += result.get("duration_ms", 0)

        verdict = result.get("overall_verdict", "clean")
        max_sev = result.get("max_severity", "clean")

        if verdict == "block":
            _store["scans_blocked"] += 1
            _store["scans_flagged"] += 1
        elif verdict != "clean":
            _store["scans_flagged"] += 1
        else:
            _store["scans_clean"] += 1

        _store["severity_counts"][max_sev] = (
            _store["severity_counts"].get(max_sev, 0) + 1
        )

        _store["last_scan_at"] = datetime.now(timezone.utc).isoformat()

        # Track per-engine hit counts
        for r in result.get("results", []):
            eng = r.get("engine", "unknown")
            cat = r.get("category", "unknown")
            if r.get("flagged"):
                _store["engine_hit_counts"][eng] = (
                    _store["engine_hit_counts"].get(eng, 0) + 1
                )
                _store["category_counts"][cat] = (
                    _store["category_counts"].get(cat, 0) + 1
                )

        # Append alert
        if max_sev in ("high", "critical"):
            alert = {
                "timestamp": _store["last_scan_at"],
                "severity": max_sev,
                "verdict": verdict,
                "text_snippet": result.get("text_snippet", "")[:120],
                "flagged_engines": [
                    r.get("engine")
                    for r in result.get("results", [])
                    if r.get("flagged")
                ],
                "score": result.get("max_score", 0),
            }
            _store["alerts"].insert(0, alert)
            if len(_store["alerts"]) > MAX_ALERTS:
                _store["alerts"] = _store["alerts"][:MAX_ALERTS]

    # Periodic flush to disk (non-blocking, best-effort)
    now = time.monotonic()
    if now - _last_persist >= _PERSIST_INTERVAL:
        _persist_store()
        _last_persist = now


def _persist_store() -> None:
    """Write in-memory store to dashboard/data/stats.json for the dashboard tab."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with _lock:
            data = dict(_store)  # shallow copy
        path = DATA_DIR / "stats.json"
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        tmp.replace(path)
    except Exception:
        pass  # best-effort; nothing fatal


def _load_store() -> dict[str, Any]:
    """Load persisted store from disk (if any) at plugin init."""
    path = DATA_DIR / "stats.json"
    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    return dict(_store)


def _merge_store(persisted: dict[str, Any]) -> None:
    """Merge persisted data into the in-memory store (avoids losing history)."""
    with _lock:
        for k in ("scans_total", "scans_clean", "scans_flagged", "scans_blocked",
                   "total_duration_ms"):
            _store[k] = max(_store[k], persisted.get(k, 0))
        if persisted.get("alerts"):
            existing = {a.get("timestamp") for a in _store["alerts"]}
            for a in persisted["alerts"]:
                if a.get("timestamp") not in existing:
                    _store["alerts"].append(a)
            _store["alerts"] = _store["alerts"][:MAX_ALERTS]
        for d in ("engine_hit_counts", "category_counts", "severity_counts"):
            for k, v in persisted.get(d, {}).items():
                _store[d][k] = max(_store[d].get(k, 0), v)


# ── Hook callbacks ──────────────────────────────────────────────────────────────


def on_pre_tool_call(tool_name: str, params: dict[str, Any], **kwargs: Any) -> None:
    """Hook fired before every tool call — scans user input for threats.

    This intercepts every tool invocation and runs the Aegis detection engines
    on the input parameters.  Results are logged and stored for the dashboard.
    """
    # Extract text content from tool parameters
    text = ""
    if isinstance(params, dict):
        for val in params.values():
            if isinstance(val, str) and len(val) > 10:
                text = val
                break
            elif isinstance(val, dict):
                for v2 in val.values():
                    if isinstance(v2, str) and len(v2) > 10:
                        text = v2
                        break
                if text:
                    break

    if not text:
        return

    result = scan_text(text).to_dict()
    _update_store(result)


def on_post_tool_call(
    tool_name: str, params: dict[str, Any], result: Any, **kwargs: Any
) -> None:
    """Hook fired after every tool call — scans LLM responses for unsafe output."""
    text = ""
    if isinstance(result, str):
        text = result
    elif isinstance(result, dict):
        for val in result.values():
            if isinstance(val, str) and len(val) > 10:
                text = val
                break

    if not text:
        return

    scan_result = scan_text(text).to_dict()
    _update_store(scan_result)


# ── CLI command handlers ─────────────────────────────────────────────────────────


def _cmd_scan(text: str, **kwargs: Any) -> str:
    """On-demand scan: ``hermes aegis scan <text>``."""
    del kwargs
    result = scan_text(text)
    _update_store(result.to_dict())
    return json.dumps(result.to_dict(), indent=2)


def _cmd_status(**kwargs: Any) -> str:
    """Current threat stats: ``hermes aegis status``."""
    with _lock:
        s = dict(_store)
    return json.dumps(
        {
            "version": s.get("version"),
            "scans_total": s.get("scans_total", 0),
            "scans_clean": s.get("scans_clean", 0),
            "scans_flagged": s.get("scans_flagged", 0),
            "scans_blocked": s.get("scans_blocked", 0),
            "severity_counts": s.get("severity_counts", {}),
            "last_scan_at": s.get("last_scan_at"),
            "engine_hit_counts": dict(
                sorted(s.get("engine_hit_counts", {}).items(), key=lambda x: -x[1])[:15]
            ),
        },
        indent=2,
    )


def _cmd_stats(**kwargs: Any) -> str:
    """Detailed aggregated stats: ``hermes aegis stats``."""
    with _lock:
        s = dict(_store)
    return json.dumps(
        {
            "scans_total": s.get("scans_total", 0),
            "scans_clean": s.get("scans_clean", 0),
            "scans_flagged": s.get("scans_flagged", 0),
            "scans_blocked": s.get("scans_blocked", 0),
            "severity_counts": s.get("severity_counts", {}),
            "category_counts": dict(
                sorted(s.get("category_counts", {}).items(), key=lambda x: -x[1])
            ),
            "engine_hit_counts": dict(
                sorted(s.get("engine_hit_counts", {}).items(), key=lambda x: -x[1])
            ),
            "total_duration_ms": round(s.get("total_duration_ms", 0), 2),
            "avg_duration_ms": round(
                s.get("total_duration_ms", 0) / max(s.get("scans_total", 1), 1), 2
            ),
            "last_scan_at": s.get("last_scan_at"),
            "recent_alerts": s.get("alerts", [])[:20],
        },
        indent=2,
    )


def _cmd_sanity(**kwargs: Any) -> str:
    """Run detection-engine self-test: ``hermes aegis sanity``."""
    results = sanity_check()
    return json.dumps(results, indent=2)


# ── Tool handler (on-demand scan from agent) ────────────────────────────────────


def _tool_scan_handler(params: dict[str, Any], **kwargs: Any) -> str:
    text = params.get("text", "")
    result = scan_text(text)
    _update_store(result.to_dict())
    return json.dumps(result.to_dict(), indent=2)


# ── Plugin entry point ──────────────────────────────────────────────────────────


# Auto-restore persisted state at module load time (not just on register())
_persisted = _load_store()
_merge_store(_persisted)
# Ensure data dir exists
DATA_DIR.mkdir(parents=True, exist_ok=True)


def register(ctx: Any) -> None:
    """Called by Hermes at plugin load time.

    Registers hooks, tools, and CLI commands.
    """
    # ── Hooks: intercept tool calls for threat detection ──────────────
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)

    # ── Tool: aegis_scan (agent-callable) ──────────────────────────────
    ctx.register_tool(
        name="aegis_scan",
        toolset="aegis",
        schema={
            "name": "aegis_scan",
            "description": (
                "Scan text for prompt injection, jailbreaks, malware, "
                "credential leaks, and other security threats. "
                "Returns a detailed analysis with severity scores."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The text to scan",
                    },
                },
                "required": ["text"],
            },
        },
        handler=_tool_scan_handler,
        description="Scan text for prompt injection and security threats.",
    )

    # ── CLI commands: hermes aegis <subcommand> ─────────────────────────
    ctx.register_cli_command(
        name="scan",
        help="Scan text for prompt injection / security threats",
        setup_fn=lambda: None,
        handler_fn=_cmd_scan,
    )
    ctx.register_cli_command(
        name="status",
        help="Show current Aegis threat detection stats",
        setup_fn=lambda: None,
        handler_fn=_cmd_status,
    )
    ctx.register_cli_command(
        name="stats",
        help="Show detailed aggregated threat statistics",
        setup_fn=lambda: None,
        handler_fn=_cmd_stats,
    )
    ctx.register_cli_command(
        name="sanity",
        help="Run detection-engine self-test (verifies all patterns)",
        setup_fn=lambda: None,
        handler_fn=_cmd_sanity,
    )

    # ── Try once at startup to persist (proves DATA_DIR is writable) ──
    try:
        _persist_store()
        print("[aegis] plugin loaded — wrote initial stats.json to", DATA_DIR)
    except Exception as exc:
        print("[aegis] WARNING: could not write initial stats.json:", exc)
