"""
dashboard.plugin_api — FastAPI backend for the Aegis dashboard tab.

Mounted at /api/plugins/aegis-latent/ by the Hermes dashboard server.
Exposes threat stats, recent alerts, and on-demand scanning.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from fastapi import APIRouter

# ── Make the plugin root importable ──────────────────────────────────────────────
# plugin_api.py is loaded by importlib as a module named
# 'hermes_dashboard_plugin_<name>', not as a package relative to the plugin root.
# We inject the parent dir so we can import from engine/ and __init__.
_PLUGIN_DIR = Path(__file__).resolve().parent.parent
if str(_PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_DIR))

from engine.detectors import scan_text  # noqa: E402

router = APIRouter()

PLUGIN_VERSION = "2.4.0"


def _get_store() -> dict[str, Any]:
    """Return the current in-memory threat store.

    This imports from __init__ at call time (not import time) so the
    dashboard plugin process and the main agent process share state
    via the stats.json file persisted to disk.
    """
    data_dir = _PLUGIN_DIR / "dashboard" / "data"
    stats_file = data_dir / "stats.json"
    if stats_file.exists():
        try:
            return json.loads(stats_file.read_text())
        except Exception:
            pass
    return {
        "scans_total": 0,
        "scans_clean": 0,
        "scans_flagged": 0,
        "scans_blocked": 0,
        "alerts": [],
        "version": PLUGIN_VERSION,
    }


# ── Endpoints ───────────────────────────────────────────────────────────────────


@router.get("/stats")
async def get_stats():
    """Return current threat detection stats."""
    store = _get_store()
    s = store.get("severity_counts", {})
    return {
        "version": store.get("version", PLUGIN_VERSION),
        "scans_total": store.get("scans_total", 0),
        "scans_clean": store.get("scans_clean", 0),
        "scans_flagged": store.get("scans_flagged", 0),
        "scans_blocked": store.get("scans_blocked", 0),
        "severity_counts": {
            "clean": s.get("clean", 0),
            "low": s.get("low", 0),
            "medium": s.get("medium", 0),
            "high": s.get("high", 0),
            "critical": s.get("critical", 0),
        },
        "last_scan_at": store.get("last_scan_at"),
        "total_duration_ms": round(store.get("total_duration_ms", 0), 2),
        "avg_duration_ms": round(
            store.get("total_duration_ms", 0) / max(store.get("scans_total", 1), 1), 2
        ),
    }


@router.get("/alerts")
async def get_alerts(limit: int = 50):
    """Return recent high/critical alerts."""
    store = _get_store()
    alerts = store.get("alerts", [])
    return {"alerts": alerts[:limit], "total": len(alerts)}


@router.get("/engines")
async def get_engines():
    """Return per-engine and per-category hit counts."""
    store = _get_store()
    return {
        "engine_hit_counts": dict(
            sorted(
                store.get("engine_hit_counts", {}).items(),
                key=lambda x: -x[1],
            )[:20]
        ),
        "category_counts": dict(
            sorted(
                store.get("category_counts", {}).items(),
                key=lambda x: -x[1],
            )
        ),
    }


@router.get("/full")
async def get_full():
    """Return the full store (for dashboard initial load)."""
    store = _get_store()
    # Trim alerts to 50 for payload size
    store["alerts"] = store.get("alerts", [])[:50]
    return store


@router.post("/scan")
async def scan(body: dict[str, str]):
    """On-demand text scan.

    Body: {"text": "string to scan"}
    Returns: ScanResult dict
    """
    from datetime import datetime, timezone

    text = body.get("text", "")
    result = scan_text(text)

    # Also persist to store
    data_dir = _PLUGIN_DIR / "dashboard" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    stats_file = data_dir / "stats.json"
    store = _get_store()
    store["scans_total"] = store.get("scans_total", 0) + 1
    if result.overall_verdict == "block":
        store["scans_blocked"] = store.get("scans_blocked", 0) + 1
        store["scans_flagged"] = store.get("scans_flagged", 0) + 1
    elif result.overall_verdict != "clean":
        store["scans_flagged"] = store.get("scans_flagged", 0) + 1
    else:
        store["scans_clean"] = store.get("scans_clean", 0) + 1

    max_sev = result.max_severity
    sev_counts = store.setdefault("severity_counts", {})
    sev_counts[max_sev] = sev_counts.get(max_sev, 0) + 1

    store["total_duration_ms"] = store.get("total_duration_ms", 0) + result.duration_ms
    store["last_scan_at"] = datetime.now(timezone.utc).isoformat()

    try:
        stats_file.write_text(json.dumps(store, indent=2))
    except Exception:
        pass

    return result.to_dict()


@router.get("/version")
async def get_version():
    """Return plugin version."""
    return {"version": PLUGIN_VERSION}


@router.get("/sanity")
async def run_sanity():
    """Run detection-engine self-test."""
    from engine.detectors import sanity_check as _sanity

    return _sanity()
