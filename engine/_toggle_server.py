"""
_toggle_server — Tiny HTTP server for dashboard ↔ plugin communication.

Endpoints:
  GET  /              → {"blocking_enabled": bool, "port": int}
  GET  /status        → (same)
  POST /toggle        → {"blocking_enabled": bool}  (flip state)
  POST /set           → {"blocking_enabled": bool}  (body: {"enabled": bool})

CAN start in one of two ways:

  1) In-process — call start() from the Hermes agent (daemon thread).
     Dies when the agent process exits.  Works only when the agent
     session is live (daemon mode).

  2) As a standalone subprocess — call start_process() from register().
     Spawns an orphan process that survives the agent.  Writes its
     port to a well-known file so the dashboard can always find it.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

_store_getter: Callable[[], dict[str, Any]] | None = None
_store_setter: Callable[[str, Any], None] | None = None
_server: HTTPServer | None = None
_thread: threading.Thread | None = None
_process: subprocess.Popen | None = None


def _make_handler():
    """Factory that returns a request handler class closing over the store callbacks."""

    class ToggleHandler(BaseHTTPRequestHandler):
        # Silence per-request logs
        def log_message(self, fmt, *args):
            logger.debug("toggle_server: " + fmt, *args)

        def _send_json(self, data: dict, status: int = 200):
            body = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")
            self.send_header("Access-Control-Max-Age", "86400")
            self.end_headers()
            self.wfile.write(body)

        def _get_store(self) -> dict:
            if _store_getter is not None:
                return _store_getter()
            return {}

        def _set_config(self, key: str, val: Any):
            if _store_setter is not None:
                _store_setter(key, val)

        def do_OPTIONS(self):
            """CORS preflight."""
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")
            self.send_header("Access-Control-Max-Age", "86400")
            self.end_headers()

        def do_GET(self):
            if self.path in ("/", "/status"):
                store = self._get_store()
                config = store.get("config", {})
                self._send_json({
                    "blocking_enabled": config.get("blocking_enabled", False),
                    "port": _server.server_port if _server else 0,
                })
            else:
                self._send_json({"error": "not found"}, 404)

        def do_POST(self):
            if self.path == "/toggle":
                store = self._get_store()
                config = store.get("config", {})
                current = config.get("blocking_enabled", False)
                new_val = not current
                self._set_config("blocking_enabled", new_val)
                self._send_json({"blocking_enabled": new_val})

            elif self.path == "/set":
                length = int(self.headers.get("Content-Length", 0))
                if length == 0:
                    self._send_json({"error": "empty body"}, 400)
                    return
                body = self.rfile.read(length)
                try:
                    data = json.loads(body)
                except json.JSONDecodeError:
                    self._send_json({"error": "invalid JSON"}, 400)
                    return
                if "enabled" not in data:
                    self._send_json({"error": "missing 'enabled' field"}, 400)
                    return
                new_val = bool(data["enabled"])
                self._set_config("blocking_enabled", new_val)
                self._send_json({"blocking_enabled": new_val})

            else:
                self._send_json({"error": "not found"}, 404)

    return ToggleHandler


# ═══════════════════════════════════════════════════════════════
#  In-process mode (daemon thread — lives as long as agent lives)
# ═══════════════════════════════════════════════════════════════

def start(
    store_getter: Callable[[], dict[str, Any]],
    store_setter: Callable[[str, Any], None],
    port: int = 0,
) -> int:
    """Start the toggle HTTP server in a daemon thread.

    Dies when the calling process exits.
    Returns the listening port, or 0 if already running.
    """
    global _store_getter, _store_setter, _server, _thread

    if _thread is not None and _thread.is_alive():
        logger.warning("toggle_server: already running on port %d", _server.server_port)
        return _server.server_port if _server else 0

    _store_getter = store_getter
    _store_setter = store_setter

    handler_cls = _make_handler()
    _server = HTTPServer(("127.0.0.1", port), handler_cls)
    actual_port = _server.server_address[1]

    _thread = threading.Thread(
        target=_server.serve_forever,
        daemon=True,
        name="aegis-toggle-server",
    )
    _thread.start()
    return actual_port


def stop():
    """Shut down the running toggle server (threaded mode)."""
    global _server, _thread
    if _server is not None:
        _server.shutdown()
        _server = None
    _thread = None


# ═══════════════════════════════════════════════════════════════
#  Standalone subprocess mode — survives agent process exit
#  Writes port to a well-known port-file for dashboard discovery
# ═══════════════════════════════════════════════════════════════

_STANDALONE_SCRIPT = r'''"""Auto-generated toggle server — spawned by aegis-latent plugin."""
import json, os, sys
from http.server import HTTPServer, BaseHTTPRequestHandler

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _hdr(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Accept")
        self.send_header("Access-Control-Max-Age", "86400")
    def _json(self, d, s=200):
        b = json.dumps(d).encode()
        self.send_response(s)
        self._hdr()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_OPTIONS(self):
        self.send_response(204)
        self._hdr()
        self.end_headers()
    def do_GET(self):
        if self.path in ("/", "/status"):
            import json as _j
            try:
                with open({STATUS_FILE_JSON!r}) as f:
                    store = _j.load(f)
                cfg = store.get("config", {{}})
            except Exception:
                cfg = {{}}
            self._json({{"blocking_enabled": cfg.get("blocking_enabled", False), "port": self.server.server_port}})
        else:
            self._json({{"error": "not found"}}, 404)
    def do_POST(self):
        if self.path in ("/toggle", "/set"):
            try:
                cnt = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(cnt) if cnt else b""
                if self.path == "/set":
                    d = json.loads(body) if body else {{}}
                    new_val = bool(d.get("enabled", not d.get("disabled", True)))
                else:
                    import json as _j
                    try:
                        with open({STATUS_FILE_JSON!r}) as f:
                            store = _j.load(f)
                        cfg = store.get("config", {{}})
                        new_val = not cfg.get("blocking_enabled", False)
                    except Exception:
                        new_val = True
                import json as _j
                n = 3
                while n > 0:
                    try:
                        with open({STATUS_FILE_JSON!r}) as f:
                            store = _j.load(f)
                        store.setdefault("config", {{}})["blocking_enabled"] = new_val
                        with open({STATUS_FILE_JSON!r}, "w") as f:
                            _j.dump(store, f, indent=2)
                        break
                    except Exception:
                        time.sleep(0.2)
                        n -= 1
                self._json({{"blocking_enabled": new_val}})
            except Exception as e:
                self._json({{"error": str(e)}}, 500)
        else:
            self._json({{"error": "not found"}}, 404)

H.status_file = {STATUS_FILE_JSON!r}
server = HTTPServer(("127.0.0.1", 0), H)
port = server.server_address[1]
with open({PORT_FILE!r}, "w") as f:
    json.dump({{"port": port}}, f)
sys.stderr.write(f"[aegis-toggle] server on 127.0.0.1:{port}\\n")
server.serve_forever()
'''


def start_process(store_getter: Callable | None = None,
                  store_setter: Callable | None = None,
                  data_dir: str | Path | None = None) -> int:
    """Start the toggle server as a standalone subprocess.

    The process orphans itself from the parent so it survives
    agent session exits.  Port is written to ``data_dir/.toggle_port``.

    Returns the port (read from the file after launch), or 0 on failure.
    """
    global _process

    if data_dir is None:
        data_dir = os.path.join(os.path.dirname(__file__), "..", "dashboard", "data")
    data_dir = Path(data_dir).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)

    port_file = data_dir / ".toggle_port"
    status_file = data_dir / "stats.json"

    # Kill any leftover toggle server from a previous session
    stop_process()

    script = _STANDALONE_SCRIPT.format(
        STATUS_FILE_JSON=json.dumps(str(status_file)),
        PORT_FILE=json.dumps(str(port_file)),
    )

    try:
        _process = subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,  # orphan from parent process group
        )
    except Exception as exc:
        logger.warning("toggle_server: failed to start subprocess: %s", exc)
        return 0

    # Wait for the port file to appear (up to 3 sec)
    for _ in range(15):
        time.sleep(0.2)
        if port_file.exists():
            try:
                with open(port_file) as f:
                    data = json.load(f)
                port = int(data["port"])
                logger.info("toggle_server: standalone on 127.0.0.1:%d", port)
                return port
            except Exception:
                pass

    logger.warning("toggle_server: subprocess started but port file not found")
    return 0


def stop_process():
    """Kill any running standalone toggle server."""
    global _process
    if _process is not None:
        try:
            _process.kill()
            _process.wait(timeout=2)
        except Exception:
            pass
        _process = None
