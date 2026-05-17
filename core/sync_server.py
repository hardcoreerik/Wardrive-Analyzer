"""
WARDRIVE Field Terminal Sync Server
------------------------------------
Exposes session JSON artifacts over HTTP and advertises via mDNS (_wardrive._tcp)
so the Tab5 can discover and sync sessions without manual IP configuration.

Usage (from the GUI or CLI):
    from core.sync_server import SyncServer
    server = SyncServer(project_dir="/path/to/project", port=8765)
    server.start()   # non-blocking, runs in background thread
    ...
    server.stop()

HTTP endpoints:
    GET /health                              → {"status": "ok", "version": "..."}
    GET /sessions                            → {"sessions": [...]}
    GET /sessions/<run_id>/<filename>        → raw JSON file contents
    GET /sessions/<run_id>                   → {"files": [...]} list available files

Requires: zeroconf (pip install zeroconf)
"""

from __future__ import annotations

import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

# zeroconf is an optional dependency — gracefully degrade if absent
try:
    from zeroconf import ServiceInfo, Zeroconf
    _ZEROCONF_OK = True
except ImportError:
    _ZEROCONF_OK = False

_SERVER_VERSION = "1.0.0"

# JSON artifact files exported by write_tab5_json_export()
_SESSION_FILES = [
    "session_summary.json",
    "capture_quality.json",
    "assistant_cards.json",
    "blue_team_findings.json",
    "red_team_observations.json",
    "purple_team_lessons.json",
    "education_cards.json",
]


def _get_local_ip() -> str:
    """Return the non-loopback IPv4 of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _load_session_summary(run_dir: str) -> dict:
    """Load minimal session_summary.json for the /sessions list."""
    path = os.path.join(run_dir, "session_summary.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


class _Handler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for Tab5 sync requests."""

    project_dir: str = ""

    def log_message(self, fmt: str, *args) -> None:  # type: ignore[override]
        pass  # suppress default logging; caller can add their own

    def _send_json(self, code: int, data: dict) -> None:
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, filepath: str) -> None:
        try:
            with open(filepath, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # type: ignore[override]
        path = self.path.rstrip("/")
        parts = [p for p in path.split("/") if p]

        # GET /health
        if not parts or parts == ["health"]:
            self._send_json(200, {"status": "ok", "version": _SERVER_VERSION})
            return

        # GET /sessions
        if parts == ["sessions"]:
            self._handle_session_list()
            return

        # GET /sessions/<run_id>
        if len(parts) == 2 and parts[0] == "sessions":
            self._handle_session_detail(parts[1])
            return

        # GET /sessions/<run_id>/<filename>
        if len(parts) == 3 and parts[0] == "sessions":
            self._handle_file(parts[1], parts[2])
            return

        self.send_response(404)
        self.end_headers()

    def _runs_dir(self) -> str:
        return os.path.join(self.project_dir, "runs")

    def _handle_session_list(self) -> None:
        runs_dir = self._runs_dir()
        sessions = []
        if os.path.isdir(runs_dir):
            for run_id in sorted(os.listdir(runs_dir), reverse=True):
                run_path = os.path.join(runs_dir, run_id)
                if not os.path.isdir(run_path):
                    continue
                summary = _load_session_summary(run_path)
                sessions.append({
                    "run_id":        run_id,
                    "network_count": summary.get("network_count", 0),
                    "created":       summary.get("created", ""),
                    "files":         [f for f in _SESSION_FILES
                                      if os.path.exists(os.path.join(run_path, f))],
                })
        self._send_json(200, {"sessions": sessions})

    def _handle_session_detail(self, run_id: str) -> None:
        run_path = os.path.join(self._runs_dir(), run_id)
        if not os.path.isdir(run_path):
            self._send_json(404, {"error": f"Session {run_id!r} not found"})
            return
        files = [f for f in _SESSION_FILES if os.path.exists(os.path.join(run_path, f))]
        self._send_json(200, {"run_id": run_id, "files": files})

    def _handle_file(self, run_id: str, filename: str) -> None:
        # Security: only allow known filenames to prevent path traversal
        if filename not in _SESSION_FILES:
            self.send_response(403)
            self.end_headers()
            return
        filepath = os.path.join(self._runs_dir(), run_id, filename)
        self._send_file(filepath)


class SyncServer:
    """
    Background HTTP server for Tab5 Wi-Fi sync.

    Instantiate once, call start() to begin serving.  The server advertises
    itself via mDNS as _wardrive._tcp so the Tab5 can discover it without
    manual IP entry.
    """

    def __init__(self, project_dir: str, port: int = 8765) -> None:
        self.project_dir = os.path.abspath(project_dir)
        self.port = port
        self._httpd: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._zeroconf: Optional["Zeroconf"] = None
        self._zc_info: Optional["ServiceInfo"] = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.is_running:
            return

        # Bind HTTP handler to project_dir
        handler = type("_BoundHandler", (_Handler,),
                       {"project_dir": self.project_dir})

        self._httpd = HTTPServer(("", self.port), handler)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, daemon=True, name="wardrive-sync-http"
        )
        self._thread.start()

        self._advertise_mdns()

    def stop(self) -> None:
        self._unadvertise_mdns()
        if self._httpd:
            self._httpd.shutdown()
            self._httpd = None
        self._thread = None

    def _advertise_mdns(self) -> None:
        if not _ZEROCONF_OK:
            return
        try:
            local_ip = _get_local_ip()
            self._zeroconf = Zeroconf()
            self._zc_info = ServiceInfo(
                type_="_wardrive._tcp.local.",
                name=f"WARDRIVE Analyzer._wardrive._tcp.local.",
                addresses=[socket.inet_aton(local_ip)],
                port=self.port,
                properties={"version": _SERVER_VERSION},
            )
            self._zeroconf.register_service(self._zc_info)
        except Exception as exc:
            # mDNS is optional — server still works via direct IP
            print(f"[sync_server] mDNS registration failed: {exc}")

    def _unadvertise_mdns(self) -> None:
        if self._zeroconf and self._zc_info:
            try:
                self._zeroconf.unregister_service(self._zc_info)
                self._zeroconf.close()
            except Exception:
                pass
            self._zeroconf = None
            self._zc_info = None

    def url(self) -> str:
        return f"http://{_get_local_ip()}:{self.port}"

    def __repr__(self) -> str:
        status = "running" if self.is_running else "stopped"
        return f"SyncServer({self.url()}, {status})"
