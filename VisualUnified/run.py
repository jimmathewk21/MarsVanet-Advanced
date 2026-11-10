"""Start the local visual VANET simulator on Windows, macOS or Linux.

No external Python packages, virtual machines, Mininet, Ryu or OVS required.
The traffic/control plane is a teaching simulation, not real OpenFlow.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
import socket
from pathlib import Path
import threading
import time
import webbrowser
from urllib.parse import urlparse

from engine import SimEngine

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
SETTINGS = BASE / "controller_settings.json"
ENGINE = SimEngine()


class LocalHTTPServer(ThreadingHTTPServer):
    # Windows SO_REUSEADDR can allow two HTTP servers to bind the same port.
    # Exclusive binding makes an occupied application port fail predictably.
    allow_reuse_address = False

    def server_bind(self):
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def load_profile():
    if not SETTINGS.exists(): return
    try:
        obj = json.loads(SETTINGS.read_text(encoding="utf-8"))
        if not isinstance(obj, dict): raise ValueError("Profile must be a JSON object")
        config = obj.get("config", {})
        if not isinstance(config, dict): raise ValueError("Invalid stored configuration")
        candidate=SimEngine(seed=ENGINE.seed,mobility_model=ENGINE.mobility_model)
        candidate.set_config(config)
        rules = obj.get("rules", [])
        if not isinstance(rules, list): raise ValueError("Invalid stored rules")
        if len(rules)>100:raise ValueError('100 rules maximum')
        normalized=[ENGINE._validated_rule(rule,str(rule['id'])) for rule in rules]
        if len({r['id'] for r in normalized})!=len(normalized):raise ValueError('Duplicate rule IDs in saved profile')
        ENGINE.set_config(candidate.config)
        ENGINE.rules=normalized
        numbers = [int(r["id"].split("-")[-1]) for r in ENGINE.rules
                   if r["id"].startswith("rule-") and r["id"].split("-")[-1].isdigit()]
        ENGINE.next_rule = max(numbers, default=0) + 1
        print(f"Loaded {len(ENGINE.rules)} user-configured flow rules")
    except (ValueError, TypeError, KeyError, OSError) as exc:
        print(f"Warning: invalid controller_settings.json ({exc}); using defaults")
        fresh = SimEngine()
        ENGINE.set_config(fresh.config)
        ENGINE.rules = fresh.rules
        ENGINE.next_rule = fresh.next_rule


def save_profile():
    current = ENGINE.status()
    output = {"config": current["config"], "rules": current["rules"]}
    temp = SETTINGS.with_suffix(".json.tmp")
    temp.write_text(json.dumps(output, indent=2), encoding="utf-8")
    os.replace(temp, SETTINGS)


def run_engine(stop_event=None):
    stop_event = stop_event or threading.Event()
    previous = time.monotonic()
    while not stop_event.wait(.10):
        current = time.monotonic()
        dt = min(.25, current - previous)
        previous = current
        try:
            ENGINE.step(dt)
        except Exception as exc:
            print(f"Simulation step error: {exc!r}", flush=True)
            with ENGINE.lock:
                if ENGINE.sumo_bridge:
                    ENGINE.set_mobility_mode('builtin')
                    ENGINE.running = False
                    ENGINE._event("MOBILITY", "SUMO connection lost; reset to built-in roads and paused", "warning")
                else:
                    ENGINE.running = False
                    ENGINE._event("SYSTEM", "Simulation error; paused (see console)", "danger")


class Handler(BaseHTTPRequestHandler):
    server_version = "MarsVanetVisual/1.0"

    def log_message(self, format_string, *args):
        # Avoid flooding terminal with routine polling requests.
        if not self.path.startswith("/api/state"):
            super().log_message(format_string, *args)

    def _headers(self, status: int, content_type: str, length: int):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def _json(self, value, status=200, attachment=None):
        data = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if attachment:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
        else:
            self._headers(status, "application/json; charset=utf-8", len(data))
        self.wfile.write(data)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid request length") from None
        if length < 0 or length > 32768:
            raise ValueError("Request is too large")
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            raise ValueError("Content-Type must be application/json")
        try:
            value = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Invalid JSON payload") from None
        if not isinstance(value, dict):
            raise ValueError("Expected a JSON object")
        return value

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/state":
            return self._json(ENGINE.status())
        if path == "/api/report":
            return self._json(ENGINE.simulation_report(), attachment="marsvanet-simulation-report.json")
        if path == '/api/flows':
            snapshot=ENGINE.status()
            return self._json({'flows':snapshot['flow_table'],'warnings':snapshot['rule_warnings']})
        if path == '/api/events':
            with ENGINE.lock:return self._json({'events':list(ENGINE.events),'limit':ENGINE.events.maxlen})
        if path in ("/", "/index.html"):
            filename = STATIC / "index.html"
        elif path in ("/app.js", "/styles.css"):
            filename = STATIC / path.lstrip("/")
        else:
            return self._json({"error": "Not found"}, 404)
        try:
            content = filename.read_bytes()
        except OSError:
            return self._json({"error": "Missing UI asset"}, 500)
        self._headers(200, mimetypes.guess_type(str(filename))[0] or "text/plain", len(content))
        self.wfile.write(content)

    def do_POST(self):
        # Serialize mutations and their persisted snapshots as one operation.
        # Separate request threads must not race on controller_settings.json.tmp.
        with ENGINE.lock:
            return self._post_locked()

    def _post_locked(self):
        path = urlparse(self.path).path
        backup=None
        try:
            data = self._read_json()
            if path == '/api/policy-preview':
                return self._json(ENGINE.preview_packet(data))
            if path == '/api/rules-analyze':
                return self._json(ENGINE.analyze_rule(data))
            if path.startswith('/api/rules') or path == '/api/config':
                names=('config','rules','next_rule','vehicles','rsu_meter_buckets','events',
                       'event_sequence','flow_stats','last_decisions','m2_config','handover_times')
                backup={name:deepcopy(getattr(ENGINE,name)) for name in names}
            if path == "/api/scenario":
                result = ENGINE.set_scenario(data.get("scenario", "normal"), data.get("attacker"), data.get("victim"))
            elif path == "/api/run":
                if type(data.get("running")) is not bool: raise ValueError("running must be boolean")
                result = ENGINE.set_running(data["running"])
            elif path == "/api/speed":
                result = ENGINE.set_speed(data.get("factor"))
            elif path == "/api/reset":
                result = ENGINE.reset()
            elif path == "/api/mobility":
                result = ENGINE.set_mobility_mode(data.get("mode", "builtin"))
            elif path == "/api/config":
                result = ENGINE.set_config(data)
            elif path == "/api/rules":
                result = ENGINE.upsert_rule(data)
            elif path.startswith("/api/rules/") and path.endswith("/toggle"):
                rule_id = path.split("/")[3]
                current = next((r for r in ENGINE.status()["rules"] if r["id"] == rule_id), None)
                if current is None: raise ValueError("Unknown rule")
                current["enabled"] = not current["enabled"]
                result = ENGINE.upsert_rule(current, rule_id)
            elif path.startswith("/api/rules/"):
                rule_id = path.split("/")[3]
                result = ENGINE.upsert_rule(data, rule_id)
            elif path == "/api/rules-delete":
                result = ENGINE.delete_rule(data.get("id", ""))
            else:
                return self._json({"error": "Not found"}, 404)
            if path.startswith("/api/rules") or path == "/api/config":
                save_profile()
        except (ValueError, TypeError) as exc:
            if backup is not None:
                for name,value in backup.items():setattr(ENGINE,name,value)
            return self._json({"error": str(exc)}, 400)
        except OSError as exc:
            if backup is not None:
                for name,value in backup.items():setattr(ENGINE,name,value)
            print('Profile persistence error:',repr(exc),flush=True)
            return self._json({'error':'Profile save failed; controller update was rolled back.'},500)
        except Exception as exc:
            if backup is not None:
                for name,value in backup.items():setattr(ENGINE,name,value)
            print("Request error:", repr(exc), flush=True)
            return self._json({"error": "Internal error"}, 500)
        return self._json(result)


def main():
    parser = argparse.ArgumentParser(description="MarsVanet unified visual simulator")
    parser.add_argument("--port", default=8765, type=int, help="Local TCP port (default 8765)")
    parser.add_argument("--no-browser", action="store_true", help="Don't open a browser tab")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535: parser.error("Port must be 1–65535")
    load_profile()
    try:
        server = LocalHTTPServer(("127.0.0.1", args.port), Handler)
    except OSError as exc:
        parser.error(f"Could not start local server: {exc}")
    stop_event = threading.Event()
    worker = threading.Thread(target=run_engine, args=(stop_event,), daemon=True,
                              name="vanet-simulation")
    worker.start()
    url = f"http://127.0.0.1:{args.port}"
    print("\n" + "=" * 63)
    print("  MARSNET / MarsVanet  •  Visual Unified SDN-VANET")
    print("  Open in your browser: " + url)
    print("  Press Ctrl+C to stop")
    print("  Mode: discrete-event network simulation (NOT real OpenFlow)")
    print("=" * 63 + "\n", flush=True)
    if not args.no_browser:
        threading.Timer(.7, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=.3)
    except KeyboardInterrupt:
        print("\nStopping MarsVanet...")
    finally:
        stop_event.set()
        worker.join(timeout=3)
        with ENGINE.lock:
            if ENGINE.sumo_bridge:
                ENGINE.sumo_bridge.close()
                ENGINE.sumo_bridge = None
        server.server_close()


if __name__ == "__main__":
    main()
