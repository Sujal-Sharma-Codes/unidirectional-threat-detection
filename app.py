"""
app.py

Local web dashboard for the existing unidirectional-threat-detection
project. This file does NOT reimplement detection, feature extraction, or
traffic simulation - it wires the existing server.py / normal_traffic.py /
attack_traffic.py / feature_extractor.py / live_monitor.py together with a
Flask app so the same real events that live_monitor.py already prints to
the terminal are also visible in a browser.

Process model (why it's built this way):
- live_monitor.py's detection loop (tail_and_monitor) runs as a background
  THREAD inside this same process, not a separate process. That means
  there is exactly one detector reading logs/login_attempts.csv and
  producing classifications - the terminal print and the dashboard event
  both come from the same call to classify_source(). No second detection
  engine, no risk of the two disagreeing.
- server.py, normal_traffic.py, and attack_traffic.py remain separate
  processes (they always were - they talk to the mock server over a real
  socket). The dashboard's "start" buttons launch them via subprocess with
  a fixed, allow-listed argument list - never a user-supplied shell
  command - to avoid turning the dashboard into a remote command executor.

Run:
    pip install -r requirements.txt
    python3 app.py
Then open http://127.0.0.1:5000
"""

import json
import os
import subprocess
import sys
import threading
import time

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

import event_bus
import live_monitor

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable

HOST = "127.0.0.1"
PORT = 5000

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9999

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Subprocess management - server.py + the two traffic generators.
# Only ever launched with fixed argument lists from ACTIONS below. Nothing
# here accepts a raw command string from the browser.
# ---------------------------------------------------------------------------
_proc_lock = threading.Lock()
_procs = {
    "server": None,       # long-running mock login server
    "traffic": None,      # most recent normal/attack traffic generator
}

NORMAL_IP_CHOICES = {"10.0.0.15", "10.0.0.24", "10.0.0.50", "10.0.0.77"}

ACTIONS = {
    "normal_short": {
        "label": "Normal traffic (45s, demo pace)",
        "build": lambda ip: [PY, "normal_traffic.py", "--demo", "--duration", "45", "--ip", ip],
    },
    "normal_long": {
        "label": "Normal traffic (120s, demo pace)",
        "build": lambda ip: [PY, "normal_traffic.py", "--demo", "--duration", "120", "--ip", ip],
    },
    "attack_bruteforce": {
        "label": "Brute force attack",
        "build": lambda ip: [PY, "attack_traffic.py", "--mode", "bruteforce",
                              "--attempts", "30", "--delay", "0.05"],
    },
    "attack_spray": {
        "label": "Credential spray attack",
        "build": lambda ip: [PY, "attack_traffic.py", "--mode", "spray",
                              "--attempts", "40", "--delay", "0.05"],
    },
}


def _probe_server_once() -> bool:
    """Open-and-close a raw TCP probe. IMPORTANT: server.py logs every
    accepted connection to login_attempts.csv regardless of what (if
    anything) is sent - so this must only ever be called a handful of
    times (at startup / on an explicit control action), never on a
    polling interval, or the dashboard would pollute its own dataset
    with junk 'attempts'."""
    import socket
    try:
        with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=0.5):
            return True
    except OSError:
        return False


# Cached knowledge of the server's reachability, updated only by
# _ensure_server_running() - never by the frequently-polled /api/status
# route - to avoid the probe-pollutes-the-log problem described above.
_server_reachable = {"value": False}


def _server_status() -> bool:
    proc = _procs.get("server")
    if proc is not None:
        return proc.poll() is None
    return _server_reachable["value"]


def _ensure_server_running():
    """Start server.py as a subprocess if nothing is already listening on
    the mock server's port. Idempotent - safe to call repeatedly. Only
    this function (called at boot and on explicit control actions, never
    on a polling loop) performs a real TCP probe."""
    with _proc_lock:
        proc = _procs.get("server")
        if proc is not None and proc.poll() is None:
            _server_reachable["value"] = True
            return  # already running, we started it
        if _probe_server_once():
            _server_reachable["value"] = True
            return  # something (e.g. a manually-started server.py) is already up
        proc = subprocess.Popen(
            [PY, "server.py"],
            cwd=BASE_DIR,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _procs["server"] = proc
        time.sleep(0.3)
        _server_reachable["value"] = proc.poll() is None


def _monitor_thread_target():
    live_monitor.run_monitor_loop()


_monitor_thread = None
_monitor_thread_lock = threading.Lock()


def _ensure_monitor_thread():
    global _monitor_thread
    with _monitor_thread_lock:
        if _monitor_thread is not None and _monitor_thread.is_alive():
            return
        ok, err = live_monitor.load_model()
        if not ok:
            return  # status endpoint will surface `err` to the dashboard
        live_monitor._stop_event.clear()
        _monitor_thread = threading.Thread(target=_monitor_thread_target, daemon=True)
        _monitor_thread.start()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/status")
def api_status():
    model_loaded = live_monitor.is_model_loaded()
    model_error = live_monitor.get_model_error()
    counters = event_bus.get_counters()

    # Best-effort threat level derived only from real recent events.
    recent = event_bus.get_history(limit=50)
    now = time.time()
    recent_attacks = [e for e in recent if e.get("prediction") == "ATTACK"
                       and now - e.get("received_at", 0) <= 120]
    if any(e.get("risk") == "HIGH" for e in recent_attacks):
        threat_level = "HIGH"
    elif recent_attacks:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    server_up = _server_status()
    return jsonify({
        "system_online": server_up,
        "server_listening": server_up,
        "model_loaded": model_loaded,
        "model_error": model_error,
        "monitor_running": live_monitor.is_monitor_running(),
        "raw_events_seen": live_monitor.get_raw_events_seen(),
        "threat_level": threat_level,
        **counters,
    })


@app.route("/api/events")
def api_events():
    limit = request.args.get("limit", default=200, type=int)
    limit = max(1, min(limit, event_bus.MAX_HISTORY))
    return jsonify(event_bus.get_history(limit=limit))


@app.route("/api/latest_attack")
def api_latest_attack():
    return jsonify(event_bus.get_latest_attack())


@app.route("/api/stream")
def api_stream():
    q = event_bus.subscribe()

    def gen():
        try:
            # Send current snapshot first so a newly-opened tab isn't empty.
            for event in event_bus.get_history(limit=100):
                yield f"data: {json.dumps(event)}\n\n"
            last_heartbeat = time.time()
            while True:
                try:
                    event = q.get(timeout=5)
                    yield f"data: {json.dumps(event)}\n\n"
                except Exception:
                    pass
                if time.time() - last_heartbeat > 15:
                    yield ": heartbeat\n\n"
                    last_heartbeat = time.time()
        finally:
            event_bus.unsubscribe(q)

    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                     headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/control/start_monitor", methods=["POST"])
def control_start_monitor():
    _ensure_server_running()
    _ensure_monitor_thread()
    if not live_monitor.is_model_loaded():
        return jsonify({"ok": False, "error": live_monitor.get_model_error()}), 409
    # Give the background thread a brief moment to flip its running flag
    # before we report status back - purely cosmetic, /api/status polling
    # would catch up within a few seconds regardless.
    for _ in range(10):
        if live_monitor.is_monitor_running():
            break
        time.sleep(0.05)
    return jsonify({"ok": True, "monitor_running": live_monitor.is_monitor_running()})


@app.route("/api/control/stop_monitor", methods=["POST"])
def control_stop_monitor():
    live_monitor.request_stop()
    return jsonify({"ok": True})


@app.route("/api/control/clear_events", methods=["POST"])
def control_clear_events():
    event_bus.clear()
    return jsonify({"ok": True})


@app.route("/api/control/traffic", methods=["POST"])
def control_traffic():
    """Launch one of a FIXED set of traffic-generation commands. The
    request body may only select an action name and (for normal traffic)
    an IP from a small allow-list - it can never supply its own argv."""
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    ip = data.get("ip", "10.0.0.50")

    if action not in ACTIONS:
        return jsonify({"ok": False, "error": f"Unknown action. Choose one of {list(ACTIONS)}"}), 400
    if ip not in NORMAL_IP_CHOICES:
        ip = "10.0.0.50"

    if not _server_status():
        _ensure_server_running()

    cmd = ACTIONS[action]["build"](ip)
    subprocess.Popen(cmd, cwd=BASE_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return jsonify({"ok": True, "launched": ACTIONS[action]["label"]})


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "internal error - check the terminal running app.py for details"}), 500


if __name__ == "__main__":
    _ensure_server_running()
    _ensure_monitor_thread()  # no-op (safely) if the model hasn't been trained yet

    print("=" * 60)
    print(" Unidirectional Threat Detection - Dashboard")
    print("=" * 60)
    if not live_monitor.is_model_loaded():
        print(f"[app] WARNING: {live_monitor.get_model_error()}")
        print("[app] The dashboard will still load, showing MODEL NOT LOADED.")
    print(f"\nDashboard running at:\n  http://{HOST}:{PORT}\n")

    app.run(host=HOST, port=PORT, threaded=True, debug=False)
