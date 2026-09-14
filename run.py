"""
run.py

Single-command launcher. This does exactly what `python3 app.py` does -
app.py already starts the mock server (if not already running) and the
live_monitor detection loop itself before starting Flask. run.py exists
only because some people expect `python3 run.py` as the entrypoint name;
both commands are equivalent.

If you'd rather see each piece start in its own terminal (useful the first
time, so you can watch server.py and live_monitor's terminal output
separately), see the README's "manual, multi-terminal" instructions instead.
"""

import app  # noqa: F401 - importing runs nothing; app.py guards startup with __main__

if __name__ == "__main__":
    app.app.logger.disabled = False
    app._ensure_server_running()
    app._ensure_monitor_thread()
    print(f"Dashboard running at:\n  http://{app.HOST}:{app.PORT}\n")
    app.app.run(host=app.HOST, port=app.PORT, threaded=True, debug=False)
