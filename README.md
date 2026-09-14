# AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

### Email login threat detector — now with a live web dashboard

## What this project does

Someone is hitting an email server's login with repeated attempts. Is that
a person who mistyped their password, or a bot doing brute-force /
credential-spray? This project detects that **from inbound attempt
patterns only** — how often, how fast, how many usernames, from where —
never using whether the login succeeded, never using response-side
traffic. That constraint matters for sensors that only see one direction
of traffic (a data diode, a DDoS-capture point, a passive tap).

A trained Random Forest classifies each source IP's recent login activity
as `NORMAL` or `ATTACK`, in real time, as attempts arrive. This update adds
a local browser dashboard on top of the existing detector so you can watch
it work without reading terminal output — **the dashboard shows exactly
what the model produces, nothing more, nothing invented.**

## Architecture

```
 normal_traffic.py / attack_traffic.py  (simulated login attempts)
                |
                v
            server.py                    (mock login server, logs every attempt)
                |
                v
     logs/login_attempts.csv             (the only handoff file - append-only)
                |
                v
        feature_extractor.py             (windowed behavioral features)
                |
        +-------+-------+
        |               |
        v               v
  train_model.py   live_monitor.py       (tails the CSV, classifies live)
  (offline, once)        |
        |                +----> terminal output (unchanged)
        v                |
network_threat_model.pkl +----> event_bus.py --> Flask (app.py) --> SSE --> dashboard.html
```

Nothing about the detection pipeline (traffic simulation, feature
extraction, the Random Forest, or the live monitor's classification logic)
was replaced. `live_monitor.py`'s `classify_source()` — the function that
actually calls the model — is unchanged from the original. The only
additions are: **(1)** the model is loaded lazily instead of at import
time, so the app doesn't crash if you haven't trained it yet, **(2)** the
monitor loop can be started/stopped instead of only exiting on Ctrl+C, and
**(3)** every real classification is also handed to `event_bus.py`, which
fans it out to the dashboard over Server-Sent Events. The terminal output
you're used to is untouched.

`live_monitor.py`'s detection loop runs as a background **thread inside
the same process as the Flask app** (not a second process). That's a
deliberate choice: it guarantees there is exactly one detector reading the
log and producing classifications, so the terminal and the dashboard can
never show two different verdicts for the same event.

## Project files

- `server.py` — mock mail login server; logs every incoming attempt (this log is our dataset)
- `normal_traffic.py` — simulates a real user logging in occasionally
- `attack_traffic.py` — simulates brute-force and credential-spray attacks
- `generate_dataset.py` — orchestrates many rounds of both to build a labeled dataset
- `feature_extractor.py` — turns raw attempts into windowed behavioral features
- `train_model.py` — trains the Random Forest, saves model + honest metrics
- `live_monitor.py` — watches attempts arrive live, classifies NORMAL/ATTACK in real time (terminal **and** dashboard)
- `event_bus.py` — **new.** Thread-safe hand-off from the monitor loop to the dashboard (history buffer, counters, SSE fan-out). No detection logic.
- `app.py` — **new.** Flask app: serves the dashboard, exposes `/api/*`, runs the monitor thread, launches traffic scripts via a fixed, allow-listed set of actions.
- `run.py` — **new.** Thin alias for `python3 app.py` for people who expect a `run.py` entrypoint.
- `templates/dashboard.html`, `static/css/dashboard.css`, `static/js/dashboard.js` — **new.** The dashboard itself (vanilla HTML/CSS/JS, no build step, no Node).
- `model_results.json` / `feature_importance.csv` — latest training run's metrics (created by `train_model.py`)

## Requirements

- Python 3.9+
- See `requirements.txt` (Flask, pandas, numpy, scikit-learn, joblib)

## Installation

```bash
pip install -r requirements.txt
```

## How to train the model (one time, or whenever you want to retrain)

```bash
python3 generate_dataset.py      # builds logs/login_attempts.csv from simulated traffic
python3 feature_extractor.py     # windows it into logs/windowed_features.csv
python3 train_model.py           # trains + saves network_threat_model.pkl / network_features.pkl
```

`generate_dataset.py` needs `server.py` running in another terminal first
(it sends real traffic over a socket, same as the live demo does):

```bash
# terminal 1
python3 server.py
# terminal 2
python3 generate_dataset.py
python3 feature_extractor.py
python3 train_model.py
```

The dashboard does **not** retrain the model on startup — it loads
whatever `network_threat_model.pkl` already exists, exactly like the
original `live_monitor.py` did.

## How to run the dashboard

**Easiest — one command:**

```bash
python3 app.py
```

This will:
1. Start `server.py` automatically if nothing is already listening on `127.0.0.1:9999`.
2. Load the trained model and start the live monitor loop (if the model exists).
3. Start the Flask dashboard.

You'll see:

```
Dashboard running at:
  http://127.0.0.1:5000
```

Open that URL in a browser.

`python3 run.py` does the same thing, if you prefer that entrypoint name.

**Manual, multi-terminal (closer to the original workflow, useful if you
want to watch `server.py`'s own terminal output separately):**

```bash
# terminal 1
python3 server.py

# terminal 2
python3 app.py
```

Either way, once the dashboard is open you can use its buttons instead of
opening more terminals:

- **Start Monitoring** / **Stop Monitoring** — starts/stops the live_monitor loop.
- **Normal Traffic (45s / 120s)** — launches `normal_traffic.py --demo` in the background.
- **Simulate Brute Force** / **Simulate Credential Spray** — launches `attack_traffic.py` with a fixed, safe argument set.
- **Clear History** — clears the dashboard's event history and counters (does **not** touch `logs/login_attempts.csv`, the model, or the monitor).

Or trigger traffic manually in another terminal, same as before:

```bash
python3 normal_traffic.py --demo --duration 60 --ip 10.0.0.50
python3 attack_traffic.py --mode bruteforce --attempts 20 --delay 0.05
python3 attack_traffic.py --mode spray --attempts 30 --delay 0.05
```

Either way, watch the dashboard (or terminal 2) — it updates the moment
attack traffic starts arriving.

## What the dashboard displays

Everything shown comes from the real pipeline. Nothing is hardcoded or
randomly generated for effect:

- **System status** — whether the mock server is reachable, whether the
  model loaded (and the exact error if it didn't), whether the monitor
  loop is running.
- **Live statistics** — total/normal/attack event counts, computed by
  counting what `event_bus.py` actually received.
- **Live event stream** — one row per real classification: timestamp,
  source IP, prediction, the model's own confidence for its predicted
  class, severity, and a short reason. No fabricated confidence values —
  if the model didn't produce one, the field would say `--` instead
  (in practice the model always returns a probability, so you'll always
  see one here).
- **Live threat timeline** — a dot per real event (green=normal,
  red=attack) plotted as they arrive.
- **Detector features panel** — click any row to see the exact
  `feature_extractor.py` feature values (`attempts_in_window`,
  `unique_usernames_in_window`, `mean_interarrival_sec`, etc.) that fed
  the model for that event.
- **Latest detection panel** — full detail on the most recent attack:
  source, time, features, prediction, and the same plain-English
  evidence strings `live_monitor.py` prints to the terminal.

### About the "attack type" label

The trained model is a **binary** classifier (`NORMAL` vs `ATTACK`) — it
was never trained to distinguish brute force from credential spray, even
though both are simulated by `attack_traffic.py` and both exist as
`true_label` values used only to build the binary training target. So the
dashboard's "Brute Force (pattern match)" / "Credential Spray (pattern
match)" labels are **not a model output** — they're a small, clearly
separate heuristic (`live_monitor._pattern_hint()`) that reuses the exact
same feature thresholds already used to build the evidence strings
(`unique_usernames_in_window >= 4` → spray-like, `min_interarrival_sec <
1.0` → brute-force-like). This is called out in code comments and here so
nobody mistakes it for something the Random Forest actually classifies.

## Supported attack types

Only what `attack_traffic.py` actually implements:
- **Brute force** — one username, many passwords, one source IP, no delay.
- **Credential spray** — many usernames, common passwords, spread across a
  simulated IP pool.

## Example workflow

1. `pip install -r requirements.txt`
2. `python3 server.py` (terminal 1) — or skip this, `app.py` will start it for you
3. `python3 generate_dataset.py && python3 feature_extractor.py && python3 train_model.py` — one time
4. `python3 app.py` (terminal 2) → open `http://127.0.0.1:5000`
5. Click **Normal Traffic (45s)** — watch normal events appear
6. Click **Simulate Brute Force** — watch it get flagged within a few seconds (the model uses a 60s rolling window, so very early attempts may take a moment to accumulate before crossing the detection threshold)
7. Click **Simulate Credential Spray** — watch a second attack pattern appear
8. Click **Stop Monitoring**, then **Start Monitoring** — confirm it resumes cleanly

## Limitations

Everything the original README called out still applies:
- Small-scale simulation, not internet-scale traffic.
- Simplified login protocol, not real IMAP/SMTP.
- Only two attack types modeled — real attackers have more variations.
- Window-based detection has inherent lag (up to the rolling window size,
  60s by default) before enough attempts accumulate to classify confidently.

New, dashboard-specific limitations:
- The Flask development server is used (`app.run(...)`), which is fine for
  a local demo but is explicitly not meant for production/public exposure.
- The dashboard binds to `127.0.0.1` only, by design — it is not exposed
  on your network.
- The "attack type" badge is a display-only heuristic, not a model
  output (see above) — the underlying classifier is binary.
- A one-time TCP probe (used only at startup to check whether `server.py`
  is already running) causes exactly one harmless extra row in
  `logs/login_attempts.csv`, because `server.py` logs any accepted
  connection regardless of payload. This is existing `server.py`
  behavior and was left as-is per the "don't modify the original
  detection system" constraint; it happens once per app startup, not on
  every status refresh.
- Traffic-control buttons launch a **fixed, allow-listed** set of
  commands (`normal_short`, `normal_long`, `attack_bruteforce`,
  `attack_spray`) — there is no way to pass arbitrary arguments or shell
  commands through the dashboard.
- `event_bus.py`'s history is capped (1000 events) and lives in memory
  only — restarting `app.py` clears the dashboard's view, though
  `logs/login_attempts.csv` and the trained model are untouched.

## Error handling

- **Model file missing** → `/api/status` reports `model_loaded: false`
  with the exact command to fix it; the dashboard shows a banner instead
  of crashing.
- **Server not running** → `app.py` starts it automatically; if that
  somehow fails, `server_listening: false` is visible in `/api/status`.
- **Port 5000 already occupied** → Flask will print a clear
  "Address already in use" error in the terminal at startup; no browser
  interaction is affected because the app never starts.
- **No events yet** → `/api/events` returns `[]`, `/api/latest_attack`
  returns `null`, and the dashboard shows its empty states instead of
  erroring.
- **Dashboard opened before the monitor starts** → the page loads fine;
  status pills show `MONITOR: IDLE` until you click Start Monitoring (or
  it's already running because `app.py` starts it automatically when the
  model is present).
- Any unhandled server-side error returns a plain JSON `{"error": "..."}`
  with a 500 status instead of a Python stack trace in the browser.

## Suggested pitch structure (unchanged from the original)

1. Problem: most IDS models assume bidirectional visibility; real
   deployments (diodes, DDoS capture points) often don't have it.
2. What we found in our own first model: it silently relied on
   response-direction (`Bwd_*`) features.
3. Rebuild: self-generated traffic, inbound-only features, honest accuracy.
4. **Live demo** — now with a browser dashboard instead of a bare terminal.
5. Limitations slide, said plainly.
