# 🛡️ AI-Based Detection of Cyber Threats in Unidirectional IP Traffic



![Python](https://img.shields.io/badge/Python-3.12-blue)




![scikit-learn](https://img.shields.io/badge/scikit--learn-RandomForest-orange)




![Status](https://img.shields.io/badge/status-active-brightgreen)



**A real-time behavioral detector for email login attacks (brute-force &
credential spray) — built to work under a realistic constraint: the sensor
can only see inbound traffic, not the server's response.**

## Why this project

Most ML-based intrusion detection research assumes bidirectional network
visibility — you can see both what came in *and* what went out. In practice,
a lot of real deployments don't get that luxury: data diodes in industrial/
SCADA networks, DDoS-victim-side capture points, and passive inbound taps
all see traffic in one direction only. This project asks a narrower,
more honest question: **can you still detect an attack with only half the
picture?**

This started as a hackathon submission trained on CICIDS2017. Judge
feedback pushed it in a better direction — build something tied to a
scenario people actually recognize ("is this repeated login activity
normal, or an attack?"), not just an abstract flow-stats classifier. That
rebuild surfaced a real problem with the original approach worth
documenting here rather than hiding: **the original model's top features
were all response-direction (`Bwd_*`) statistics — information a
one-way sensor could never actually observe.** That's a form of data
leakage relative to the stated problem, even though it scored 99.9%
accuracy.

This repo is the rebuilt version: a self-generated dataset (a mock mail
login server + normal/attack traffic simulators), features derived only
from what an inbound-only sensor can see, a live terminal monitor, and a
browser dashboard — all fed by one real trained model, not a mockup.

## Results (honest, not inflated)

| Metric | Value |
|---|---|
| Accuracy | ~99% |
| Precision (attack) | 1.00 |
| Recall (attack) | 0.96–0.98 |
| Top feature | `mean_interarrival_sec` (request timing — not response data) |

Full metrics in [`model_results.json`](./model_results.json) and
[`feature_importance.csv`](./feature_importance.csv).

## Architecture
---

## What changed from the original submission

| | Before | After |
|---|---|---|
| Data source | CICIDS2017 (static, 2017, third-party) | Self-generated, from a login server we built (`generate_dataset.py`) |
| Top features | `Bwd Packet Length Mean/Std/Max...` — **response-direction** stats | `mean_interarrival_sec`, `attempts_in_window`, `unique_usernames_in_window` — **observable from inbound traffic only** |
| Real-world framing | Abstract network flow stats | "Is this repeated email login activity normal or an attack?" — the exact scenario judges asked for |
| Demo | Replays held-out test rows from a saved dataset | Live terminal monitor + browser dashboard, both fed by real-time/real-log model predictions |
| Reported accuracy | 99.9% (inflated by response-side leakage) | 99% (honest — driven by legitimate timing/volume signal, verified no leakage) |

## The real-world scenario

Someone is hitting an email server's login with repeated attempts. Is that
a person who mistyped their password, or a bot doing brute-force /
credential-spray? We detect this from **inbound attempt patterns only**:
how often, how fast, how many usernames, from where — never using whether
the login succeeded, never using response-side traffic.

## Project files

- `server.py` — mock mail login server; logs every incoming attempt (this log is our dataset)
- `normal_traffic.py` — simulates a real user logging in occasionally
- `attack_traffic.py` — simulates brute-force and credential-spray attacks
- `generate_dataset.py` — orchestrates many rounds of both to build a labeled dataset
- `feature_extractor.py` — turns raw attempts into windowed behavioral features
- `train_model.py` — trains the Random Forest, saves model + honest metrics
- `live_monitor.py` — terminal demo: watches attempts arrive live, flags NORMAL/ATTACK in real time with plain-English reasons
- `export_events.py` — runs the trained model over any traffic log and exports a JSON events file for the dashboard
- `dashboard.html` — **the GUI**: open it in any browser, load an events file, and watch the detection timeline, alert feed, and reasoning replay live
- `model_results.json` / `feature_importance.csv` — latest training run's metrics

## How to run

**1. Build the dataset and train (one time):**
```bash
# terminal 1
python3 server.py

# terminal 2
python3 generate_dataset.py
python3 feature_extractor.py
python3 train_model.py
# terminal 1 (if not already running)
python3 server.py

# terminal 2
python3 live_monitor.py

# terminal 3 — normal user
python3 normal_traffic.py --duration 60 --ip 10.0.0.50

# terminal 4 — attack, whenever you want to trigger a detection live
python3 attack_traffic.py --mode bruteforce --attempts 20 --delay 0.05
python3 attack_traffic.py --mode spray --attempts 30 --delay 0.05

# after step 1, export what the model decided on your generated log
python3 export_events.py --raw logs/login_attempts.csv --out dashboard_events.json
