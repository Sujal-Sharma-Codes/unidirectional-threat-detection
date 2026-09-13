# AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
### Email login threat detector — rebuilt after judge feedback

## What changed from the original submission

| | Before | After |
|---|---|---|
| Data source | CICIDS2017 (static, 2017, third-party) | Self-generated, from a login server we built (`generate_dataset.py`) |
| Top features | `Bwd Packet Length Mean/Std/Max...` — **response-direction** stats | `mean_interarrival_sec`, `attempts_in_window`, `unique_usernames_in_window` — **observable from inbound traffic only** |
| Real-world framing | Abstract network flow stats | "Is this repeated email login activity normal or an attack?" — the exact scenario judges asked for |
| Demo | Replays held-out test rows from a saved dataset | `live_monitor.py` watches attempts arrive in real time and flags them as they happen |
| Reported accuracy | 99.9% (inflated by response-side leakage) | 99% (honest — driven by legitimate timing/volume signal, verified no leakage) |

The original model's top features (`Bwd_*`) require seeing the server's
*response* traffic — which a one-way sensor (a data diode, a DDoS-victim
capture point, a passive tap that only sees inbound packets) cannot see.
This rebuild only uses signals a purely inbound sensor could observe.

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
- `live_monitor.py` — **the demo**: watches attempts arrive live, flags NORMAL/ATTACK in real time with plain-English reasons
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
```

**2. Run the live demo:**
```bash
# terminal 1 (if not already running)
python3 server.py

# terminal 2
python3 live_monitor.py

# terminal 3 — normal user
python3 normal_traffic.py --duration 60 --ip 10.0.0.50

# terminal 4 — attack, whenever you want to trigger a detection live
python3 attack_traffic.py --mode bruteforce --attempts 20 --delay 0.05
python3 attack_traffic.py --mode spray --attempts 30 --delay 0.05
```

Watch terminal 2 — it will print `✅ normal` for the real user and
`🚨 ATTACK` with reasoning the moment attack traffic starts arriving.

## Honest limitations (say these out loud in your pitch — it builds credibility)

- Small-scale simulation, not internet-scale traffic
- Simplified login protocol, not real IMAP/SMTP
- Only two attack types modeled (brute force, credential spray) — real
  attackers have more variations
- Window-based detection has some inherent lag (up to the window size)
  before enough attempts accumulate to classify confidently

## Suggested pitch structure

1. Problem: most IDS models assume bidirectional visibility; real deployments (diodes, DDoS capture points) often don't have it
2. What we found in our own first model: it silently relied on response-direction (`Bwd_*`) features — show the old `feature_importance.csv` as evidence you understand your own system
3. Rebuild: self-generated traffic, inbound-only features, honest accuracy
4. **Live demo** — this is the centerpiece, run it live, don't show slides of it
5. Limitations slide, said plainly
