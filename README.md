# unidirectional-threat-detection
Real-time detection of brute-force &amp; credential-spray login attacks using only inbound traffic features — built for scenarios where bidirectional network visibility isn't available (data diodes, DDoS capture points, passive taps).


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
from what an inbound-only sensor can see, and a live monitor that
classifies real login attempts as they arrive — not a static test-set replay.

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
