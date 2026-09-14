"""
event_bus.py

The ONLY thing this module does is hand real detection results from
live_monitor.py to whoever wants to display them (the Flask dashboard's
SSE stream, the REST snapshot endpoint, etc). It contains no detection
logic and no traffic simulation - it is a thread-safe mailbox + bounded
history + running counters.

Design:
- publish() is called by live_monitor.py's monitoring loop, once per real
  classification result (i.e. once per source_ip that actually received
  new attempts this poll cycle). Nothing here invents events.
- Subscribers (SSE connections) each get their own Queue so a slow browser
  tab can't block the detection loop or other tabs.
- History is a bounded deque (default 1000) so memory doesn't grow forever
  during a long-running demo.
- Counters (total/normal/attack) are derived by counting what actually
  passed through publish() - not sampled, not estimated.
"""

import threading
import time
from collections import deque
from queue import Queue, Full

MAX_HISTORY = 1000

_lock = threading.Lock()
_history = deque(maxlen=MAX_HISTORY)
_subscribers = set()

_counters = {
    "total_events": 0,
    "normal_events": 0,
    "attack_events": 0,
}

_next_id = 1


def publish(event: dict):
    """Add a real event (produced by live_monitor.py) to history and fan it
    out to every connected dashboard client. `event` is expected to already
    contain only fields derived from the actual detector output - this
    function does not add or fabricate any detection fields, only an id
    and a wall-clock receipt timestamp for display/ordering."""
    global _next_id
    with _lock:
        event = dict(event)  # shallow copy, don't mutate caller's dict
        event["id"] = _next_id
        event["received_at"] = time.time()
        _next_id += 1

        _counters["total_events"] += 1
        if event.get("prediction") == "ATTACK":
            _counters["attack_events"] += 1
        else:
            _counters["normal_events"] += 1

        _history.append(event)
        subs = list(_subscribers)

    for q in subs:
        try:
            q.put_nowait(event)
        except Full:
            # Slow consumer - drop the event for that subscriber only,
            # never blocks the detector or other subscribers.
            pass


def subscribe() -> Queue:
    q = Queue(maxsize=200)
    with _lock:
        _subscribers.add(q)
    return q


def unsubscribe(q: Queue):
    with _lock:
        _subscribers.discard(q)


def get_history(limit: int = None) -> list:
    with _lock:
        items = list(_history)
    if limit:
        return items[-limit:]
    return items


def get_counters() -> dict:
    with _lock:
        return dict(_counters)


def get_latest_attack() -> dict:
    with _lock:
        for event in reversed(_history):
            if event.get("prediction") == "ATTACK":
                return event
    return None


def clear():
    """Wipe history and counters. Does NOT touch the model, the monitor
    thread, or logs/login_attempts.csv - this only clears what the
    dashboard has accumulated for display."""
    with _lock:
        _history.clear()
        _counters["total_events"] = 0
        _counters["normal_events"] = 0
        _counters["attack_events"] = 0
