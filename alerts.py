import threading
import time
from datetime import datetime

# Lock protects the alert list because the sniffer
# and Flask dashboard run in different threads.
_lock = threading.Lock()

# Stores all generated alerts
_alerts = []

# Remembers when each alert was last generated
_last_fired = {}

# Live counters shown on the dashboard
stats = {
    "packets": 0
}


def add_alert(kind, src_ip, details, cooldown=10):
    """
    Add a new alert.

    Returns:
        True  -> alert was created
        False -> alert was suppressed because of cooldown
    """

    key = (kind, src_ip)
    now = time.time()

    with _lock:

        # Prevent duplicate alerts within the cooldown period
        if now - _last_fired.get(key, 0) < cooldown:
            return False

        _last_fired[key] = now

        alert = {
            "id": len(_alerts) + 1,
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": kind,
            "src_ip": src_ip,
            "details": details
        }

        _alerts.append(alert)

        print(
            f"[ALERT] {alert['time']} | "
            f"{kind} | {src_ip} | {details}"
        )

        return True


def get_alerts(limit=100):
    """
    Return the newest alerts first.
    """

    with _lock:
        return list(reversed(_alerts[-limit:]))