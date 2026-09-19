"""Synthetic demo feed — lets you see the whole pipeline work end-to-end
without a real Wazuh/SIEM connection. Triggered explicitly via
POST /api/demo/simulate-attack, never run automatically."""
from datetime import datetime, timedelta


def brute_force_scenario(src_ip: str = "198.51.100.23", user: str = "admin") -> list[dict]:
    base = datetime.utcnow() - timedelta(minutes=5)
    events = []
    for i in range(6):
        events.append(
            {
                "source": "synthetic_demo",
                "event_type": "login_failed",
                "occurred_at": (base + timedelta(seconds=i * 5)).isoformat(),
                "data": {"src_ip": src_ip, "user": user, "outcome": "failed"},
            }
        )
    events.append(
        {
            "source": "synthetic_demo",
            "event_type": "login_success",
            "occurred_at": (base + timedelta(seconds=40)).isoformat(),
            "data": {"src_ip": src_ip, "user": user, "outcome": "success"},
        }
    )
    return events
