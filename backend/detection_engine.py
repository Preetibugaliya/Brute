"""
Detection Engine for Brute Force Attack Detection Tool
------------------------------------------------------
Handles:
  - Classic brute force (same IP, multiple failed logins)
  - Distributed brute force (multiple IPs, one account)
  - Credential stuffing (many different usernames from one IP)
  - ML-based anomaly scoring using Isolation Forest
"""

import time
import random
import hashlib
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional
import numpy as np
from sklearn.ensemble import IsolationForest
import threading

# ─────────────────────────────────────────────────────
# Shared in-memory stores
# ─────────────────────────────────────────────────────
login_logs: List[dict] = []          # All login attempt records
blocked_ips: set = set()             # IPs blocked by admin
alerts: List[dict] = []             # Real-time alerts buffer

# Per-IP and per-user sliding windows  { key: deque of timestamps }
ip_fail_window: Dict[str, deque] = defaultdict(deque)
user_fail_window: Dict[str, deque] = defaultdict(deque)

# Track unique usernames tried per IP (credential stuffing detection)
ip_usernames: Dict[str, set] = defaultdict(set)

# Config thresholds (can be changed at runtime via API)
config = {
    "fail_threshold": 5,          # Max failures before flagging
    "time_window": 120,           # Sliding window in seconds (2 min)
    "dist_threshold": 3,          # Min IPs hitting same user = distributed
    "stuffing_threshold": 10,     # Unique usernames per IP = stuffing
    "risk_weights": {
        "frequency": 0.4,
        "time_gap": 0.2,
        "repeated_user": 0.2,
        "ip_reputation": 0.2,
    }
}

# Known malicious IP prefixes (simulated threat intel)
BLACKLISTED_PREFIXES = {"10.0.0.", "192.168.99.", "172.31."}

# ─────────────────────────────────────────────────────
# Isolation Forest ML Model (trained in memory)
# ─────────────────────────────────────────────────────
_ml_model: Optional[IsolationForest] = None
_model_lock = threading.Lock()
_model_train_buffer: List[List[float]] = []


def _get_or_train_model() -> Optional[IsolationForest]:
    """Return trained Isolation Forest, or None if not enough data."""
    global _ml_model, _model_train_buffer
    with _model_lock:
        if len(_model_train_buffer) >= 20:
            X = np.array(_model_train_buffer[-500:])  # Use last 500 rows
            model = IsolationForest(
                n_estimators=100,
                contamination=0.1,   # Expect ~10% anomalies
                random_state=42
            )
            model.fit(X)
            _ml_model = model
        return _ml_model


def _extract_features(ip: str, username: str, timestamp: float) -> List[float]:
    """Extract numeric feature vector for ML scoring."""
    window = config["time_window"]
    now = timestamp

    # Feature 1: Failure rate in window for this IP
    ip_fails = [t for t in ip_fail_window[ip] if now - t <= window]
    freq = len(ip_fails)

    # Feature 2: Average time gap between attempts (smaller = faster = worse)
    if len(ip_fails) >= 2:
        # Prevent microsecond gaps from exploding the math during simulations
        gaps = [max(0.5, ip_fails[i] - ip_fails[i-1]) for i in range(1, len(ip_fails))]
        avg_gap = sum(gaps) / len(gaps)
    else:
        avg_gap = window  # No pattern yet → neutral

    # Feature 3: Unique usernames tried by this IP
    unique_users = len(ip_usernames[ip])

    # Feature 4: IP reputation score (0=clean, 1=suspicious)
    ip_rep = 1.0 if any(ip.startswith(p) for p in BLACKLISTED_PREFIXES) else 0.0

    return [freq, avg_gap, unique_users, ip_rep]


def _ml_anomaly_score(features: List[float]) -> float:
    """
    Return anomaly score 0-100 using Isolation Forest.
    Higher = more anomalous = higher risk.
    Falls back to heuristic if model not ready.
    """
    model = _get_or_train_model()
    if model is None:
        # Heuristic fallback
        freq, avg_gap, unique_users, ip_rep = features
        score = freq * 6 + (1 / avg_gap) * 15 + unique_users * 5 + ip_rep * 20
        return round(min(96.0, score), 1)

    X = np.array([features])
    # IsolationForest score_samples returns negative; more negative = more anomalous
    raw = model.score_samples(X)[0]
    # Normalize to 0-100 (raw typically in range [-0.5, 0.1])
    normalized = max(0, min(96.0, (raw + 0.5) / 0.6 * -100 + 100))
    return round(normalized, 1)


def _classify_risk(score: float, fail_count: int) -> str:
    """Classify into Normal / Suspicious / High Risk Attack."""
    if score >= 70 or fail_count >= config["fail_threshold"] * 2:
        return "High Risk Attack"
    elif score >= 40 or fail_count >= config["fail_threshold"]:
        return "Suspicious"
    else:
        return "Normal Activity"


# ─────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────
def process_login_attempt(
    ip: str,
    username: str,
    success: bool,
    user_agent: str = "",
    country: str = "Unknown",
    city: str = "Unknown",
) -> dict:
    """
    Main entry point. Process a login attempt and return enriched log record.
    This function is called by the API on every login event.
    """
    ts = time.time()
    now_str = datetime.now(timezone.utc).isoformat()

    # ── Update sliding windows ──────────────────────
    window = config["time_window"]
    _prune_window(ip_fail_window[ip], ts, window)
    _prune_window(user_fail_window[username], ts, window)

    if not success:
        ip_fail_window[ip].append(ts)
        user_fail_window[username].append(ts)
        ip_usernames[ip].add(username)

    # ── Count failures ──────────────────────────────
    ip_fail_count = len(ip_fail_window[ip])
    user_fail_count = len(user_fail_window[username])

    # ── Distributed brute force check ───────────────
    # How many different IPs attacked this user recently?
    attacking_ips = sum(
        1 for other_ip, window_q in ip_fail_window.items()
        if username in ip_usernames.get(other_ip, set()) and len(window_q) > 0
    )
    is_distributed = attacking_ips >= config["dist_threshold"]

    # ── Credential stuffing check ───────────────────
    is_stuffing = len(ip_usernames[ip]) >= config["stuffing_threshold"]

    # ── ML Feature extraction & scoring ────────────
    features = _extract_features(ip, username, ts)
    if not success:
        _model_train_buffer.append(features)
    risk_score = _ml_anomaly_score(features)

    # Boost risk score for special attack patterns
    if is_distributed:
        risk_score += random.uniform(10.0, 20.0)
    if is_stuffing:
        risk_score += random.uniform(15.0, 25.0)
    if any(ip.startswith(p) for p in BLACKLISTED_PREFIXES):
        risk_score += 15.0

    risk_score = min(99.0, risk_score)
    # Add minor jitter to prevent all having exact same score
    if risk_score >= 80:
        risk_score = round(risk_score - random.uniform(0.1, 8.5), 1)

    risk_label = _classify_risk(risk_score, ip_fail_count)

    # ── Build log record ────────────────────────────
    log_id = hashlib.md5(f"{ip}{username}{ts}".encode()).hexdigest()[:12]
    record = {
        "id": log_id,
        "timestamp": now_str,
        "ts_epoch": ts,
        "ip": ip,
        "username": username,
        "success": success,
        "user_agent": user_agent,
        "country": country,
        "city": city,
        "ip_fail_count": ip_fail_count,
        "user_fail_count": user_fail_count,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "is_distributed": is_distributed,
        "is_stuffing": is_stuffing,
        "is_blocked": ip in blocked_ips,
        "attack_type": _determine_attack_type(is_distributed, is_stuffing, ip_fail_count),
        "features": {
            "frequency": round(features[0], 2),
            "avg_gap_sec": round(features[1], 2),
            "unique_users": int(features[2]),
            "ip_reputation": features[3],
        }
    }

    # ── Store & alert ────────────────────────────────
    login_logs.append(record)
    _trim_logs()

    if risk_label in ("Suspicious", "High Risk Attack"):
        _create_alert(record)

    return record


def _determine_attack_type(distributed: bool, stuffing: bool, fail_count: int) -> str:
    if stuffing:
        return "Credential Stuffing"
    if distributed:
        return "Distributed Brute Force"
    if fail_count >= config["fail_threshold"]:
        return "Brute Force"
    return "Normal"


def _prune_window(dq: deque, now: float, window: float):
    """Remove timestamps outside the sliding window."""
    while dq and now - dq[0] > window:
        dq.popleft()


def _trim_logs(max_size: int = 2000):
    """Keep only the latest records to avoid memory bloat."""
    global login_logs
    if len(login_logs) > max_size:
        login_logs = login_logs[-max_size:]


def _create_alert(record: dict):
    """Push a real-time alert to the alerts buffer."""
    alert = {
        "id": record["id"],
        "timestamp": record["timestamp"],
        "ip": record["ip"],
        "username": record["username"],
        "risk_score": record["risk_score"],
        "risk_label": record["risk_label"],
        "attack_type": record["attack_type"],
        "message": _build_alert_message(record),
    }
    alerts.append(alert)
    # Keep only last 100 alerts
    if len(alerts) > 100:
        alerts.pop(0)


def _build_alert_message(record: dict) -> str:
    if record["risk_label"] == "High Risk Attack":
        return (f"🚨 HIGH RISK: IP {record['ip']} has {record['ip_fail_count']} failed attempts "
                f"on user '{record['username']}'. Risk Score: {record['risk_score']}")
    return (f"⚠️ SUSPICIOUS: IP {record['ip']} showing unusual login pattern "
            f"for '{record['username']}'. Risk Score: {record['risk_score']}")


def block_ip(ip: str) -> dict:
    """Block an IP address (simulated firewall rule)."""
    blocked_ips.add(ip)
    return {"status": "blocked", "ip": ip, "timestamp": datetime.now(timezone.utc).isoformat()}


def unblock_ip(ip: str) -> dict:
    """Unblock an IP address."""
    blocked_ips.discard(ip)
    return {"status": "unblocked", "ip": ip, "timestamp": datetime.now(timezone.utc).isoformat()}


def get_dashboard_stats() -> dict:
    """Aggregate statistics for dashboard cards."""
    total = len(login_logs)
    failed = sum(1 for l in login_logs if not l["success"])
    active_attacks = sum(1 for l in login_logs if l["risk_label"] == "High Risk Attack")
    blocked = len(blocked_ips)

    # Top attacking IPs
    ip_counts: dict = defaultdict(int)
    for l in login_logs:
        if not l["success"]:
            ip_counts[l["ip"]] += 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Risk distribution
    risk_dist = {"Normal Activity": 0, "Suspicious": 0, "High Risk Attack": 0}
    for l in login_logs:
        risk_dist[l.get("risk_label", "Normal Activity")] += 1

    # Failed attempts over last 60 minutes (per minute buckets)
    now = time.time()
    buckets = defaultdict(int)
    for l in login_logs:
        if not l["success"] and now - l["ts_epoch"] <= 3600:
            minute_key = int((now - l["ts_epoch"]) // 60)
            buckets[60 - minute_key] += 1
    time_series = [{"minute": i, "count": buckets.get(i, 0)} for i in range(1, 61)]

    return {
        "total_requests": total,
        "failed_logins": failed,
        "active_attacks": active_attacks,
        "blocked_ips": blocked,
        "success_rate": round((total - failed) / max(total, 1) * 100, 1),
        "top_attacking_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
        "risk_distribution": risk_dist,
        "time_series": time_series,
        "recent_alerts": alerts[-20:][::-1],
    }
