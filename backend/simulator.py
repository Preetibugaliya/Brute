"""
Simulator Module
-----------------
Generates realistic synthetic login attempts including:
  - Normal legitimate logins
  - Classic brute force attacks
  - Distributed brute force
  - Credential stuffing
Used for demo/testing the detection tool without real traffic.
"""

import random
import asyncio
import time
from datetime import datetime
from typing import List, Optional
from detection_engine import process_login_attempt

# ─────────────────────────────────────────────────────
# Fake data pools
# ─────────────────────────────────────────────────────
LEGITIMATE_USERS = [
    "alice", "bob", "charlie", "diana", "eve",
    "frank", "grace", "hank", "iris", "jack",
]

ATTACKER_IPS = [
    "10.0.0.15", "10.0.0.23", "10.0.0.87",
    "192.168.99.5", "192.168.99.12",
    "172.31.0.44", "172.31.0.89",
    "45.33.32.156", "198.211.127.10", "89.248.167.131",
    "185.220.101.45", "162.247.74.74",
]

LEGIT_IPS = [
    f"203.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    for _ in range(20)
]

COMMON_PASSWORDS_LIST = [
    "password", "123456", "admin", "letmein", "qwerty",
    "monkey", "master", "superman", "abc123", "pass@123",
]

COUNTRIES = [
    ("Russia", "Moscow"), ("China", "Beijing"), ("USA", "New York"),
    ("Germany", "Berlin"), ("Brazil", "São Paulo"), ("Unknown", "Unknown"),
    ("Iran", "Tehran"), ("India", "Mumbai"), ("UK", "London"),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
    "python-requests/2.31.0",
    "Hydra/9.0 (brute-force-tool)",
    "curl/7.88.1",
    "Go-http-client/1.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]


def _random_location():
    return random.choice(COUNTRIES)


def _simulate_normal_login() -> dict:
    """Simulate a legitimate successful or occasional single-fail login."""
    ip = random.choice(LEGIT_IPS)
    username = random.choice(LEGITIMATE_USERS)
    success = random.random() > 0.1  # 90% success
    country, city = _random_location()
    return process_login_attempt(
        ip=ip, username=username, success=success,
        user_agent=USER_AGENTS[0], country=country, city=city,
    )


def _simulate_brute_force(target_user: Optional[str] = None) -> List[dict]:
    """Simulate a brute force attack from a single attacker IP."""
    ip = random.choice(ATTACKER_IPS)
    username = target_user or random.choice(LEGITIMATE_USERS)
    country, city = random.choice([("Russia", "Moscow"), ("China", "Beijing"), ("Unknown", "Unknown")])
    count = random.randint(8, 20)
    logs = []
    for i in range(count):
        success = (i == count - 1 and random.random() > 0.7)
        logs.append(process_login_attempt(
            ip=ip, username=username, success=success,
            user_agent=random.choice(USER_AGENTS[2:]),
            country=country, city=city,
        ))
    return logs


def _simulate_distributed_attack(target_user: Optional[str] = None) -> List[dict]:
    """Simulate distributed brute force: multiple IPs on one user account."""
    username = target_user or random.choice(LEGITIMATE_USERS)
    ips = random.sample(ATTACKER_IPS, min(6, len(ATTACKER_IPS)))
    logs = []
    for ip in ips:
        count = random.randint(3, 8)
        country, city = _random_location()
        for _ in range(count):
            logs.append(process_login_attempt(
                ip=ip, username=username, success=False,
                user_agent=random.choice(USER_AGENTS),
                country=country, city=city,
            ))
    return logs


def _simulate_credential_stuffing(attacker_ip: Optional[str] = None) -> List[dict]:
    """Simulate credential stuffing: one IP, many different usernames."""
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    country, city = ("Russia", "Moscow")
    stuffed_users = [
        f"user{random.randint(1000, 9999)}" for _ in range(random.randint(15, 25))
    ]
    logs = []
    for username in stuffed_users:
        success = random.random() > 0.95  # Very low success rate
        logs.append(process_login_attempt(
            ip=ip, username=username, success=success,
            user_agent="python-requests/2.31.0",
            country=country, city=city,
        ))
    return logs


def run_full_simulation(mode: str = "mixed") -> dict:
    """
    Run a full attack simulation.
    mode: 'brute_force' | 'distributed' | 'stuffing' | 'mixed'
    Returns summary of generated logs.
    """
    generated = []

    # Always mix in normal traffic at a much higher volume
    for _ in range(random.randint(20, 60)):
        generated.append(_simulate_normal_login())

    if mode == "brute_force":
        for _ in range(3): generated.extend(_simulate_brute_force())
    elif mode == "distributed":
        for _ in range(3): generated.extend(_simulate_distributed_attack())
    elif mode == "stuffing":
        for _ in range(3): generated.extend(_simulate_credential_stuffing())
    else:  # mixed
        for _ in range(4): generated.extend(_simulate_brute_force())
        for _ in range(3): generated.extend(_simulate_distributed_attack())
        for _ in range(4): generated.extend(_simulate_credential_stuffing())
        for _ in range(random.randint(20, 40)):
            generated.append(_simulate_normal_login())

    high_risk = sum(1 for l in generated if l["risk_label"] == "High Risk Attack")
    suspicious = sum(1 for l in generated if l["risk_label"] == "Suspicious")

    return {
        "total_generated": len(generated),
        "high_risk": high_risk,
        "suspicious": suspicious,
        "normal": len(generated) - high_risk - suspicious,
        "attack_types": list({l["attack_type"] for l in generated}),
        "logs_sample": generated[-5:],  # Return last 5 for display
    }
