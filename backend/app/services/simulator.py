"""Attack simulation engine — generates realistic log sequences for four
scenarios (brute force, malware, insider threat, API abuse) and feeds them
through the detection pipeline with realistic delays.

Each scenario is an async function that:
  1. Generates a sequence of :class:`LogEntry` objects.
  2. Feeds each through :func:`detection_engine.process_log`.
  3. Sleeps between events so the frontend sees data streaming in over
     WebSocket in real time.
"""

from __future__ import annotations

import asyncio
import logging
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import List

from app.models.alert import LogEntry
from app.services import detection_engine

logger = logging.getLogger(__name__)

# ── Randomisation pools ──────────────────────────────────────────────────────

_SUSPICIOUS_IPS = [
    "185.220.101.34", "91.219.236.174", "23.129.64.210",
    "104.244.76.13", "198.98.56.78", "45.155.205.99",
    "162.247.74.201", "185.56.80.65", "5.188.86.114",
    "193.142.146.55", "194.26.192.64", "80.82.77.139",
]

_INTERNAL_IPS = [
    "10.0.1.45", "10.0.2.112", "10.0.3.78",
    "192.168.1.100", "192.168.1.201", "172.16.0.55",
]

_SUSPICIOUS_LOCATIONS = [
    {"country": "Russia", "city": "Moscow"},
    {"country": "China", "city": "Shanghai"},
    {"country": "Nigeria", "city": "Lagos"},
    {"country": "North Korea", "city": "Pyongyang"},
    {"country": "Iran", "city": "Tehran"},
    {"country": "Romania", "city": "Bucharest"},
    {"country": "Brazil", "city": "São Paulo"},
]

_INTERNAL_LOCATIONS = [
    {"country": "US", "city": "New York"},
    {"country": "US", "city": "San Francisco"},
    {"country": "US", "city": "Chicago"},
]

_USERS = ["john.doe", "jane.smith", "bob.wilson", "alice.chen", "charlie.brown"]
_ADMIN_USERS = ["admin", "root", "sysadmin", "admin.global", "sa_backup"]
_DEVICES = [
    "WORKSTATION-001", "WORKSTATION-047", "LAPTOP-CORP-12",
    "SERVER-PROD-01", "SERVER-DB-03", "DESKTOP-IT-05",
]

_MALWARE_C2_IPS = [
    "45.33.32.156", "104.244.72.115", "23.129.64.100",
    "185.100.87.41", "91.121.87.18",
]

_BAD_PROCESSES = [
    "svchost_update.exe", "winlogon_helper.dll", "chrome_update.bat",
    "system32_patch.ps1", "driver_update.scr",
]


def _now_iso(offset_seconds: int = 0) -> str:
    """Return an ISO-8601 timestamp shifted by *offset_seconds*."""
    dt = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return dt.isoformat()


def _rand(lo: float, hi: float) -> float:
    return random.uniform(lo, hi)


# ═════════════════════════════════════════════════════════════════════════════
#  SCENARIO 1 — BRUTE FORCE
# ═════════════════════════════════════════════════════════════════════════════

async def run_bruteforce() -> str:
    """Simulate a brute-force / credential-stuffing attack.

    Sequence:
      - 8–15 failed logins from a foreign IP
      - 1 successful login
      - Privilege escalation attempt
    """
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    logger.info("Starting brute-force simulation %s", job_id)

    src_ip = random.choice(_SUSPICIOUS_IPS)
    location = random.choice(_SUSPICIOUS_LOCATIONS)
    target_user = random.choice(_USERS)
    admin_user = random.choice(_ADMIN_USERS)
    device = random.choice(_DEVICES)

    failed_count = random.randint(8, 15)
    offset = 0

    # Phase 1 — Failed logins (mix of normal + admin users)
    for i in range(failed_count):
        user = target_user if i < failed_count - 3 else admin_user
        log = LogEntry(
            timestamp=_now_iso(offset),
            user=user,
            ip_address=src_ip,
            location=location,
            device=device,
            event_type="authentication_failure",
            severity="medium",
            raw_message=(
                f"Failed login attempt #{i + 1} for user '{user}' from "
                f"{src_ip} ({location['city']}, {location['country']}). "
                f"Reason: invalid credentials. Auth method: password."
            ),
        )
        await detection_engine.process_log(log, simulation_type="bruteforce")
        offset += random.randint(5, 15)
        await asyncio.sleep(_rand(0.3, 0.8))

    # Phase 2 — Successful login (attacker found valid credentials)
    log = LogEntry(
        timestamp=_now_iso(offset),
        user=target_user,
        ip_address=src_ip,
        location=location,
        device=device,
        event_type="login_success",
        severity="low",
        raw_message=(
            f"Successful login for user '{target_user}' from {src_ip} "
            f"({location['city']}, {location['country']}). "
            f"Session established. MFA: not enrolled."
        ),
    )
    await detection_engine.process_log(log, simulation_type="bruteforce")
    offset += random.randint(10, 30)
    await asyncio.sleep(_rand(0.5, 1.0))

    # Phase 3 — Privilege escalation attempt
    log = LogEntry(
        timestamp=_now_iso(offset),
        user=target_user,
        ip_address=src_ip,
        location=location,
        device=device,
        event_type="privilege_escalation",
        severity="critical",
        raw_message=(
            f"Privilege escalation attempt detected: user '{target_user}' "
            f"executed 'sudo su - root' on {device}. "
            f"Source: {src_ip}. Previous session established {offset}s ago."
        ),
    )
    await detection_engine.process_log(log, simulation_type="bruteforce")
    await asyncio.sleep(0.3)

    logger.info("Brute-force simulation %s completed", job_id)
    return job_id


# ═════════════════════════════════════════════════════════════════════════════
#  SCENARIO 2 — MALWARE / C2 BEACONING
# ═════════════════════════════════════════════════════════════════════════════

async def run_malware() -> str:
    """Simulate a malware infection with C2 beaconing and data staging.

    Sequence:
      - Suspicious process execution
      - Outbound connection to known-bad IP
      - Large file read from system directories
      - Registry/config modification
    """
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    logger.info("Starting malware simulation %s", job_id)

    user = random.choice(_USERS)
    device = random.choice(_DEVICES)
    internal_ip = random.choice(_INTERNAL_IPS)
    c2_ip = random.choice(_MALWARE_C2_IPS)
    process = random.choice(_BAD_PROCESSES)
    location = random.choice(_INTERNAL_LOCATIONS)
    offset = 0

    # Step 1 — Suspicious process execution
    log = LogEntry(
        timestamp=_now_iso(offset),
        user=user,
        ip_address=internal_ip,
        location=location,
        device=device,
        event_type="process_execution",
        severity="high",
        raw_message=(
            f"Suspicious process '{process}' spawned by explorer.exe on {device}. "
            f"User: {user}. PID: {random.randint(1000, 9999)}. "
            f"Hash: {uuid.uuid4().hex}. Process is unsigned and not in whitelist."
        ),
    )
    await detection_engine.process_log(log, simulation_type="malware")
    offset += random.randint(5, 15)
    await asyncio.sleep(_rand(0.4, 0.9))

    # Step 2 — Outbound C2 connection
    log = LogEntry(
        timestamp=_now_iso(offset),
        user=user,
        ip_address=internal_ip,
        location=location,
        device=device,
        event_type="network_connection",
        severity="high",
        raw_message=(
            f"Outbound connection from {device} ({internal_ip}) to known malicious IP "
            f"{c2_ip}:443 (TLS). Process: {process}. Bytes sent: "
            f"{random.randint(256, 4096)}. Matched threat intel feed: "
            f"AlienVault OTX, VirusTotal."
        ),
    )
    await detection_engine.process_log(log, simulation_type="malware")
    offset += random.randint(10, 30)
    await asyncio.sleep(_rand(0.4, 0.9))

    # Step 3 — Large file read from system directories
    log = LogEntry(
        timestamp=_now_iso(offset),
        user=user,
        ip_address=internal_ip,
        location=location,
        device=device,
        event_type="file_access",
        severity="medium",
        raw_message=(
            f"Bulk file read detected on {device}: {process} accessed "
            f"{random.randint(50, 500)} files in C:\\Windows\\System32 and "
            f"C:\\Users\\{user}\\Documents. Total read: "
            f"{random.randint(100, 800)} MB. Potential staging for exfiltration."
        ),
    )
    await detection_engine.process_log(log, simulation_type="malware")
    offset += random.randint(5, 20)
    await asyncio.sleep(_rand(0.4, 0.9))

    # Step 4 — Registry modification for persistence
    log = LogEntry(
        timestamp=_now_iso(offset),
        user=user,
        ip_address=internal_ip,
        location=location,
        device=device,
        event_type="privilege_escalation",
        severity="critical",
        raw_message=(
            f"Registry modification detected on {device}: {process} added entry to "
            f"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run. "
            f"Value: '{process}' → 'C:\\ProgramData\\{process}'. "
            f"This establishes persistence via auto-start. Executed sudo elevation."
        ),
    )
    await detection_engine.process_log(log, simulation_type="malware")
    await asyncio.sleep(0.3)

    logger.info("Malware simulation %s completed", job_id)
    return job_id


# ═════════════════════════════════════════════════════════════════════════════
#  SCENARIO 3 — INSIDER THREAT
# ═════════════════════════════════════════════════════════════════════════════

async def run_insider_threat() -> str:
    """Simulate an insider threat: bulk DB reads + large file download.

    Sequence:
      - Multiple abnormal database queries (bulk reads)
      - Large file download outside business hours
    """
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    logger.info("Starting insider-threat simulation %s", job_id)

    user = random.choice(_USERS)
    device = random.choice(_DEVICES)
    internal_ip = random.choice(_INTERNAL_IPS)
    location = random.choice(_INTERNAL_LOCATIONS)
    offset = 0

    tables = ["customers", "payments", "employees", "contracts", "accounts"]

    # Phase 1 — Anomalous bulk DB queries
    query_count = random.randint(15, 25)
    for i in range(query_count):
        table = random.choice(tables)
        log = LogEntry(
            timestamp=_now_iso(offset),
            user=user,
            ip_address=internal_ip,
            location=location,
            device=device,
            event_type="database_query",
            severity="low",
            raw_message=(
                f"SELECT * FROM {table} — returned {random.randint(1000, 50000)} rows. "
                f"Query executed by '{user}' from {device}. Duration: "
                f"{random.randint(50, 3000)}ms. No WHERE clause — full table scan."
            ),
        )
        await detection_engine.process_log(log, simulation_type="insider_threat")
        offset += random.randint(2, 8)
        await asyncio.sleep(_rand(0.2, 0.5))

    # Phase 2 — Large file downloads
    for i in range(3):
        size_mb = random.randint(150, 350)
        log = LogEntry(
            timestamp=_now_iso(offset),
            user=user,
            ip_address=internal_ip,
            location=location,
            device=device,
            event_type="file_download",
            severity="medium",
            raw_message=(
                f"File download: '{user}' downloaded {size_mb} MB from internal file "
                f"server (\\\\fileserver\\confidential\\Q{random.randint(1, 4)}_reports). "
                f"Destination: {device} local disk. Time: off-hours "
                f"({random.randint(1, 5)}:{random.randint(10, 59):02d} AM UTC)."
            ),
        )
        await detection_engine.process_log(log, simulation_type="insider_threat")
        offset += random.randint(10, 30)
        await asyncio.sleep(_rand(0.4, 0.8))

    logger.info("Insider-threat simulation %s completed", job_id)
    return job_id


# ═════════════════════════════════════════════════════════════════════════════
#  SCENARIO 4 — API ABUSE
# ═════════════════════════════════════════════════════════════════════════════

async def run_api_abuse() -> str:
    """Simulate API abuse: rate-limit bypass + token reuse from different IP.

    Sequence:
      - Spike in API calls from a single OAuth token
      - Rate-limit bypass attempts
      - Token reuse from a different IP
    """
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    logger.info("Starting API-abuse simulation %s", job_id)

    user = random.choice(_USERS)
    device = random.choice(_DEVICES)
    primary_ip = random.choice(_INTERNAL_IPS)
    secondary_ip = random.choice(_SUSPICIOUS_IPS)
    location = random.choice(_INTERNAL_LOCATIONS)
    endpoints = [
        "/api/v2/users", "/api/v2/accounts", "/api/v2/export",
        "/api/v2/transactions", "/api/v2/reports", "/api/v2/config",
    ]
    offset = 0

    # Phase 1 — High-volume API calls (exceed 500/min threshold simulated by
    # sending many events rapidly)
    burst_count = random.randint(20, 35)
    for i in range(burst_count):
        endpoint = random.choice(endpoints)
        log = LogEntry(
            timestamp=_now_iso(offset),
            user=user,
            ip_address=primary_ip,
            location=location,
            device=device,
            event_type="api_request",
            severity="low",
            raw_message=(
                f"API call: GET {endpoint} by token '{user}' from {primary_ip}. "
                f"Response: 200 OK. Payload: {random.randint(1, 500)} KB. "
                f"Rate: {random.randint(100, 600)} req/min."
            ),
        )
        await detection_engine.process_log(log, simulation_type="api_abuse")
        offset += 1  # Events spaced 1 second apart
        await asyncio.sleep(_rand(0.1, 0.3))

    # Phase 2 — Rate-limit bypass attempts
    for i in range(5):
        log = LogEntry(
            timestamp=_now_iso(offset),
            user=user,
            ip_address=primary_ip,
            location=location,
            device=device,
            event_type="api_request",
            severity="medium",
            raw_message=(
                f"Rate limit bypass attempt: token '{user}' sent request with "
                f"X-Forwarded-For: {random.choice(_SUSPICIOUS_IPS)} to circumvent "
                f"IP-based rate limiting on {random.choice(endpoints)}. "
                f"Header manipulation detected."
            ),
        )
        await detection_engine.process_log(log, simulation_type="api_abuse")
        offset += 2
        await asyncio.sleep(_rand(0.2, 0.5))

    # Phase 3 — Token reuse from different IP
    for i in range(3):
        log = LogEntry(
            timestamp=_now_iso(offset),
            user=user,
            ip_address=secondary_ip,
            location=random.choice(_SUSPICIOUS_LOCATIONS),
            device=f"UNKNOWN-DEVICE-{random.randint(1, 99):02d}",
            event_type="api_token_usage",
            severity="high",
            raw_message=(
                f"Token replay detected: OAuth token for '{user}' used from "
                f"{secondary_ip} — differs from primary IP {primary_ip}. "
                f"Time delta: {random.randint(5, 55)}s. "
                f"Endpoint: {random.choice(endpoints)}."
            ),
        )
        await detection_engine.process_log(log, simulation_type="api_abuse")
        offset += random.randint(3, 10)
        await asyncio.sleep(_rand(0.3, 0.7))

    logger.info("API-abuse simulation %s completed", job_id)
    return job_id

# ═════════════════════════════════════════════════════════════════════════════
#  SCENARIO 5 — RANSOMWARE
# ═════════════════════════════════════════════════════════════════════════════

async def run_ransomware() -> str:
    """Simulate a ransomware attack: mass file encryption and VSS deletion.

    Sequence:
      - High volume of file writes (encryption)
      - Appending .encrypted extension
      - Shadow copy deletion (vssadmin)
    """
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    logger.info("Starting ransomware simulation %s", job_id)

    user = random.choice(_USERS)
    device = random.choice(_DEVICES)
    internal_ip = random.choice(_INTERNAL_IPS)
    location = random.choice(_INTERNAL_LOCATIONS)
    offset = 0

    # Phase 1 — Mass file encryption
    for i in range(5):
        log = LogEntry(
            timestamp=_now_iso(offset),
            user=user,
            ip_address=internal_ip,
            location=location,
            device=device,
            event_type="file_access",
            severity="high",
            raw_message=(
                f"Ransomware activity detected on {device}: Process 'svchost.exe' "
                f"rapidly modified {random.randint(1000, 5000)} files in C:\\Users\\{user}\\Documents, "
                f"appending '.locky' extension. Entropy of written files is highly elevated (0.98)."
            ),
        )
        await detection_engine.process_log(log, simulation_type="ransomware")
        offset += random.randint(1, 3)
        await asyncio.sleep(_rand(0.2, 0.4))

    # Phase 2 — Volume Shadow Copy deletion
    log = LogEntry(
        timestamp=_now_iso(offset),
        user=user,
        ip_address=internal_ip,
        location=location,
        device=device,
        event_type="process_execution",
        severity="critical",
        raw_message=(
            f"Destructive action on {device}: Process 'vssadmin.exe' executed with arguments "
            f"'delete shadows /all /quiet'. This is a known precursor to ransomware to prevent recovery."
        ),
    )
    await detection_engine.process_log(log, simulation_type="ransomware")
    
    logger.info("Ransomware simulation %s completed", job_id)
    return job_id


# ═════════════════════════════════════════════════════════════════════════════
#  SCENARIO 6 — DDOS ATTACK
# ═════════════════════════════════════════════════════════════════════════════

async def run_ddos() -> str:
    """Simulate a DDoS attack against web properties."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    logger.info("Starting DDoS simulation %s", job_id)

    target_device = "WAF-PERIMETER-01"
    offset = 0

    for i in range(15):
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        log = LogEntry(
            timestamp=_now_iso(offset),
            user="anonymous",
            ip_address=src_ip,
            location=random.choice(_SUSPICIOUS_LOCATIONS),
            device=target_device,
            event_type="network_connection",
            severity="medium",
            raw_message=(
                f"High volume SYN flood detected targeting {target_device}. "
                f"Rate: {random.randint(50000, 150000)} pps from distributed sources including {src_ip}. "
                f"Connection tracking table at 98% capacity."
            ),
        )
        await detection_engine.process_log(log, simulation_type="ddos")
        offset += 1
        await asyncio.sleep(_rand(0.1, 0.2))

    logger.info("DDoS simulation %s completed", job_id)
    return job_id


# ═════════════════════════════════════════════════════════════════════════════
#  SCENARIO 7 — SQL INJECTION (SQLi)
# ═════════════════════════════════════════════════════════════════════════════

async def run_sqli() -> str:
    """Simulate a Web App SQL Injection attack."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    logger.info("Starting SQLi simulation %s", job_id)

    src_ip = random.choice(_SUSPICIOUS_IPS)
    location = random.choice(_SUSPICIOUS_LOCATIONS)
    device = "WEBSERVER-01"
    offset = 0

    payloads = [
        "' OR 1=1 --",
        "admin' --",
        "1; DROP TABLE users",
        "UNION SELECT null, username, password FROM users"
    ]

    for i in range(8):
        log = LogEntry(
            timestamp=_now_iso(offset),
            user="anonymous",
            ip_address=src_ip,
            location=location,
            device=device,
            event_type="api_request",
            severity="high",
            raw_message=(
                f"Web Application Firewall alert: SQL Injection payload detected from {src_ip}. "
                f"Request URI: /login.php?user={random.choice(payloads)}. "
                f"Matched regex pattern for SQLi."
            ),
        )
        await detection_engine.process_log(log, simulation_type="sqli")
        offset += random.randint(1, 3)
        await asyncio.sleep(_rand(0.2, 0.5))

    logger.info("SQLi simulation %s completed", job_id)
    return job_id

# ═════════════════════════════════════════════════════════════════════════════
#  SCENARIO 8 — PASSWORD SPRAYING
# ═════════════════════════════════════════════════════════════════════════════

async def run_password_spraying() -> str:
    """Simulate a password spraying attack.
    Sequence: 1-2 failed logins across many different user accounts from the same IP.
    """
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    logger.info("Starting password spraying simulation %s", job_id)

    src_ip = random.choice(_SUSPICIOUS_IPS)
    location = random.choice(_SUSPICIOUS_LOCATIONS)
    device = "UNKNOWN-DEVICE"
    offset = 0

    target_users = [f"user.{i:03d}" for i in range(20)]
    for u in target_users:
        log = LogEntry(
            timestamp=_now_iso(offset),
            user=u,
            ip_address=src_ip,
            location=location,
            device=device,
            event_type="authentication_failure",
            severity="medium",
            raw_message=(
                f"Failed login attempt for user '{u}' from {src_ip} "
                f"({location['city']}, {location['country']}). "
                f"Reason: invalid credentials. Auth method: password."
            ),
        )
        await detection_engine.process_log(log, simulation_type="password_spraying")
        offset += random.randint(1, 3)
        await asyncio.sleep(_rand(0.1, 0.3))

    logger.info("Password spraying simulation %s completed", job_id)
    return job_id

# ═════════════════════════════════════════════════════════════════════════════
#  SCENARIO 9 — IMPOSSIBLE TRAVEL
# ═════════════════════════════════════════════════════════════════════════════

async def run_impossible_travel() -> str:
    """Simulate impossible travel.
    Sequence: Successful login from two distant locations within a short timeframe.
    """
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    logger.info("Starting impossible travel simulation %s", job_id)

    user = random.choice(_USERS)
    device = random.choice(_DEVICES)
    
    loc1 = {"country": "India", "city": "Mumbai"}
    ip1 = "103.112.50.21"
    
    loc2 = {"country": "UK", "city": "London"}
    ip2 = "212.115.109.11"
    
    offset = 0

    log1 = LogEntry(
        timestamp=_now_iso(offset),
        user=user,
        ip_address=ip1,
        location=loc1,
        device=device,
        event_type="login_success",
        severity="low",
        raw_message=f"Successful login for user '{user}' from {ip1} ({loc1['city']}, {loc1['country']})."
    )
    await detection_engine.process_log(log1, simulation_type="impossible_travel")
    await asyncio.sleep(0.5)

    offset += 1200 # 20 minutes later

    log2 = LogEntry(
        timestamp=_now_iso(offset),
        user=user,
        ip_address=ip2,
        location=loc2,
        device=device,
        event_type="login_success",
        severity="high",
        raw_message=f"Successful login for user '{user}' from {ip2} ({loc2['city']}, {loc2['country']})."
    )
    await detection_engine.process_log(log2, simulation_type="impossible_travel")
    
    logger.info("Impossible travel simulation %s completed", job_id)
    return job_id

# ═════════════════════════════════════════════════════════════════════════════
#  SCENARIO 10 — BEACONING
# ═════════════════════════════════════════════════════════════════════════════

async def run_beaconing() -> str:
    """Simulate C2 beaconing.
    Sequence: Outbound connections to external IP at highly regular intervals.
    """
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    logger.info("Starting beaconing simulation %s", job_id)

    user = random.choice(_USERS)
    device = random.choice(_DEVICES)
    internal_ip = random.choice(_INTERNAL_IPS)
    c2_ip = random.choice(_MALWARE_C2_IPS)
    location = random.choice(_INTERNAL_LOCATIONS)
    offset = 0

    for i in range(10):
        log = LogEntry(
            timestamp=_now_iso(offset),
            user=user,
            ip_address=internal_ip,
            location=location,
            device=device,
            event_type="network_connection",
            severity="medium",
            raw_message=(
                f"Outbound connection from {device} ({internal_ip}) to {c2_ip}:443. "
                f"Bytes sent: {random.randint(100, 150)}. Bytes received: {random.randint(100, 150)}. "
                f"Periodic heartbeat beacon detected."
            ),
        )
        await detection_engine.process_log(log, simulation_type="beaconing")
        offset += 60 + random.uniform(-1, 1) # Regular 60s interval
        await asyncio.sleep(0.2)

    logger.info("Beaconing simulation %s completed", job_id)
    return job_id

# ═════════════════════════════════════════════════════════════════════════════
#  SCENARIO 11 — DNS TUNNELING
# ═════════════════════════════════════════════════════════════════════════════

async def run_dns_tunneling() -> str:
    """Simulate DNS tunneling for data exfiltration."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    logger.info("Starting DNS tunneling simulation %s", job_id)

    user = random.choice(_USERS)
    device = random.choice(_DEVICES)
    internal_ip = random.choice(_INTERNAL_IPS)
    location = random.choice(_INTERNAL_LOCATIONS)
    offset = 0

    for i in range(15):
        subdomain = uuid.uuid4().hex + uuid.uuid4().hex
        log = LogEntry(
            timestamp=_now_iso(offset),
            user=user,
            ip_address=internal_ip,
            location=location,
            device=device,
            event_type="dns_query",
            severity="high",
            raw_message=(
                f"DNS Query: {subdomain}.evil-domain.com. "
                f"High entropy subdomain detected from {device} ({internal_ip}). "
                f"Potential DNS tunneling payload."
            ),
        )
        await detection_engine.process_log(log, simulation_type="dns_tunneling")
        offset += random.randint(1, 3)
        await asyncio.sleep(0.1)

    logger.info("DNS tunneling simulation %s completed", job_id)
    return job_id

# ═════════════════════════════════════════════════════════════════════════════
#  SCENARIO 12 — CLOUD METADATA ABUSE
# ═════════════════════════════════════════════════════════════════════════════

async def run_cloud_metadata_abuse() -> str:
    """Simulate cloud metadata service abuse (SSRF)."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    logger.info("Starting Cloud metadata abuse simulation %s", job_id)

    device = "EC2-WEB-PROD"
    internal_ip = random.choice(_INTERNAL_IPS)
    location = random.choice(_INTERNAL_LOCATIONS)
    offset = 0

    log = LogEntry(
        timestamp=_now_iso(offset),
        user="www-data",
        ip_address=internal_ip,
        location=location,
        device=device,
        event_type="api_request",
        severity="critical",
        raw_message=(
            f"HTTP request from web application process on {device} ({internal_ip}) "
            f"targeting 169.254.169.254/latest/meta-data/iam/security-credentials/. "
            f"Potential SSRF attempting IAM credential theft."
        ),
    )
    await detection_engine.process_log(log, simulation_type="cloud_metadata_abuse")
    await asyncio.sleep(0.5)

    logger.info("Cloud metadata abuse simulation %s completed", job_id)
    return job_id

# ═════════════════════════════════════════════════════════════════════════════
#  SCENARIO 13 — IAM PRIVILEGE ESCALATION
# ═════════════════════════════════════════════════════════════════════════════

async def run_iam_privilege_escalation() -> str:
    """Simulate IAM privilege escalation in the cloud."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    logger.info("Starting IAM Privilege Escalation simulation %s", job_id)

    user = "dev.contractor"
    src_ip = random.choice(_SUSPICIOUS_IPS)
    location = random.choice(_SUSPICIOUS_LOCATIONS)
    device = "AWS-CLI"
    offset = 0

    log = LogEntry(
        timestamp=_now_iso(offset),
        user=user,
        ip_address=src_ip,
        location=location,
        device=device,
        event_type="iam_policy_change",
        severity="critical",
        raw_message=(
            f"IAM Event: User '{user}' called iam:AttachUserPolicy from {src_ip} "
            f"attaching 'AdministratorAccess' to their own account. "
            f"Unauthorized privilege escalation detected."
        ),
    )
    await detection_engine.process_log(log, simulation_type="iam_privilege_escalation")
    await asyncio.sleep(0.5)

    logger.info("IAM Privilege Escalation simulation %s completed", job_id)
    return job_id

# ═════════════════════════════════════════════════════════════════════════════
#  SCENARIO 14 — STAGING BEFORE EXFILTRATION
# ═════════════════════════════════════════════════════════════════════════════

async def run_staging_before_exfiltration() -> str:
    """Simulate data staging before exfiltration."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    logger.info("Starting Staging before exfiltration simulation %s", job_id)

    user = random.choice(_USERS)
    device = random.choice(_DEVICES)
    internal_ip = random.choice(_INTERNAL_IPS)
    location = random.choice(_INTERNAL_LOCATIONS)
    offset = 0

    for i in range(5):
        log = LogEntry(
            timestamp=_now_iso(offset),
            user=user,
            ip_address=internal_ip,
            location=location,
            device=device,
            event_type="file_access",
            severity="medium",
            raw_message=(
                f"File read: process 'tar' accessed confidential directory. "
                f"Aggregating {random.randint(50, 150)} files."
            ),
        )
        await detection_engine.process_log(log, simulation_type="staging_exfiltration")
        offset += random.randint(2, 5)
        await asyncio.sleep(0.2)

    log = LogEntry(
        timestamp=_now_iso(offset),
        user=user,
        ip_address=internal_ip,
        location=location,
        device=device,
        event_type="file_creation",
        severity="high",
        raw_message=(
            f"Large compressed archive created in /tmp/backup_{random.randint(1000,9999)}.tar.gz. "
            f"Size: {random.randint(500, 2000)} MB. Highly indicative of data staging for exfiltration."
        ),
    )
    await detection_engine.process_log(log, simulation_type="staging_exfiltration")
    await asyncio.sleep(0.5)

    logger.info("Staging before exfiltration simulation %s completed", job_id)
    return job_id

# ═════════════════════════════════════════════════════════════════════════════
#  SCENARIO 15 — SLOW-DRIP EXFILTRATION
# ═════════════════════════════════════════════════════════════════════════════

async def run_slow_drip_exfiltration() -> str:
    """Simulate slow-drip data exfiltration over days."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    logger.info("Starting Slow-drip exfiltration simulation %s", job_id)

    user = random.choice(_USERS)
    device = random.choice(_DEVICES)
    internal_ip = random.choice(_INTERNAL_IPS)
    location = random.choice(_INTERNAL_LOCATIONS)
    dst_ip = random.choice(_SUSPICIOUS_IPS)
    
    # 7 days of daily transfers
    for day in range(7):
        offset = -(7 - day) * 86400  # Go back up to 7 days
        log = LogEntry(
            timestamp=_now_iso(offset),
            user=user,
            ip_address=internal_ip,
            location=location,
            device=device,
            event_type="network_connection",
            severity="high",
            raw_message=(
                f"Sustained outbound transfer to {dst_ip}. "
                f"Bytes sent: 480 MB (just below 500MB daily threshold). "
                f"Slow-drip exfiltration detected over day {day+1}."
            ),
        )
        await detection_engine.process_log(log, simulation_type="slow_drip_exfiltration")
        await asyncio.sleep(0.2)

    logger.info("Slow-drip exfiltration simulation %s completed", job_id)
    return job_id

# ═════════════════════════════════════════════════════════════════════════════
#  SCENARIO 11 — DECEPTION TECHNOLOGY (HONEYPOT)
# ═════════════════════════════════════════════════════════════════════════════

async def run_honeypot_access() -> str:
    """Simulate an attacker tripping a honeypot endpoint."""
    job_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    logger.info("Starting honeypot simulation %s", job_id)

    src_ip = random.choice(_INTERNAL_IPS)
    target_user = "sa_backup"
    device = random.choice(_DEVICES)

    # Legitimate looking internal traffic first
    logs = [
        LogEntry(
            timestamp=_now_iso(),
            user=target_user,
            ip_address=src_ip,
            location={"country": "US", "city": "Internal"},
            device=device,
            event_type="web_access",
            severity="low",
            raw_message="GET /dashboard/home HTTP/1.1 200 OK",
        ),
        LogEntry(
            timestamp=_now_iso(1),
            user=target_user,
            ip_address=src_ip,
            location={"country": "US", "city": "Internal"},
            device=device,
            event_type="web_access",
            severity="low",
            raw_message="GET /api/v1/user/profile HTTP/1.1 200 OK",
        )
    ]
    
    for log in logs:
        await detection_engine.process_log(log, simulation_type="honeypot_access")
        await asyncio.sleep(_rand(0.2, 0.8))
        
    # The Trap: Accessing a hidden honeypot
    await asyncio.sleep(2.0)
    trap_log = LogEntry(
        timestamp=_now_iso(3),
        user=target_user,
        ip_address=src_ip,
        location={"country": "US", "city": "Internal"},
        device=device,
        event_type="web_access",
        severity="critical",
        raw_message="GET /.env HTTP/1.1 403 Forbidden",
    )
    await detection_engine.process_log(trap_log, simulation_type="honeypot_access")
    await asyncio.sleep(_rand(0.5, 1.2))

    trap_log_2 = LogEntry(
        timestamp=_now_iso(5),
        user=target_user,
        ip_address=src_ip,
        location={"country": "US", "city": "Internal"},
        device=device,
        event_type="web_access",
        severity="critical",
        raw_message="GET /admin-backup-2023.zip HTTP/1.1 404 Not Found",
    )
    await detection_engine.process_log(trap_log_2, simulation_type="honeypot_access")

    logger.info("Honeypot simulation %s completed", job_id)
    return job_id

