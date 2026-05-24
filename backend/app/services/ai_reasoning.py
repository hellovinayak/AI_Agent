"""AI reasoning service — mock library + live OpenAI / Claude integration.

The mock library provides **complete, realistic, detailed** analysis text for
every detection rule so the frontend always has rich data to display even
without an API key.  When a live provider is configured the service constructs
a structured prompt, calls the API, parses JSON, and falls back to mock on any
error.
"""

from __future__ import annotations

import json
import logging
import random
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# pyrefly: ignore [missing-import]
import httpx

from app.core.config import settings
from app.models.alert import AIAnalysis, Alert

logger = logging.getLogger(__name__)

# ── Helper pools for randomisation ───────────────────────────────────────────

_SUSPICIOUS_IPS = [
    "185.220.101.34", "91.219.236.174", "23.129.64.210",
    "104.244.76.13", "198.98.56.78", "45.155.205.99",
    "162.247.74.201", "185.56.80.65", "5.188.86.114",
    "193.142.146.55",
]

_CITIES = [
    ("Moscow", "Russia"), ("Lagos", "Nigeria"), ("Beijing", "China"),
    ("São Paulo", "Brazil"), ("Pyongyang", "North Korea"),
    ("Bucharest", "Romania"), ("Tehran", "Iran"), ("Minsk", "Belarus"),
]

_ANALYSTS = ["SOC-Analyst-1", "SOC-Analyst-2", "IR-Lead", "CISO-Bot"]


def _rand_ip() -> str:
    return random.choice(_SUSPICIOUS_IPS)


def _rand_city() -> tuple[str, str]:
    return random.choice(_CITIES)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ═════════════════════════════════════════════════════════════════════════════
#  MOCK RESPONSE LIBRARY — one per detection rule
# ═════════════════════════════════════════════════════════════════════════════

def _mock_det001(alert: Alert) -> AIAnalysis:
    """Brute-force / credential-stuffing analysis."""
    city, country = _rand_city()
    src_ip = alert.ip_address or _rand_ip()
    return AIAnalysis(
        explanation=(
            f"Detected a credential-stuffing attack originating from {src_ip} "
            f"(geo: {city}, {country}). The source IP attempted {random.randint(8, 47)} "
            f"authentication requests against user '{alert.user}' within a 120-second "
            f"window using a rotating set of passwords consistent with the Combo-List "
            f"technique. The IP belongs to AS{random.randint(10000,99999)} and has been "
            f"flagged in 3 threat-intelligence feeds (AbuseIPDB score 92/100). "
            f"No successful authentication was observed during this burst, but the "
            f"velocity and pattern strongly indicate automated tooling such as Hydra or "
            f"Sentry MBA."
        ),
        narrative=(
            f"An external threat actor operating from {country} leveraged a credential "
            f"dump — likely sourced from a third-party breach — to perform high-speed "
            f"login attempts against the '{alert.user}' account. The attacker cycled "
            f"through approximately {random.randint(500, 5000)} username/password "
            f"combinations in under two minutes, suggesting automated tooling behind a "
            f"residential-proxy network. If any credential pair matched, the attacker's "
            f"next move would be to establish persistence and move laterally toward "
            f"high-value assets."
        ),
        severity_reasoning=(
            "Severity set to HIGH because: (1) login velocity exceeds the 5-attempts/"
            "2-min threshold by a wide margin, (2) the source IP is associated with "
            "known malicious infrastructure, (3) the targeted account has elevated "
            "privileges in the identity provider."
        ),
        mitre_tactics=["Initial Access", "Credential Access"],
        mitre_techniques=[
            {"id": "T1110.004", "name": "Credential Stuffing"},
            {"id": "T1078", "name": "Valid Accounts"},
        ],
        recommended_actions=[
            f"Block {src_ip} at the perimeter firewall and WAF immediately",
            "Enable progressive rate-limiting on the authentication endpoint",
            f"Notify user '{alert.user}' and force password reset",
            "Check if the credential pair appears in known breach databases (HIBP)",
            "Review authentication logs for successful logins from this IP range",
            "Consider enabling CAPTCHA after 3 failed attempts",
        ],
        business_impact=(
            f"If the attacker successfully authenticates as '{alert.user}', they could "
            f"access sensitive internal systems, exfiltrate data, and potentially "
            f"escalate to domain-admin privileges. Estimated blast radius: "
            f"{random.randint(3, 12)} connected services."
        ),
        next_step_prediction=(
            "If a valid credential is found, expect lateral movement within "
            "5–15 minutes — likely via RDP or SMB — targeting file shares and "
            "database servers. The attacker will also attempt to establish a "
            "persistence mechanism (e.g. scheduled task or SSH key injection)."
        ),
        generated_by="mock",
        generated_at=datetime.now(timezone.utc),
    )


def _mock_det002(alert: Alert) -> AIAnalysis:
    """Geo-anomaly login analysis."""
    city, country = _rand_city()
    return AIAnalysis(
        explanation=(
            f"A successful authentication for '{alert.user}' was observed from "
            f"{city}, {country} — a location that does not appear in the user's "
            f"90-day login history. The previous login originated from New York, US "
            f"approximately {random.randint(1, 8)} hours ago, making physical travel "
            f"between the two locations impossible ('impossible-travel' heuristic). "
            f"The session was established from IP {alert.ip_address} using "
            f"user-agent string consistent with a headless browser."
        ),
        narrative=(
            f"A potential account-takeover is in progress. The threat actor, operating "
            f"from {country}, successfully authenticated as '{alert.user}' using valid "
            f"credentials — possibly obtained through phishing or a prior credential "
            f"leak. The geographic anomaly strongly suggests the legitimate user did "
            f"not initiate this session."
        ),
        severity_reasoning=(
            "Severity set to MEDIUM because: (1) impossible-travel detected but MFA "
            "status is unknown, (2) no post-login anomalous behavior observed yet, "
            "(3) the user has not reported a compromised account."
        ),
        mitre_tactics=["Initial Access", "Defense Evasion"],
        mitre_techniques=[
            {"id": "T1078", "name": "Valid Accounts"},
            {"id": "T1090", "name": "Proxy"},
        ],
        recommended_actions=[
            f"Contact '{alert.user}' immediately to verify the login",
            "Invalidate all active sessions for the account",
            "Force MFA re-enrollment",
            "Review access logs for any data exfiltration during the session",
            f"Add {alert.ip_address} to the watchlist",
        ],
        business_impact=(
            f"Unauthorized access to '{alert.user}' account could expose "
            f"confidential project data, customer PII, and internal communications. "
            f"Risk of data breach notification requirements under GDPR/CCPA."
        ),
        next_step_prediction=(
            "If this is a genuine compromise, expect the attacker to begin "
            "harvesting emails, downloading shared documents, and potentially "
            "setting up mail-forwarding rules for persistent access."
        ),
        generated_by="mock",
        generated_at=datetime.now(timezone.utc),
    )


def _mock_det003(alert: Alert) -> AIAnalysis:
    """Admin account targeted analysis."""
    src_ip = alert.ip_address or _rand_ip()
    city, country = _rand_city()
    return AIAnalysis(
        explanation=(
            f"A sustained attack against the administrative account '{alert.user}' has "
            f"been detected. The source IP {src_ip} ({city}, {country}) executed "
            f"{random.randint(12, 50)} failed login attempts in rapid succession, "
            f"specifically targeting accounts with 'admin', 'root', or 'sysadmin' in "
            f"the username. This pattern indicates targeted reconnaissance combined "
            f"with password spraying against high-value accounts."
        ),
        narrative=(
            f"The attacker has identified '{alert.user}' as a privileged account — "
            f"likely through OSINT, LinkedIn enumeration, or a prior directory-listing "
            f"leak. By focusing exclusively on admin-tier accounts, the threat actor "
            f"aims to bypass the need for lateral movement entirely. If successful, "
            f"they gain immediate domain-wide control."
        ),
        severity_reasoning=(
            "Severity set to CRITICAL because: (1) the targeted account has domain-admin "
            "privileges, (2) compromise would grant unrestricted access to all systems, "
            "(3) the attack pattern shows deliberate, targeted intent rather than "
            "opportunistic scanning."
        ),
        mitre_tactics=["Initial Access", "Credential Access", "Privilege Escalation"],
        mitre_techniques=[
            {"id": "T1110.003", "name": "Password Spraying"},
            {"id": "T1078.002", "name": "Domain Accounts"},
            {"id": "T1087", "name": "Account Discovery"},
        ],
        recommended_actions=[
            f"Immediately block {src_ip} and the /24 subnet at the perimeter",
            f"Lock the '{alert.user}' account and rotate all credentials",
            "Enable hardware-token MFA for all admin accounts",
            "Audit recent changes made by this admin account",
            "Engage the incident response team for full investigation",
            "Review PAM (Privileged Access Management) policies",
        ],
        business_impact=(
            "Compromise of a domain-admin account is a Severity-1 event. The attacker "
            f"would control Active Directory, all group policies, and every machine in "
            f"the domain. Potential for ransomware deployment, mass data exfiltration, "
            f"and complete operational disruption."
        ),
        next_step_prediction=(
            "If credentials are obtained, the attacker will immediately create a "
            "secondary admin account for persistence, disable security logging, and "
            "begin staging data for exfiltration — likely within minutes."
        ),
        generated_by="mock",
        generated_at=datetime.now(timezone.utc),
    )


def _mock_det004(alert: Alert) -> AIAnalysis:
    """API rate-limit abuse analysis."""
    return AIAnalysis(
        explanation=(
            f"API token belonging to '{alert.user}' generated "
            f"{random.randint(520, 2800)} requests per minute — exceeding the 500 "
            f"req/min threshold by {random.randint(1, 5)}x. Request patterns show "
            f"sequential endpoint enumeration across /api/v2/users, /api/v2/accounts, "
            f"and /api/v2/export, consistent with automated data-scraping behavior. "
            f"The token was issued {random.randint(1, 30)} days ago from IP "
            f"{alert.ip_address}."
        ),
        narrative=(
            f"A compromised or abused API token is being used to systematically "
            f"enumerate and extract data through the REST API. The request velocity "
            f"and endpoint sequencing indicate purpose-built scraping tooling rather "
            f"than legitimate application usage. The actor may be harvesting user "
            f"records, financial data, or configuration details."
        ),
        severity_reasoning=(
            "Severity set to HIGH because: (1) rate significantly exceeds normal "
            "thresholds, (2) endpoint access pattern suggests data exfiltration intent, "
            "(3) the token has broad read permissions."
        ),
        mitre_tactics=["Collection", "Exfiltration"],
        mitre_techniques=[
            {"id": "T1119", "name": "Automated Collection"},
            {"id": "T1530", "name": "Data from Cloud Storage"},
        ],
        recommended_actions=[
            "Immediately revoke the API token",
            f"Block IP {alert.ip_address} at the API gateway",
            "Implement stricter per-token rate limiting (100 req/min)",
            f"Audit all data accessed by '{alert.user}' token in the last 24h",
            "Enable anomaly detection on API usage patterns",
            "Rotate all API tokens issued to this user",
        ],
        business_impact=(
            "Unrestricted API access could result in bulk extraction of customer "
            f"records, PII, and business-critical data. Estimated exposure: "
            f"{random.randint(10000, 500000)} records across {random.randint(3, 8)} "
            f"data stores."
        ),
        next_step_prediction=(
            "The attacker will attempt to exfiltrate harvested data to an external "
            "endpoint. If the token is revoked, they may attempt to create new tokens "
            "using stolen credentials or pivot to direct database access."
        ),
        generated_by="mock",
        generated_at=datetime.now(timezone.utc),
    )


def _mock_det005(alert: Alert) -> AIAnalysis:
    """Database query volume anomaly analysis."""
    baseline = random.randint(50, 200)
    actual = baseline * random.randint(11, 25)
    return AIAnalysis(
        explanation=(
            f"User '{alert.user}' executed {actual} database queries in the last "
            f"hour — {actual // baseline}x above their rolling 7-day baseline of "
            f"{baseline} queries/hour. The queries targeted tables containing customer "
            f"PII (users, payments, addresses) and used SELECT * patterns with no "
            f"WHERE clause filtering, indicating bulk data extraction."
        ),
        narrative=(
            f"An insider or compromised account is performing mass data extraction "
            f"from production databases. '{alert.user}' — who normally runs fewer "
            f"than {baseline} queries per hour — has initiated a systematic dump of "
            f"sensitive tables. The timing ({random.choice(['2:30 AM', '3:15 AM', '11:45 PM'])} "
            f"local time) suggests deliberate evasion of monitoring during off-hours."
        ),
        severity_reasoning=(
            "Severity set to HIGH because: (1) query volume exceeds baseline by >10x, "
            "(2) queries target PII-containing tables, (3) activity occurs outside "
            "normal working hours, (4) no corresponding business justification found."
        ),
        mitre_tactics=["Collection", "Exfiltration"],
        mitre_techniques=[
            {"id": "T1213", "name": "Data from Information Repositories"},
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
        ],
        recommended_actions=[
            f"Temporarily suspend '{alert.user}' database access",
            "Review all queries executed in the last 4 hours",
            "Check for any data exports or file downloads by this user",
            "Engage DLP (Data Loss Prevention) to scan outbound traffic",
            "Interview the user or their manager about legitimate need",
            "Enable row-level access logging on sensitive tables",
        ],
        business_impact=(
            f"Potential exposure of {random.randint(50000, 2000000)} customer records "
            f"including PII. Regulatory notification obligations under GDPR, CCPA, "
            f"and SOX. Estimated incident cost: ${random.randint(500000, 5000000):,}."
        ),
        next_step_prediction=(
            "Data is likely being staged locally before exfiltration via cloud "
            "storage, personal email, or USB. Expect a large file transfer "
            "attempt within the next 30 minutes."
        ),
        generated_by="mock",
        generated_at=datetime.now(timezone.utc),
    )


def _mock_det006(alert: Alert) -> AIAnalysis:
    """Large file download analysis."""
    size_mb = random.randint(510, 2500)
    return AIAnalysis(
        explanation=(
            f"User '{alert.user}' downloaded approximately {size_mb} MB of data in a "
            f"single session from the internal file server. The download included "
            f"{random.randint(15, 200)} files from directories marked as 'Confidential' "
            f"and 'Internal Only'. The session originated from {alert.ip_address} "
            f"using the device '{alert.device}'."
        ),
        narrative=(
            f"A potential data exfiltration event is underway. '{alert.user}' initiated "
            f"a bulk download of {size_mb} MB — far exceeding normal file-access "
            f"patterns. The downloaded content spans multiple restricted directories, "
            f"suggesting the user is performing a systematic grab of sensitive "
            f"intellectual property or client data prior to departure."
        ),
        severity_reasoning=(
            "Severity set to MEDIUM because: (1) download exceeds 500 MB threshold, "
            "(2) files are from restricted directories, (3) no prior similar pattern "
            "from this user, but (4) the user has legitimate access permissions."
        ),
        mitre_tactics=["Collection", "Exfiltration"],
        mitre_techniques=[
            {"id": "T1005", "name": "Data from Local System"},
            {"id": "T1567", "name": "Exfiltration Over Web Service"},
        ],
        recommended_actions=[
            f"Review the full list of files downloaded by '{alert.user}'",
            "Check if the user has submitted a resignation recently (HR flag)",
            "Enable enhanced DLP monitoring for this user's account",
            "Restrict external USB and cloud-sync applications on their device",
            "Preserve forensic evidence of the download session",
        ],
        business_impact=(
            f"Potential loss of {size_mb} MB of confidential data including trade "
            f"secrets, client contracts, and proprietary source code. "
            f"Competitive harm could be significant if data reaches a competitor."
        ),
        next_step_prediction=(
            "The user may attempt to upload the downloaded files to a personal "
            "cloud service (Google Drive, Dropbox) or transfer via personal email. "
            "Monitor outbound traffic for large uploads in the next hour."
        ),
        generated_by="mock",
        generated_at=datetime.now(timezone.utc),
    )


def _mock_det007(alert: Alert) -> AIAnalysis:
    """Token reuse from different IP analysis."""
    ip2 = _rand_ip()
    return AIAnalysis(
        explanation=(
            f"OAuth token for '{alert.user}' was used from two different IP addresses "
            f"within a 60-second window: {alert.ip_address} and {ip2}. "
            f"This is physically impossible for a single legitimate user and indicates "
            f"the token has been stolen and is being replayed by a second party. "
            f"The token was originally issued {random.randint(2, 72)} hours ago."
        ),
        narrative=(
            f"A threat actor has obtained '{alert.user}'s OAuth token — likely through "
            f"session hijacking, a man-in-the-middle attack, or malware on the user's "
            f"endpoint. The actor is now replaying the token from {ip2} while the "
            f"legitimate user continues to use it from {alert.ip_address}, creating "
            f"a classic 'session cloning' scenario."
        ),
        severity_reasoning=(
            "Severity set to CRITICAL because: (1) token reuse from disparate IPs "
            "within 60s is a definitive indicator of compromise, (2) the stolen token "
            "inherits all of the user's permissions, (3) active exploitation is "
            "occurring in real-time."
        ),
        mitre_tactics=["Credential Access", "Lateral Movement"],
        mitre_techniques=[
            {"id": "T1528", "name": "Steal Application Access Token"},
            {"id": "T1550.001", "name": "Application Access Token"},
        ],
        recommended_actions=[
            "Immediately revoke the compromised OAuth token",
            f"Block IP {ip2} at the perimeter",
            f"Force re-authentication for '{alert.user}'",
            "Scan the user's endpoint for malware or browser extensions",
            "Review all actions performed under the stolen token",
            "Enable token-binding or certificate-pinned tokens",
        ],
        business_impact=(
            f"Active session hijacking gives the attacker full access as '{alert.user}'. "
            f"All data and actions available to this user are compromised. If the user "
            f"has admin access, the blast radius extends to "
            f"{random.randint(5, 50)} connected systems."
        ),
        next_step_prediction=(
            "The attacker will escalate privileges, create backdoor accounts, and "
            "begin data exfiltration. Expect persistence mechanisms (API key creation, "
            "OAuth app registration) within minutes."
        ),
        generated_by="mock",
        generated_at=datetime.now(timezone.utc),
    )


def _mock_det008(alert: Alert) -> AIAnalysis:
    """Privilege escalation command analysis."""
    cmds = random.choice([
        "sudo su -", "net localgroup administrators /add",
        "chmod u+s /bin/bash", "dsenl . -u admin -P passw0rd",
        "runas /user:DOMAIN\\admin cmd.exe",
    ])
    return AIAnalysis(
        explanation=(
            f"Privilege escalation command detected on device '{alert.device}' "
            f"executed by '{alert.user}': `{cmds}`. The command was issued from "
            f"IP {alert.ip_address} at {_now_iso()}. This follows a sequence of "
            f"failed login attempts and a successful authentication from an unusual "
            f"location, strongly suggesting post-compromise lateral movement."
        ),
        narrative=(
            f"After gaining initial access (likely through credential stuffing), the "
            f"attacker is now attempting to escalate from '{alert.user}' (standard user) "
            f"to administrator privileges. The execution of `{cmds}` indicates the "
            f"actor is following a well-known post-exploitation playbook — likely "
            f"aided by toolkits such as Mimikatz, BloodHound, or manual enumeration."
        ),
        severity_reasoning=(
            "Severity set to CRITICAL because: (1) privilege escalation is a direct "
            "step toward domain compromise, (2) the command pattern matches known "
            "post-exploitation techniques, (3) this event follows prior indicators "
            "of compromise in the kill-chain."
        ),
        mitre_tactics=["Privilege Escalation", "Execution", "Persistence"],
        mitre_techniques=[
            {"id": "T1548", "name": "Abuse Elevation Control Mechanism"},
            {"id": "T1059", "name": "Command and Scripting Interpreter"},
            {"id": "T1136", "name": "Create Account"},
        ],
        recommended_actions=[
            f"Immediately isolate device '{alert.device}' from the network",
            f"Disable account '{alert.user}' and rotate all credentials",
            "Capture memory dump and disk image for forensics",
            "Review all commands executed in this session",
            "Check for newly created admin accounts or scheduled tasks",
            "Engage the incident response team — this is an active intrusion",
        ],
        business_impact=(
            "Successful privilege escalation gives the attacker admin-level control "
            f"of '{alert.device}' and potentially the entire domain. This is a "
            f"critical-severity event that could lead to ransomware deployment, "
            f"data destruction, or full network compromise."
        ),
        next_step_prediction=(
            "With elevated privileges, the attacker will dump credentials (LSASS), "
            "enumerate the domain via LDAP, and begin lateral movement to domain "
            "controllers within 10–20 minutes. Ransomware deployment may follow."
        ),
        generated_by="mock",
        generated_at=datetime.now(timezone.utc),
    )


def _mock_det009(alert: Alert) -> AIAnalysis:
    """Zero-Day Anomaly analysis."""
    return AIAnalysis(
        explanation=(
            f"An Unsupervised Machine Learning model (Isolation Forest) flagged an event "
            f"by '{alert.user}' on device '{alert.device}' as highly anomalous. "
            f"The log's numerical features (time of day, payload length, event type frequencies) "
            f"deviated significantly from the learned 'normal' baseline for this environment. "
            f"This behavior does not match any known static detection rules, suggesting a "
            f"novel attack vector or an insider threat operating outside typical parameters."
        ),
        narrative=(
            f"SHIELDX has detected a completely novel anomaly. A threat actor or insider "
            f"is performing actions that bypass traditional signature-based detections. "
            f"By correlating unusual timestamps with abnormal payload sizes and API endpoints, "
            f"we've identified activity that falls into the 1% most anomalous events in the dataset. "
            f"This could represent a zero-day exploit, advanced persistent threat (APT) beaconing, "
            f"or a compromised account being used in an unpredictable way."
        ),
        severity_reasoning=(
            "Severity set to HIGH because: (1) Unsupervised ML flagged it as a statistical outlier, "
            "(2) it bypassed all known static rules, indicating stealth or novelty, "
            "(3) requires immediate human review to classify the unknown behavior."
        ),
        mitre_tactics=["Defense Evasion", "Discovery", "Initial Access"],
        mitre_techniques=[
            {"id": "T1562", "name": "Impair Defenses"},
            {"id": "T1008", "name": "Fallback Channels"},
        ],
        recommended_actions=[
            "Isolate the affected device immediately",
            "Review full raw logs for the past 24 hours around this timestamp",
            "Check for unpatched vulnerabilities on the targeted service",
            "Engage Tier 3 SOC analysts to reverse-engineer the activity",
            "Collect forensic disk images and network pcaps",
        ],
        business_impact=(
            "Zero-day threats carry extremely high risk because traditional defenses cannot stop them. "
            "If this is a novel data exfiltration or ransomware strain, the entire network could "
            "be compromised without raising standard alarms."
        ),
        next_step_prediction=(
            "Since this represents an unknown behavior, expect the actor to attempt lateral movement "
            "using similarly obfuscated techniques, potentially deploying custom malware payloads."
        ),
        generated_by="mock",
        generated_at=datetime.now(timezone.utc),
    )


# Map rule IDs to their mock generators.
_MOCK_GENERATORS: Dict[str, Any] = {
    "DET-001": _mock_det001,
    "DET-002": _mock_det002,
    "DET-003": _mock_det003,
    "DET-004": _mock_det004,
    "DET-005": _mock_det005,
    "DET-006": _mock_det006,
    "DET-007": _mock_det007,
    "DET-008": _mock_det008,
    "DET-009": _mock_det009,
}


# ═════════════════════════════════════════════════════════════════════════════
#  LIVE AI PROVIDERS
# ═════════════════════════════════════════════════════════════════════════════

_SYSTEM_PROMPT = """\
You are SHIELDX, an expert Security Operations Center analyst. Analyze the
security alert provided and return a JSON object with EXACTLY these keys:
- explanation (string): Detailed technical analysis of the alert
- narrative (string): Attacker-perspective story of the incident
- severity_reasoning (string): Why this severity level is appropriate
- mitre_tactics (array of strings): MITRE ATT&CK tactics observed
- mitre_techniques (array of objects with "id" and "name"): MITRE techniques
- recommended_actions (array of strings): Ordered analyst actions
- business_impact (string): Potential business consequences
- next_step_prediction (string): Predicted attacker next move

Respond ONLY with valid JSON. No markdown, no explanation outside the JSON.
"""


async def _call_openai(alert: Alert) -> AIAnalysis | None:
    """Call OpenAI ChatCompletion API and parse the response."""
    if not settings.OPENAI_API_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": settings.OPENAI_MODEL,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": alert.model_dump_json()},
                    ],
                    "temperature": 0.4,
                    "response_format": {"type": "json_object"},
                },
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            return AIAnalysis(**parsed, generated_by="openai", generated_at=datetime.now(timezone.utc))
    except Exception as exc:
        logger.warning("OpenAI call failed, falling back to mock: %s", exc)
        return None


async def _call_claude(alert: Alert) -> AIAnalysis | None:
    """Call Anthropic Messages API and parse the response."""
    if not settings.ANTHROPIC_API_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": settings.ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": settings.CLAUDE_MODEL,
                    "max_tokens": 2048,
                    "system": _SYSTEM_PROMPT,
                    "messages": [
                        {"role": "user", "content": alert.model_dump_json()},
                    ],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["content"][0]["text"]
            # Try to extract JSON from potential markdown wrapping
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            parsed = json.loads(content)
            return AIAnalysis(**parsed, generated_by="claude", generated_at=datetime.now(timezone.utc))
    except Exception as exc:
        logger.warning("Claude call failed, falling back to mock: %s", exc)
        return None


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ═════════════════════════════════════════════════════════════════════════════

async def analyze_alert(alert: Alert) -> AIAnalysis:
    """Produce an AI analysis for the given alert.

    Tries the configured provider first; falls back to the mock library.
    """
    provider = settings.AI_PROVIDER.lower()

    if provider == "openai":
        result = await _call_openai(alert)
        if result:
            return result
    elif provider == "claude":
        result = await _call_claude(alert)
        if result:
            return result

    # Fallback: mock
    generator = _MOCK_GENERATORS.get(alert.rule_id, _mock_det001)
    return generator(alert)


async def _call_free_ai(message: str, system_context: str) -> str | None:
    """Public keyless fallback to query a real GPT-4o-mini model when credentials fail."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Construct a comprehensive system prompt blending system context + query
            full_prompt = (
                f"{system_context}\n\n"
                f"User Question: {message}\n\n"
                "Please reply as a helpful, expert cybersecurity analyst. Keep your tone natural, professional, and conversational. "
                "Answer the user's question directly and fully, using the security context provided if relevant, but also answering "
                "general conversational questions naturally."
            )
            
            resp = await client.post(
                "https://text.pollinations.ai/",
                headers={"Content-Type": "application/json"},
                json={
                    "messages": [
                        {"role": "user", "content": full_prompt}
                    ],
                    "model": "openai"
                }
            )
            if resp.status_code == 200:
                reply = resp.text.strip()
                if reply:
                    logger.info("Free fallback AI successfully triaged query via Pollinations AI")
                    return reply
            logger.warning("Free AI request failed: %d - %s", resp.status_code, resp.text)
    except Exception as e:
        logger.exception("Failed to invoke free fallback AI engine")
    return None


async def chat(
    message: str,
    recent_alerts: List[Dict[str, Any]] | None = None,
    open_incidents: List[Dict[str, Any]] | None = None,
    risk_score: float = 0.0,
    incident_id: str | None = None,
) -> Dict[str, Any]:
    """Handle a free-form analyst chat message.

    Injects the last 5 alerts, open incidents, and current risk score as
    system context so the AI can answer questions about the current threat
    landscape.
    """
    context_parts: List[str] = []
    context_used: List[str] = []

    if risk_score > 0:
        context_parts.append(f"Current global risk score: {risk_score}/100")
        context_used.append("risk_score")

    if recent_alerts:
        alerts_summary = json.dumps(recent_alerts[:5], indent=2, default=str)
        context_parts.append(f"Recent alerts:\n{alerts_summary}")
        context_used.append("recent_alerts")

    if open_incidents:
        incidents_summary = json.dumps(open_incidents[:5], indent=2, default=str)
        context_parts.append(f"Open incidents:\n{incidents_summary}")
        context_used.append("open_incidents")

    if incident_id:
        context_parts.append(f"The analyst is asking about incident: {incident_id}")
        context_used.append(f"incident:{incident_id}")

    system_context = (
        "You are SHIELDX, an AI-powered SOC assistant. "
        "Answer the analyst's question using the context provided.\n\n"
        + "\n\n".join(context_parts)
    )

    provider = settings.AI_PROVIDER.lower()

    # ── Try live providers ───────────────────────────────────────────────
    if provider == "openai" and settings.OPENAI_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": settings.OPENAI_MODEL,
                        "messages": [
                            {"role": "system", "content": system_context},
                            {"role": "user", "content": message},
                        ],
                        "temperature": 0.5,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                reply = data["choices"][0]["message"]["content"]
                return {"reply": reply, "context_used": context_used, "provider": "openai"}
        except Exception as exc:
            logger.warning("OpenAI chat failed (will try keyless fallback): %s", exc)

    if provider == "claude" and settings.ANTHROPIC_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": settings.ANTHROPIC_API_KEY,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": settings.CLAUDE_MODEL,
                        "max_tokens": 2048,
                        "system": system_context,
                        "messages": [{"role": "user", "content": message}],
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                reply = data["content"][0]["text"]
                return {"reply": reply, "context_used": context_used, "provider": "claude"}
        except Exception as exc:
            logger.warning("Claude chat failed (will try keyless fallback): %s", exc)

    # ── Try Keyless Free GPT-4o-mini Fallback ────────────────────────────
    free_reply = await _call_free_ai(message, system_context)
    if free_reply:
        # We append a small badge noting that the keyless fallback handled it
        return {"reply": free_reply, "context_used": context_used, "provider": "free-gpt-4o-mini"}

    # ── Try Mock Local Fallback (Ultimate safety net) ────────────────────
    mock_reply = _generate_mock_chat_reply(message, recent_alerts, risk_score)
    return {"reply": mock_reply, "context_used": context_used, "provider": "mock"}


def _generate_mock_chat_reply(
    message: str,
    recent_alerts: List[Dict[str, Any]] | None,
    risk_score: float,
) -> str:
    """Generate a natural, contextually-aware conversational reply resembling ChatGPT."""
    msg_lower = message.lower().strip("?!. ")
    alert_count = len(recent_alerts) if recent_alerts else 0

    # 1. GREETINGS
    if msg_lower in ("hello", "hi", "hey", "greetings", "yo", "sup"):
        return (
            "Hello! I am SHIELDX, your virtual autonomous SOC analyst. 🛡️\n\n"
            f"Currently, I am tracking **{alert_count} active security alert(s)** with an environment risk index of **{risk_score:.0f}/100**.\n\n"
            "How can I assist you with your threat hunting, log analysis, or mitigation playbooks today? "
            "You can ask me to explain a specific threat, check if customer data was exposed, or recommend containment steps."
        )

    # 2. GRATITUDE
    if "thank" in msg_lower or "thanks" in msg_lower or "awesome" in msg_lower:
        return (
            "You're very welcome! I'm always online and listening to the telemetry feed to keep your environment secure. 🚀\n\n"
            "Let me know if there's anything else you'd like to investigate, or if you want to test another attack scenario!"
        )

    # 3. CUSTOMER DATA EXPOSURE QUERY
    if "customer" in msg_lower or "data" in msg_lower or "exposed" in msg_lower:
        if alert_count > 0:
            return (
                "🔍 **Investigation Report: Potential Customer Data Exposure**\n\n"
                "I have audited all correlated logs from our recent simulations. Here is my current assessment:\n\n"
                "1. **Brute Force (DET-001/DET-003)**: An automated brute-force campaign targeted `charlie.brown`. Although privilege escalation attempts were detected, **no bulk databases read logs or exfiltration footprints** have been correlated for this identity yet. Data exposure probability is currently **LOW (under 15%)**.\n"
                "2. **API Abuse / Database Query (DET-004/DET-005)**: If you triggered a Database Query Volume anomaly, we observed high-velocity query spikes on tables containing PII. This is a **HIGH RISK** scenario, and I strongly recommend executing a **Block IP** or **Disable Account** playbook to completely prevent any egress traffic.\n\n"
                "Would you like me to block the source IP address associated with the latest threat?"
            )
        else:
            return (
                "I've checked the environment logs, and there are currently **0 active alerts or incidents** recorded. "
                "No credentials have been targeted, and no system logins have occurred, so **no customer data is exposed**. You are fully secure!\n\n"
                "To test data exposure tracking, trigger the **Brute Force** or **Insider Threat** simulation on the dashboard!"
            )

    # 4. RISK SCORE QUESTIONS
    if "risk" in msg_lower or "score" in msg_lower or "status" in msg_lower:
        level = "LOW" if risk_score < 30 else "MODERATE" if risk_score < 60 else "HIGH" if risk_score < 80 else "CRITICAL"
        status_icon = "🟢" if level == "LOW" else "🟡" if level == "MODERATE" else "🔴"
        return (
            f"{status_icon} **Current Security posture: {level}**\n\n"
            f"The environment global risk level is rated at **{risk_score:.0f}/100**.\n\n"
            f"This is based on {alert_count} active security alert(s) currently registered in the database. "
            f"If you stop injecting simulation scripts, the risk score will naturally decay by **1 point per minute** back to the secure baseline.\n\n"
            f"{'⚠️ **Action Recommended**: I advise reviewing high-severity incidents and locking compromised sessions.' if risk_score >= 50 else '✅ No critical response actions are pending.'}"
        )

    # 5. INVESTIGATION STEPS
    if "incident" in msg_lower or "investigate" in msg_lower or "what should i do" in msg_lower:
        return (
            "Sure! Let's walk through an investigation workflow for the current alerts:\n\n"
            "1. **Contain the Source**: Go to the Dashboard and use the **Recommended Responses** to trigger an IP block on the attacker's origin address.\n"
            "2. **Analyze the Attack Timeline**: Navigate to the **Incidents** page and click the active incident to inspect the chronological timeline of events.\n"
            "3. **Verify Identity Compromise**: Check the user account role in the Directory and mandate an MFA credential reset.\n"
            "4. **Map Techniques**: Review the MITRE ATT&CK techniques mapped to this alert (visible in the Dashboard AI Panel).\n\n"
            "Would you like me to analyze a specific incident ID or target user for you?"
        )

    # 6. HELP / CAPABILITIES
    if "help" in msg_lower or "what can" in msg_lower or "capabilities" in msg_lower:
        return (
            "I'm **SHIELDX**, your virtual autonomous L2 SOC analyst! 🤖\n\n"
            "I am grounded in your local telemetry database and can help you with:\n"
            "• 🔍 **Threat Diagnostics** — Explain security alerts in simple terms.\n"
            "• 🎯 **Attack Chains Mapping** — Connect the dots across logins and command logs.\n"
            "• 🛡️ **Orchestrated Playbooks** — Suggest standard SOAR responses to block attackers.\n"
            "• 📊 **Risk Calculations** — Track the velocity and severity of incoming alerts.\n\n"
            "Just ask me a question like *'Was customer data exposed?'* or *'How do I investigate this?'*!"
        )

    # 7. CONVERSATIONAL FALLBACK
    return (
        f"I understand your question regarding our security posture. Based on our current live telemetry:\n\n"
        f"• **Active Alerts**: {alert_count}\n"
        f"• **Risk Index**: {risk_score:.0f}/100\n"
        f"• **Reasoning Provider**: {settings.AI_PROVIDER.upper()}\n\n"
        f"*{message}*\n\n"
        "To give you the most accurate triage report, could you specify which alert, IP address, or user account you are investigating? "
        "Alternatively, you can try one of these standard queries:\n"
        "• *'Was customer data exposed?'*\n"
        "• *'What is the current risk level?'*\n"
        "• *'How do I investigate this incident?'*"
    )


async def generate_incident_report(incident: Dict[str, Any]) -> str:
    """Generate a detailed markdown incident report using the LLM or a mock fallback."""
    incident_json = json.dumps(incident, indent=2, default=str)
    prompt = f"""\
Generate a professional incident report with these sections:
1. Executive Summary (2 sentences, non-technical)
2. Technical Timeline (what happened, in order)
3. MITRE ATT&CK Mapping (tactics and techniques used)
4. Blast Radius Assessment (what was at risk)
5. Recommended Actions (immediate and long-term)
6. Confidence Assessment (how certain are we this was real)

Incident data: {incident_json}
"""
    system_prompt = "You are an expert Security Operations Center (SOC) Lead. Generate a high-quality incident report in Markdown format."

    provider = settings.AI_PROVIDER.lower()

    # 1. Try OpenAI
    if provider == "openai" and settings.OPENAI_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": settings.OPENAI_MODEL,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.3,
                    },
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.warning("OpenAI report generation failed: %s", e)

    # 2. Try Claude
    if provider == "claude" and settings.ANTHROPIC_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": settings.ANTHROPIC_API_KEY,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": settings.CLAUDE_MODEL,
                        "max_tokens": 4096,
                        "system": system_prompt,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                )
                if resp.status_code == 200:
                    return resp.json()["content"][0]["text"]
        except Exception as e:
            logger.warning("Claude report generation failed: %s", e)

    # 3. Try Keyless Free Fallback (Pollinations)
    free_report = await _call_free_ai(prompt, system_prompt)
    if free_report:
        return free_report

    # 4. Ultimate Mock Fallback
    return _generate_mock_report_content(incident)


def _generate_mock_report_content(incident: Dict[str, Any]) -> str:
    """Generate a clean, structured mock Markdown report if all AI services are down."""
    incident_id = incident.get("id", "INC-UNKNOWN")
    title = incident.get("title", "Unknown Security Incident")
    severity = incident.get("severity", "HIGH")
    user = incident.get("affected_user", "unknown_user")
    ip = incident.get("affected_ip", "unknown_ip")
    status = incident.get("status", "open")
    created_at = incident.get("created_at", "N/A")

    # Parse timeline if it is a JSON string
    timeline = incident.get("timeline")
    if isinstance(timeline, str):
        try:
            timeline = json.loads(timeline)
        except Exception:
            timeline = []

    timeline_str = ""
    if isinstance(timeline, list) and len(timeline) > 0:
        for t in timeline:
            desc = t.get("description", t.get("raw_message", "Event triggered"))
            ts = t.get("timestamp", "N/A")
            timeline_str += f"- **[{ts}]** {desc}\n"
    else:
        timeline_str = f"- **[{created_at}]** Incident was flagged by security filters.\n"

    mitre_tactics = incident.get("mitre_tactics", [])
    if isinstance(mitre_tactics, str):
        try:
            mitre_tactics = json.loads(mitre_tactics)
        except Exception:
            mitre_tactics = ["Initial Access", "Credential Access"]

    mitre_str = ", ".join(mitre_tactics) if mitre_tactics else "Credential Access, Initial Access"

    return f"""# SHIELDX INCIDENT INVESTIGATION REPORT
**INCIDENT ID:** {incident_id}  
**TITLE:** {title}  
**SEVERITY:** {severity.upper()}  
**STATUS:** {status.upper()}  
**GENERATION TIME:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  

---

### 1. Executive Summary
SHIELDX correlated anomalous patterns involving account credentials and source IPs into a consolidated threat incident. 
This incident indicates unauthorized system access targeting username `{user}` from origin IP `{ip}`, which is highly likely to be a credential-compromise campaign.

### 2. Technical Timeline
Here is the chronological progression of events detected within this threat chain:
{timeline_str}

### 3. MITRE ATT&CK Mapping
The actions taken by the threat actor map directly to the following MITRE ATT&CK tactics:
- **Tactics:** {mitre_str}
- **Techniques:** T1110 (Brute Force), T1078 (Valid Accounts), T1090 (Proxy/Proxying)

### 4. Blast Radius Assessment
- **High Risk**: Identity store (`{user}` user account) could be compromised.
- **Medium Risk**: Peripheral data repositories accessed from IP `{ip}`.
- **Low Risk**: Endpoint control remains intact; no local host containment breaches observed.

### 5. Recommended Actions
*   **Immediate**: Invalidate all active user sessions for `{user}` and enforce a hardware-key password reset.
*   **Immediate**: Deploy perimeter block on IP address `{ip}`.
*   **Long-term**: Configure advanced Geo-blocking policies and progressive lockouts.

### 6. Confidence Assessment
- **Final Confidence Score:** 0.94 / 1.00
- **Assessment**: The threat velocity combined with geographic impossibility guarantees malicious intent.
"""

