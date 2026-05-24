import asyncio
import httpx
import hashlib
import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Set, Optional
import os

logger = logging.getLogger(__name__)

class IOCEnrichmentEngine:
    """
    Enriches alerts with threat intelligence from open feeds.
    All feeds used are free and open — no API keys required.
    """

    TOR_EXIT_NODES_URL = 'https://check.torproject.org/torbulkexitlist'
    FEODO_TRACKER_URL  = 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt'
    EMERGING_THREATS_URL = 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt'

    def __init__(self):
        self._tor_exits: Set[str] = set()
        self._known_malicious: Set[str] = set()
        self._cache: Dict[str, Any] = {}
        self._last_refresh: Optional[datetime] = None
        self._refresh_task = None
        
    def start(self):
        if self._refresh_task is None:
            self._refresh_task = asyncio.create_task(self._refresh_feeds())

    async def _refresh_feeds(self):
        """Refresh threat intel feeds every 6 hours"""
        while True:
            await self._load_feeds()
            self._last_refresh = datetime.now(timezone.utc)
            await asyncio.sleep(6 * 3600)

    async def _load_feeds(self):
        async with httpx.AsyncClient(timeout=15.0) as client:
            for url, target in [
                (self.TOR_EXIT_NODES_URL,    self._tor_exits),
                (self.FEODO_TRACKER_URL,     self._known_malicious),
                (self.EMERGING_THREATS_URL,  self._known_malicious)
            ]:
                try:
                    resp = await client.get(url)
                    ips = {
                        line.strip()
                        for line in resp.text.splitlines()
                        if line and not line.startswith('#')
                    }
                    target.update(ips)
                    logger.info(f"Loaded {len(ips)} IPs from {url}")
                except Exception as e:
                    logger.error(f"Feed load failed {url}: {e}")

    async def enrich_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        ioc_results = {}

        # Enrich source IP
        if ip := alert.get('source_ip'):
            ioc_results['source_ip'] = await self._enrich_ip(ip)

        # Enrich destination IP
        if ip := alert.get('destination_ip'):
            ioc_results['destination_ip'] = await self._enrich_ip(ip)

        # Enrich domain if present
        if domain := alert.get('domain'):
            ioc_results['domain'] = await self._enrich_domain(domain)

        if not ioc_results:
            return alert

        alert['ioc_enrichment'] = ioc_results
        alert['ioc_risk_boost'] = self._compute_risk_boost(ioc_results)

        # Auto-boost confidence if IOC matches known bad
        if alert['ioc_risk_boost'] > 0:
            alert['confidence'] = min(alert.get('confidence', 0.5) + alert['ioc_risk_boost'], 1.0)
            alert['ioc_confirmed'] = True

        return alert

    async def _enrich_ip(self, ip: str) -> Dict[str, Any]:
        if ip in self._cache:
            return self._cache[ip]

        result = {
            'ip': ip,
            'is_tor_exit':       ip in self._tor_exits,
            'is_known_malicious': ip in self._known_malicious,
            'is_private':        self._is_private(ip),
            'threat_feeds_matched': [],
            'risk_level': 'unknown',
            'last_checked': datetime.now(timezone.utc).isoformat()
        }

        if ip in self._tor_exits:
            result['threat_feeds_matched'].append('tor_exit_nodes')
        if ip in self._known_malicious:
            result['threat_feeds_matched'].append('feodo_tracker')

        # Try AbuseIPDB if key configured (free tier = 1000/day)
        if abuse_key := self._get_abuse_key():
            result.update(await self._query_abuseipdb(ip, abuse_key))

        result['risk_level'] = (
            'critical' if result['is_known_malicious'] or result['is_tor_exit'] else
            'high'     if result.get('abuse_confidence', 0) > 50 else
            'medium'   if result.get('abuse_confidence', 0) > 20 else
            'low'
        )

        self._cache[ip] = result
        return result

    async def _enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain entropy — high entropy = likely DGA"""
        entropy = self._compute_entropy(domain.split('.')[0])
        return {
            'domain': domain,
            'entropy_score': round(entropy, 3),
            'likely_dga': entropy > 3.5,
            'subdomain_length': len(domain.split('.')[0]),
            'risk_level': 'high' if entropy > 3.5 else 'low'
        }

    def _compute_entropy(self, s: str) -> float:
        import math
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())

    def _compute_risk_boost(self, ioc_results: Dict[str, Any]) -> float:
        boost = 0.0
        for key, result in ioc_results.items():
            if result.get('is_tor_exit'):        boost += 0.25
            if result.get('is_known_malicious'): boost += 0.30
            if result.get('likely_dga'):         boost += 0.20
            if result.get('abuse_confidence', 0) > 75: boost += 0.20
        return min(boost, 0.50)

    def _is_private(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def _get_abuse_key(self) -> Optional[str]:
        return os.getenv('ABUSEIPDB_KEY')

    async def _query_abuseipdb(self, ip: str, key: str) -> Dict[str, Any]:
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    params={'ipAddress': ip, 'maxAgeInDays': 90},
                    headers={'Key': key, 'Accept': 'application/json'},
                    timeout=3.0
                )
                data = resp.json().get('data', {})
                return {
                    'abuse_confidence': data.get('abuseConfidenceScore', 0),
                    'abuse_reports':    data.get('totalReports', 0),
                    'isp':              data.get('isp', 'unknown'),
                    'country':          data.get('countryCode', 'unknown'),
                    'usage_type':       data.get('usageType', 'unknown')
                }
            except Exception:
                return {}

ioc_enrichment_engine = IOCEnrichmentEngine()
