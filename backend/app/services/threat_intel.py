import httpx
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

class ThreatIntelFeed:
    """Checks IPs and domains against open threat intel feeds"""

    FEEDS = {
        'abuse_ch': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
        'emerging_threats': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt'
    }

    def __init__(self):
        self.malicious_ips = set()
        self.last_updated = None
        self._refresh()

    def _refresh(self):
        for name, url in self.FEEDS.items():
            try:
                resp = httpx.get(url, timeout=10.0)
                if resp.status_code == 200:
                    ips = {line.strip() for line in resp.text.splitlines()
                           if line and not line.startswith('#')}
                    self.malicious_ips.update(ips)
                    logger.info(f"Loaded {len(ips)} malicious IPs from {name}")
            except Exception as e:
                logger.warning(f"Failed to load threat intel from {name}: {e}")
        self.last_updated = datetime.now(timezone.utc)

    def check_ip(self, ip: str) -> dict:
        return {
            'is_known_malicious': ip in self.malicious_ips,
            'feed_source': 'abuse.ch + emerging_threats' if ip in self.malicious_ips else None,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None
        }

# Singleton instance
threat_intel = ThreatIntelFeed()
