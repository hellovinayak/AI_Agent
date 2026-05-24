import React from 'react';
import './IOCEnrichmentBadges.css';

export default function IOCEnrichmentBadges({ enrichment }: { enrichment: any }) {
  if (!enrichment) return null;
  const ip = enrichment.source_ip;
  if (!ip) return null;

  return (
    <div className="ioc-badges">
      {ip.is_tor_exit && (
        <span className="ioc-badge critical">
          🧅 TOR EXIT NODE
        </span>
      )}
      {ip.is_known_malicious && (
        <span className="ioc-badge critical">
          ☠ KNOWN MALICIOUS — abuse.ch
        </span>
      )}
      {enrichment.domain?.likely_dga && (
        <span className="ioc-badge high">
          ⚠ DGA DOMAIN — entropy {enrichment.domain.entropy_score}
        </span>
      )}
      {ip.abuse_confidence > 50 && (
        <span className="ioc-badge high">
          ⚡ {ip.abuse_confidence}% abuse confidence
          · {ip.abuse_reports} reports
        </span>
      )}
    </div>
  );
}
