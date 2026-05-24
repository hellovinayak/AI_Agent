import React, { useState, useEffect } from 'react';
import './TriageScoreCard.css';

export default function TriageScoreCard({ triage }: { triage: any }) {
  const [timeLeft, setTimeLeft] = useState('');

  useEffect(() => {
    if (!triage || !triage.ack_deadline) return;

    const tick = () => {
      const deadline = new Date(triage.ack_deadline).getTime();
      const diff = deadline - Date.now();
      if (diff <= 0) {
        setTimeLeft('SLA BREACHED');
        return;
      }
      const m = Math.floor(diff / 60000);
      const s = Math.floor((diff % 60000) / 1000);
      setTimeLeft(`${m}m ${s}s`);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [triage?.ack_deadline]);

  if (!triage || !triage.priority) return null;

  const priorityColor = {
    'P1_CRITICAL': '#ff3b3b',
    'P2_HIGH':     '#ff8c00',
    'P3_MEDIUM':   '#ffd60a',
    'P4_LOW':      '#4da6ff'
  }[triage.priority as string] || '#888';

  const isSlaBreached = timeLeft === 'SLA BREACHED';

  return (
    <div className="triage-card" style={{
      borderLeft: `3px solid ${priorityColor}`
    }}>
      <div className="triage-header">
        <div className="priority-badge" style={{
          background: `${priorityColor}22`,
          color: priorityColor,
          border: `1px solid ${priorityColor}44`
        }}>
          {triage.priority.replace('_', ' ')}
        </div>
        <div className="triage-score">
          {Math.round(triage.triage_score)}
          <span className="score-label">/100</span>
        </div>
      </div>

      {/* SLA countdown */}
      <div className={`sla-countdown ${isSlaBreached ? 'breached' : ''}`}
        style={{ color: isSlaBreached ? '#ff3b3b' :
                 timeLeft.startsWith('0m') ? '#ff8c00' : '#e8eaf0' }}>
        <span className="sla-label">ACK DEADLINE</span>
        <span className="sla-timer">{timeLeft}</span>
      </div>

      {/* Score breakdown */}
      <div className="score-breakdown">
        {Object.entries(triage.score_breakdown || {}).map(([k, v]) => (
          <div key={k} className="breakdown-row">
            <span className="breakdown-key">
              {k.replace(/_/g, ' ')}
            </span>
            <div className="breakdown-bar">
              <div className="breakdown-fill"
                style={{ width: `${((v as number) / 40) * 100}%`,
                         background: priorityColor }} />
            </div>
            <span className="breakdown-val">{v as number}</span>
          </div>
        ))}
      </div>

      {/* Auto actions triggered */}
      {triage.auto_actions_triggered?.length > 0 && (
        <div className="auto-actions">
          <div className="auto-label">AUTO-TRIGGERED</div>
          {triage.auto_actions_triggered.map((action: string) => (
            <div key={action} className="auto-action">
              ⚡ {action.replace(/_/g, ' ')}
            </div>
          ))}
        </div>
      )}

      {/* Escalation path */}
      <div className="escalation-path">
        {triage.escalation_path?.map((step: string, i: number) => (
          <div key={i} className="escalation-step">
            <span className="step-num">{i + 1}</span>
            <span className="step-text">{step}</span>
          </div>
        ))}
      </div>

      <div className="analyst-tier">
        Recommended: <strong>{triage.recommended_analyst_tier} Analyst</strong>
      </div>
    </div>
  );
}
