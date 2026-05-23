import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ChevronLeft,
  Clock,
  ShieldAlert,
  Brain,
  ListFilter,
  User,
  Globe,
  CheckCircle,
  Play,
  RotateCcw,
  Zap,
} from 'lucide-react';
import toast from 'react-hot-toast';

import { api } from '../services/api';
import { Incident, Severity, ResponseAction } from '../types';

export function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [incident, setIncident] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(true);
  const [acting, setActing] = useState<string | null>(null);
  const [resolving, setResolving] = useState(false);
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);

  useEffect(() => {
    async function loadIncident() {
      if (!id) return;
      setLoading(true);
      try {
        const inc = await api.getIncident(id);
        setIncident(inc);
      } catch (err: any) {
        toast.error(`Failed to load incident detail: ${err.message || err}`);
      } finally {
        setLoading(false);
      }
    }
    loadIncident();
  }, [id]);

  const severityColors: Record<Severity | string, string> = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#f59e0b',
    low: '#3b82f6',
  };

  const statusColors: Record<string, string> = {
    open: 'text-rose-400 border-rose-500/20 bg-rose-500/10',
    investigating: 'text-amber-400 border-amber-500/20 bg-amber-500/10',
    resolved: 'text-emerald-400 border-emerald-500/20 bg-emerald-500/10',
  };

  const handleExecuteAction = async (actionType: string) => {
    if (!incident) return;
    setActing(actionType);
    const actToast = toast.loading(`Executing response: ${actionType.replace('_', ' ').toUpperCase()}...`);
    try {
      // Determine target based on action type
      let target = incident.affected_ip;
      if (actionType === 'disable_account' || actionType === 'force_mfa_reset') {
        target = incident.affected_user;
      }

      const action = await api.executeAction(actionType, target, incident.id, undefined);
      
      // Update local state to show action taken
      setIncident((prev) => {
        if (!prev) return null;
        return {
          ...prev,
          response_actions_taken: [action, ...(prev.response_actions_taken || [])],
        };
      });

      toast.success(
        <div>
          <p className="font-bold">Mitigation Executed</p>
          <p className="text-xs text-slate-300">Action: {action.action_type}</p>
          <p className="text-xs text-slate-400">Target: {action.target} ({action.status})</p>
        </div>,
        { id: actToast }
      );
    } catch (err: any) {
      toast.error(`Action failed: ${err.message || err}`, { id: actToast });
    } finally {
      setActing(null);
    }
  };

  if (loading) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="h-10 w-48 bg-slate-900 rounded-xl" />
        <div className="h-32 bg-slate-900 rounded-2xl" />
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 h-96 bg-slate-900 rounded-2xl" />
          <div className="h-96 bg-slate-900 rounded-2xl" />
        </div>
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-12 text-center text-slate-400">
        <ShieldAlert className="h-12 w-12 text-slate-700 mx-auto mb-4" />
        <h3 className="text-lg font-bold text-slate-300">Incident Not Found</h3>
        <button
          onClick={() => navigate('/incidents')}
          className="mt-4 px-4 py-2 bg-indigo-600 text-white rounded-xl text-xs font-bold"
        >
          Back to Incidents List
        </button>
      </div>
    );
  }

  const sevColor = severityColors[incident.severity.toLowerCase()] || '#6b7280';

  return (
    <div className="space-y-6">
      {/* Back Button */}
      <button
        onClick={() => navigate('/incidents')}
        className="flex items-center space-x-1.5 text-xs font-bold text-slate-400 hover:text-slate-200 transition-colors"
      >
        <ChevronLeft className="h-4 w-4" />
        <span>Back to Incidents List</span>
      </button>

      {/* Incident Header Card */}
      <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-xl flex flex-col md:flex-row justify-between items-start md:items-center gap-6 relative overflow-hidden">
        {/* Decorative corner glow */}
        <div
          className="absolute -top-16 -right-16 h-32 w-32 rounded-full opacity-10 blur-2xl"
          style={{ backgroundColor: sevColor }}
        />

        <div className="space-y-3 relative z-10">
          <div className="flex flex-wrap items-center gap-3">
            <span
              className="text-[10px] font-black uppercase tracking-widest px-2.5 py-0.5 rounded border"
              style={{
                color: sevColor,
                borderColor: `${sevColor}40`,
                backgroundColor: `${sevColor}10`,
              }}
            >
              {incident.severity}
            </span>
            <span
              className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${
                statusColors[incident.status.toLowerCase()] || 'text-slate-400 border-slate-700 bg-slate-800'
              }`}
            >
              {incident.status}
            </span>
          </div>
          <h1 className="text-2xl md:text-3xl font-extrabold text-slate-100 tracking-tight leading-tight">
            {incident.title}
          </h1>
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs text-slate-500 font-mono">
            <span className="flex items-center space-x-1.5">
              <Clock className="h-4 w-4" />
              <span>Created {new Date(incident.created_at).toLocaleString()}</span>
            </span>
            <span>ID: {incident.id.toUpperCase()}</span>
          </div>
        </div>

        {/* Action controls (Resolve) */}
        {incident.status !== 'resolved' && (
          <button
            onClick={async () => {
              setResolving(true);
              const toastId = toast.loading('Resolving incident...');
              try {
                // Mock resolving the incident on DB
                await api.executeAction('quarantine_process', incident.affected_ip, incident.id, undefined);
                setIncident((prev) => prev ? { ...prev, status: 'resolved' } : null);
                toast.success('Incident status updated to RESOLVED!', { id: toastId });
              } catch (err: any) {
                toast.error(`Resolution failed: ${err.message || err}`, { id: toastId });
              } finally {
                setResolving(false);
              }
            }}
            disabled={resolving}
            className="flex items-center space-x-2 px-5 py-3 text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 hover:bg-emerald-500/20 rounded-xl transition-all active:scale-95 z-10"
          >
            <CheckCircle className="h-4 w-4" />
            <span>Mark as Resolved</span>
          </button>
        )}
      </div>

      {/* Grid: Correlation Timeline (2/3) & AI Narrative (1/3) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Core Timeline Events (2/3) */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-xl space-y-6">
          <div className="flex items-center space-x-2.5 border-b border-slate-800/60 pb-4">
            <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              <ListFilter className="h-4 w-4" />
            </span>
            <div>
              <h2 className="font-bold text-slate-200">Reconstructed Attack Chain</h2>
              <p className="text-xs text-slate-400">Chronological alert sequence correlated by SOC heuristics</p>
            </div>
          </div>

          {/* Vertical Timeline strip */}
          <div className="relative border-l border-slate-800 pl-6 ml-3 space-y-8">
            {incident.timeline?.map((evt, idx) => {
              const itemSev = evt.severity.toLowerCase() as Severity;
              const dotColor = severityColors[itemSev] || '#6b7280';
              return (
                <div key={idx} className="relative group">
                  {/* Timeline Node marker dot */}
                  <span
                    className="absolute -left-[31px] top-1 h-4.5 w-4.5 rounded-full border-2 border-slate-950 flex items-center justify-center transition-transform group-hover:scale-110 shadow-lg"
                    style={{ backgroundColor: dotColor }}
                  />
                  <div>
                    <span className="text-[10px] font-mono text-slate-500 font-semibold uppercase">
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </span>
                    <h4 className="font-bold text-slate-200 text-sm mt-0.5">{evt.event_type}</h4>
                    <p className="text-xs text-slate-400 mt-1 leading-relaxed">{evt.description}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* AI Narrative Panel (1/3) */}
        <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-xl flex flex-col justify-between">
          <div className="space-y-6">
            <div className="flex items-center space-x-2.5 border-b border-slate-800/60 pb-4">
              <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                <Brain className="h-4 w-4" />
              </span>
              <div>
                <h2 className="font-bold text-slate-200">Incident Narrative</h2>
                <p className="text-xs text-slate-400 font-mono">Autonomous AI correlation description</p>
              </div>
            </div>

            {/* AI Narrative text block */}
            <div className="space-y-4">
              <div>
                <h5 className="text-[10px] font-mono font-bold text-indigo-400 uppercase tracking-widest mb-1">
                  Threat Narrative Summary
                </h5>
                <p className="text-xs text-slate-300 leading-relaxed font-sans font-medium">
                  {incident.ai_narrative || 'AI narrative unavailable for this incident.'}
                </p>
              </div>

              {incident.mitre_tactics && incident.mitre_tactics.length > 0 && (
                <div>
                  <h5 className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-widest mb-1.5">
                    MITRE ATT&CK Tactics
                  </h5>
                  <div className="flex flex-wrap gap-1.5">
                    {incident.mitre_tactics.map((tactic, idx) => (
                      <span
                        key={idx}
                        className="text-[10px] font-mono font-bold px-2 py-0.5 rounded border border-slate-700 bg-slate-800 text-slate-300"
                      >
                        {tactic}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {incident.business_impact && (
                <div className="p-3 bg-red-950/10 border border-red-500/20 rounded-xl">
                  <p className="text-[10px] font-mono font-bold uppercase tracking-widest text-red-400">
                    Business Consequences
                  </p>
                  <p className="text-xs text-slate-300 mt-0.5 leading-relaxed font-sans">
                    {incident.business_impact}
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Core targets display */}
          <div className="border-t border-slate-800/60 pt-4 mt-6 space-y-3 font-mono text-xs">
            <div className="flex items-center space-x-2 text-slate-400">
              <User className="h-4 w-4 text-slate-500" />
              <span>Target Identity: <strong className="text-slate-300 font-bold">{incident.affected_user}</strong></span>
            </div>
            <div className="flex items-center space-x-2 text-slate-400">
              <Globe className="h-4 w-4 text-slate-500" />
              <span>Attacker IP Address: <strong className="text-slate-300 font-bold">{incident.affected_ip}</strong></span>
            </div>
          </div>
        </div>
      </div>

      {/* Response Orchestration Section */}
      <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-xl space-y-6">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center border-b border-slate-800/60 pb-4 gap-4">
          <div className="flex items-center space-x-2.5">
            <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <ShieldAlert className="h-4 w-4" />
            </span>
            <div>
              <h2 className="font-bold text-slate-200">Incident Remediation & Actions</h2>
              <p className="text-xs text-slate-400">Trigger orchestrated playbooks or audit response histories</p>
            </div>
          </div>
        </div>

        {/* Buttons grid & Actions taken history */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Action buttons list */}
          <div className="lg:col-span-2 space-y-4">
            <h4 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-widest">
              Available SOAR Playbooks
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              {[
                { id: 'block_ip', label: 'Block Source IP', target: incident.affected_ip, desc: 'Firewall perimeter ban' },
                { id: 'disable_account', label: 'Disable IAM Account', target: incident.affected_user, desc: 'AD account lock' },
                { id: 'force_mfa_reset', label: 'Force MFA Reset', target: incident.affected_user, desc: 'Reset credentials' },
              ].map((play) => (
                <button
                  key={play.id}
                  onClick={() => handleExecuteAction(play.id)}
                  disabled={incident.status === 'resolved' || acting !== null}
                  className="flex flex-col items-center justify-center p-4 rounded-xl border border-white/5 bg-slate-950/60 hover:bg-slate-900/60 hover:border-slate-800 active:scale-95 hover:scale-[1.01] transition-all disabled:opacity-30 disabled:pointer-events-none text-center"
                >
                  <Zap className="h-4 w-4 text-emerald-400 mb-1" />
                  <span className="text-xs font-bold text-slate-200">{play.label}</span>
                  <span className="text-[10px] text-slate-500 font-mono mt-1 select-none">
                    Target: {play.target}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Action history audits */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80">
            <h4 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-widest mb-4">
              Response Action Audit
            </h4>
            <div className="space-y-3 overflow-y-auto max-h-40 scrollbar-thin">
              {!incident.response_actions_taken || incident.response_actions_taken.length === 0 ? (
                <p className="text-slate-600 text-xs font-semibold text-center py-6 select-none">
                  No mitigation playbooks audited yet.
                </p>
              ) : (
                incident.response_actions_taken.map((act: ResponseAction, idx) => (
                  <div key={idx} className="flex justify-between items-start text-xs border-b border-slate-900 pb-2">
                    <div>
                      <p className="font-bold text-slate-300 font-mono uppercase">{act.action_type.replace('_', ' ')}</p>
                      <p className="text-[10px] text-slate-500 font-mono mt-0.5">{act.target}</p>
                    </div>
                    <span className="text-[10px] font-bold text-emerald-400 uppercase font-mono bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded">
                      {act.status}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
