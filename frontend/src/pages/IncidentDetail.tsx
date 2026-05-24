import React, { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
// @ts-ignore
import html2pdf from 'html2pdf.js';
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
  Sparkles,
  FileText,
  Download,
} from 'lucide-react';
import toast from 'react-hot-toast';

import { api } from '../services/api';
import { Incident, Severity, ResponseAction } from '../types';
import { ThreatGraph } from '../components/ThreatGraph';
import TriageScoreCard from '../components/TriageScoreCard';

export function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [incident, setIncident] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(true);
  const [acting, setActing] = useState<string | null>(null);
  const [resolving, setResolving] = useState(false);
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [reportContent, setReportContent] = useState<string | null>(null);

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
  const handleGenerateReport = async () => {
    if (!incident) return;
    setGeneratingReport(true);
    const toastId = toast.loading('Generating AI incident report...');
    try {
      const res = await api.generateIncidentReport(incident.id);
      setReportContent(res.report);
      toast.success('AI Incident Report generated successfully!', { id: toastId });

      // We no longer download automatically; user can preview and download as PDF
    } catch (err: any) {
      toast.error(`Report generation failed: ${err.message || err}`, { id: toastId });
    } finally {
      setGeneratingReport(false);
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

  const sevColor = severityColors[incident.severity?.toLowerCase()] || '#6b7280';

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
                statusColors[incident.status?.toLowerCase()] || 'text-slate-400 border-slate-700 bg-slate-800'
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

        {/* Action controls (Resolve & Generate Report) */}
        <div className="flex flex-wrap items-center gap-3 z-10">
          <button
            onClick={handleGenerateReport}
            disabled={generatingReport}
            className="flex items-center space-x-2 px-5 py-3 text-xs font-bold text-indigo-400 bg-indigo-500/10 border border-indigo-500/20 hover:bg-indigo-500/20 rounded-xl transition-all active:scale-95 disabled:opacity-50"
          >
            <Sparkles className="h-4 w-4" />
            <span>{generatingReport ? 'Generating...' : 'Generate Report'}</span>
          </button>

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
              className="flex items-center space-x-2 px-5 py-3 text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 hover:bg-emerald-500/20 rounded-xl transition-all active:scale-95"
            >
              <CheckCircle className="h-4 w-4" />
              <span>Mark as Resolved</span>
            </button>
          )}
        </div>
      </div>

      {incident.triage_data && (
        <TriageScoreCard triage={incident.triage_data} />
      )}

      {/* Threat Timeline progression bar */}
      <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex items-center space-x-2 border-b border-slate-800/60 pb-3">
          <Clock className="h-4 w-4 text-indigo-400" />
          <h3 className="font-bold text-slate-200 text-sm">Attack Killchain Progression</h3>
        </div>

        <div className="flex flex-col md:flex-row items-center justify-between gap-4 overflow-x-auto py-4 scrollbar-thin">
          {/* Node 1: Initial Threat Telemetry */}
          <div className="flex flex-col items-center text-center max-w-[200px] relative">
            <div className="h-10 w-10 rounded-full bg-rose-500/20 border border-rose-500/50 flex items-center justify-center text-rose-400 font-bold text-xs shadow-lg shadow-rose-950/40">
              1
            </div>
            <p className="text-xs font-bold text-slate-200 mt-2">First Alert Fired</p>
            <p className="text-[10px] text-slate-500 font-mono mt-0.5">Telemetry Ingested</p>
          </div>

          <div className="hidden md:block flex-1 h-[2px] bg-slate-800 min-w-[50px] relative -top-3">
            <div className="absolute top-0 left-0 h-full bg-indigo-500 animate-pulse w-full"></div>
          </div>

          {/* Node 2: AI Risk Correlation */}
          <div className="flex flex-col items-center text-center max-w-[200px]">
            <div className="h-10 w-10 rounded-full bg-indigo-500/20 border border-indigo-500/50 flex items-center justify-center text-indigo-400 font-bold text-xs shadow-lg shadow-indigo-950/40">
              2
            </div>
            <p className="text-xs font-bold text-slate-200 mt-2">AI Core Grouping</p>
            <p className="text-[10px] text-slate-500 font-mono mt-0.5">Incident Created</p>
          </div>

          <div className="hidden md:block flex-1 h-[2px] bg-slate-800 min-w-[50px] relative -top-3">
            {incident.response_actions_taken && incident.response_actions_taken.length > 0 && (
              <div className="absolute top-0 left-0 h-full bg-emerald-500 w-full"></div>
            )}
          </div>

          {/* Node 3: SOAR Mitigation */}
          <div className="flex flex-col items-center text-center max-w-[200px]">
            <div className={`h-10 w-10 rounded-full flex items-center justify-center font-bold text-xs shadow-lg ${
              incident.response_actions_taken && incident.response_actions_taken.length > 0
                ? 'bg-emerald-500/20 border border-emerald-500/50 text-emerald-400 shadow-emerald-950/40'
                : 'bg-slate-800/40 border border-slate-700/50 text-slate-500'
            }`}>
              3
            </div>
            <p className="text-xs font-bold text-slate-200 mt-2">SOAR Mitigation</p>
            <p className="text-[10px] text-slate-500 font-mono mt-0.5">
              {incident.response_actions_taken && incident.response_actions_taken.length > 0
                ? `${incident.response_actions_taken.length} Action(s) Taken`
                : 'Actions Pending'}
            </p>
          </div>

          <div className="hidden md:block flex-1 h-[2px] bg-slate-800 min-w-[50px] relative -top-3">
            {incident.status === 'resolved' && (
              <div className="absolute top-0 left-0 h-full bg-emerald-500 w-full"></div>
            )}
          </div>

          {/* Node 4: Resolution */}
          <div className="flex flex-col items-center text-center max-w-[200px]">
            <div className={`h-10 w-10 rounded-full flex items-center justify-center font-bold text-xs shadow-lg ${
              incident.status === 'resolved'
                ? 'bg-emerald-500/20 border border-emerald-500/50 text-emerald-400 shadow-emerald-950/40'
                : 'bg-amber-500/20 border border-amber-500/50 text-amber-400 shadow-amber-950/40'
            }`}>
              4
            </div>
            <p className="text-xs font-bold text-slate-200 mt-2">Triage Resolution</p>
            <p className="text-[10px] text-slate-500 font-mono mt-0.5 uppercase">
              {incident.status}
            </p>
          </div>
        </div>
      </div>

      {/* Threat Graph Visualization */}
      <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex items-center space-x-2.5 border-b border-slate-800/60 pb-4">
          <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <Zap className="h-4 w-4" />
          </span>
          <div>
            <h2 className="font-bold text-slate-200">Interactive Threat Graph & Blast Radius</h2>
            <p className="text-xs text-slate-500 mt-0.5">Causal risk propagation across entity property graph</p>
          </div>
        </div>
        <ThreatGraph incidentId={incident.id} />
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
              const itemSev = (evt.severity || 'low').toLowerCase() as Severity;
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
                      <p className="font-bold text-slate-300 font-mono uppercase">{(act.action_type || 'unknown').replace('_', ' ')}</p>
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

      {/* Report Modal */}
      {reportContent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in select-text">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="p-6 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <FileText className="h-5 w-5 text-indigo-400" />
                <h3 className="font-bold text-slate-200 text-lg">AI Incident Report Preview</h3>
              </div>
              <button
                onClick={() => setReportContent(null)}
                className="text-slate-400 hover:text-slate-200 font-bold text-xs px-3 py-1.5 bg-slate-800 rounded-lg hover:bg-slate-700 transition-colors"
              >
                Close
              </button>
            </div>

            <div id="report-content-to-pdf" className="p-6 overflow-y-auto font-sans text-slate-300 text-sm leading-relaxed whitespace-pre-wrap select-text max-h-[50vh] scrollbar-thin bg-black/20">
              {reportContent}
            </div>

            <div className="p-6 border-t border-slate-800 bg-slate-950/40 flex items-center justify-between gap-4">
              <p className="text-xs text-slate-500 font-mono">
                Report generated via SHIELDX L2 Reasoning Engine
              </p>
              <button
                onClick={() => {
                  const blob = new Blob([reportContent], { type: 'text/markdown' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `SHIELDX_Report_${incident.id}.md`;
                  document.body.appendChild(a);
                  a.click();
                  document.body.removeChild(a);
                  URL.revokeObjectURL(url);
                }}
                className="flex items-center space-x-2 px-4 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-xl transition-all active:scale-95 shadow-lg shadow-indigo-950/40"
              >
                <Download className="h-4 w-4" />
                <span>Download Report (.md)</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
