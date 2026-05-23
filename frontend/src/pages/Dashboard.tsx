import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  ShieldCheck,
  Activity,
  Terminal,
  Clock,
  ChevronDown,
  ChevronUp,
  Brain,
  ShieldAlert,
  User,
  Globe,
  Monitor,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts';
import toast from 'react-hot-toast';

import { useStore } from '../stores/useStore';
import { api } from '../services/api';
import { SimulatorPanel } from '../components/SimulatorPanel';
import { Alert, Incident, Severity } from '../types';

export function Dashboard() {
  const navigate = useNavigate();
  const logsEndRef = useRef<HTMLDivElement>(null);
  
  const {
    alerts,
    incidents,
    logs,
    riskScore,
    fpSuppressed,
    connectionStatus,
    setAlerts,
    setIncidents,
  } = useStore();

  const [aiExpanded, setAiExpanded] = useState(true);
  const [selectedAlertForAction, setSelectedAlertForAction] = useState<Alert | null>(null);
  const [acting, setActing] = useState<string | null>(null);

  // Fetch initial paginated data
  useEffect(() => {
    async function loadData() {
      try {
        const [alertsRes, incidentsRes] = await Promise.all([
          api.getAlerts(1, 100),
          api.getIncidents(1, 10),
        ]);
        setAlerts(alertsRes.alerts);
        setIncidents(incidentsRes.incidents);
      } catch (err) {
        console.error('Failed to load dashboard data:', err);
      }
    }
    loadData();
  }, [setAlerts, setIncidents]);

  // Scroll terminal logs to bottom when new logs arrive
  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  // Get active threats (non-suppressed alerts)
  const activeThreatsCount = alerts.filter((a) => a.status !== 'suppressed').length;

  // Latest alert with AI analysis
  const latestAiAlert = alerts.find((a) => a.ai_analysis && a.status !== 'suppressed');
  const aiAnalysis = latestAiAlert?.ai_analysis;

  // Severity Colors mapping
  const severityColors: Record<Severity, string> = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#f59e0b',
    low: '#3b82f6',
  };

  // Compile severity trend data for Recharts
  const chartData = React.useMemo(() => {
    if (alerts.length === 0) {
      return [
        { name: '00:00', critical: 0, high: 0, medium: 0, low: 0 },
        { name: '04:00', critical: 0, high: 0, medium: 0, low: 0 },
        { name: '08:00', critical: 0, high: 0, medium: 0, low: 0 },
        { name: '12:00', critical: 0, high: 0, medium: 0, low: 0 },
        { name: '16:00', critical: 0, high: 0, medium: 0, low: 0 },
        { name: '20:00', critical: 0, high: 0, medium: 0, low: 0 },
      ];
    }

    // Group alerts by hour blocks (simple bucketing)
    const buckets: Record<string, Record<Severity, number>> = {};
    alerts.forEach((alert) => {
      try {
        const date = new Date(alert.timestamp);
        const timeStr = `${date.getHours().toString().padStart(2, '0')}:00`;
        if (!buckets[timeStr]) {
          buckets[timeStr] = { critical: 0, high: 0, medium: 0, low: 0 };
        }
        buckets[timeStr][alert.severity]++;
      } catch {
        const timeStr = '12:00';
        if (!buckets[timeStr]) {
          buckets[timeStr] = { critical: 0, high: 0, medium: 0, low: 0 };
        }
        buckets[timeStr][alert.severity]++;
      }
    });

    return Object.entries(buckets)
      .map(([name, counts]) => ({
        name,
        critical: counts.critical,
        high: counts.high,
        medium: counts.medium,
        low: counts.low,
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [alerts]);

  // Execute a response action
  const handleExecuteAction = async (actionType: string) => {
    const targetAlert = selectedAlertForAction || latestAiAlert;
    if (!targetAlert) {
      toast.error('No target alert selected to execute response actions on.');
      return;
    }

    // Determine target based on action type
    let target = targetAlert.ip_address;
    if (actionType === 'disable_account' || actionType === 'force_mfa_reset') {
      target = targetAlert.user;
    } else if (actionType === 'isolate_device') {
      target = targetAlert.device;
    }

    setActing(actionType);
    const actToast = toast.loading(`Initiating response: ${actionType.replace('_', ' ').toUpperCase()}...`);
    try {
      const action = await api.executeAction(actionType, target, targetAlert.incident_id, targetAlert.id);
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

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between space-y-4 md:space-y-0">
        <div>
          <h1 className="text-3xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-white via-slate-100 to-slate-400 tracking-tight">
            Security Control Room
          </h1>
          <p className="text-sm text-slate-400">
            Autonomous alert monitoring, threat intelligence correlation, and remediation panel.
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 rounded-xl bg-slate-900 border border-slate-800 px-4 py-2 text-xs font-semibold">
            <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-slate-300">FastAPI Ingestion Online</span>
          </div>
        </div>
      </div>

      {/* 4 Stats Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Risk Gauge Card */}
        <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 flex items-center justify-between shadow-xl">
          <div>
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-1">Global Risk Score</span>
            <span className="text-3xl font-black text-slate-200 tracking-tight block">
              {Math.round(riskScore)}
              <span className="text-xs font-normal text-slate-500 ml-1">/100</span>
            </span>
            <span className="text-xs text-slate-500 mt-2 block font-medium">
              {riskScore > 70 ? '🔴 Critical Severity Threat' : riskScore > 40 ? '🟡 Moderate Operations Load' : '🟢 Secure Baseline'}
            </span>
          </div>
          {/* Circular SVG Gauge */}
          <div className="relative h-16 w-16">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
              <path
                className="text-slate-800"
                strokeWidth="3"
                stroke="currentColor"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
              <path
                className={`transition-all duration-500 ${
                  riskScore > 70 ? 'text-red-500' : riskScore > 40 ? 'text-amber-500' : 'text-emerald-500'
                }`}
                strokeWidth="3"
                strokeDasharray={`${riskScore}, 100`}
                strokeLinecap="round"
                stroke="currentColor"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center text-xs font-black text-slate-300">
              {Math.round(riskScore)}%
            </div>
          </div>
        </div>

        {/* Active Threats */}
        <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 flex items-center justify-between shadow-xl">
          <div>
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-1">Active Threats</span>
            <span className="text-3xl font-black text-slate-200 tracking-tight block">{activeThreatsCount}</span>
            <span className="text-xs text-rose-500 mt-2 block font-semibold animate-pulse flex items-center space-x-1">
              <AlertTriangle className="h-3 w-3 mr-0.5" />
              <span>Awaiting Analyst Triaging</span>
            </span>
          </div>
          <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-rose-500/10 text-rose-400 border border-rose-500/20 shadow-[0_0_15px_rgba(239,68,68,0.15)]">
            <ShieldAlert className="h-6 w-6" />
          </span>
        </div>

        {/* Suppressed False Positives */}
        <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 flex items-center justify-between shadow-xl">
          <div>
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-1">Suppressed Alerts</span>
            <span className="text-3xl font-black text-slate-200 tracking-tight block">{fpSuppressed}</span>
            <span className="text-xs text-emerald-400 mt-2 block font-medium">
              False positives filtered by AI logic
            </span>
          </div>
          <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shadow-[0_0_15px_rgba(16,185,129,0.15)]">
            <ShieldCheck className="h-6 w-6" />
          </span>
        </div>

        {/* Connectivity health */}
        <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 flex items-center justify-between shadow-xl">
          <div>
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-1">Ingestion Health</span>
            <span className="text-3xl font-black text-slate-200 tracking-tight block">99.8%</span>
            <span className="text-xs text-indigo-400 mt-2 block font-semibold uppercase tracking-wider">
              {connectionStatus === 'connected' ? 'WebSocket Streaming' : 'Reconnecting...'}
            </span>
          </div>
          <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 shadow-[0_0_15px_rgba(99,102,241,0.15)]">
            <Activity className="h-6 w-6" />
          </span>
        </div>
      </div>

      {/* Grid: Terminal Logs & Severity Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* scrolling Live Terminal Logs (2/3) */}
        <div className="lg:col-span-2 bg-slate-950 border border-slate-800 rounded-2xl p-6 shadow-2xl flex flex-col h-[400px]">
          <div className="flex items-center justify-between mb-4 border-b border-slate-800/80 pb-3">
            <div className="flex items-center space-x-2.5">
              <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <Terminal className="h-3.5 w-3.5" />
              </span>
              <h2 className="font-bold text-slate-200 text-sm">Real-time Environment Logs Feed</h2>
            </div>
            <div className="flex items-center space-x-1">
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-ping" />
              <span className="text-[10px] font-mono text-slate-500 tracking-wider">LISTENING...</span>
            </div>
          </div>
          {/* Scroll container */}
          <div className="flex-1 overflow-y-auto font-mono text-xs text-slate-400 space-y-2 pr-2 scrollbar-thin">
            {logs.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-600 space-y-2">
                <ShieldAlert className="h-8 w-8 text-slate-700 animate-pulse" />
                <p>Telemetry stream idle. Fire up a simulation in the dashboard control panel.</p>
              </div>
            ) : (
              logs.map((log, idx) => {
                const isCritical = log.severity.toLowerCase() === 'critical';
                const isHigh = log.severity.toLowerCase() === 'high';
                const color = isCritical ? 'text-red-400' : isHigh ? 'text-orange-400' : 'text-amber-400';
                return (
                  <div key={idx} className="hover:bg-white/5 py-1 px-2 rounded transition-colors flex items-start space-x-2">
                    <span className="text-emerald-500 font-semibold select-none flex-shrink-0">[{log.timestamp.split('T')[1]?.slice(0, 8)}]</span>
                    <span className={`${color} font-bold select-none uppercase flex-shrink-0 w-20`}>{log.severity}</span>
                    <span className="text-slate-300 break-all">{log.raw_message}</span>
                  </div>
                );
              })
            )}
            <div ref={logsEndRef} />
          </div>
        </div>

        {/* Severity Chart Widget (1/3) */}
        <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-xl flex flex-col h-[400px]">
          <div className="mb-4">
            <h2 className="font-bold text-slate-200 text-sm">Threat Velocity Tracking</h2>
            <p className="text-xs text-slate-400">Ingested alert counts bucketed by hourly block</p>
          </div>
          <div className="flex-1 min-h-0 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="criticalGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="highGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="name" stroke="#475569" fontSize={9} className="font-mono" />
                <YAxis stroke="#475569" fontSize={9} className="font-mono" allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    border: '1px solid rgba(255,255,255,0.08)',
                    borderRadius: '8px',
                    fontSize: '11px',
                  }}
                />
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" />
                <Area type="monotone" dataKey="critical" stroke="#ef4444" fillOpacity={1} fill="url(#criticalGrad)" />
                <Area type="monotone" dataKey="high" stroke="#f97316" fillOpacity={1} fill="url(#highGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Row: Active Incidents List & AI Reasoning Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Active Incidents Table */}
        <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="font-bold text-slate-200">Active Security Incidents</h2>
              <p className="text-xs text-slate-400">Correlated multi-alert cyber attack chains</p>
            </div>
            <button
              onClick={() => navigate('/incidents')}
              className="text-xs font-semibold text-indigo-400 hover:text-indigo-300 transition-colors"
            >
              View All
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="text-xs uppercase tracking-wider text-slate-500 border-b border-slate-800">
                <tr>
                  <th className="pb-3">Severity</th>
                  <th className="pb-3">Incident Description</th>
                  <th className="pb-3">Impact User</th>
                  <th className="pb-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {incidents.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-8 text-center text-slate-500 text-xs">
                      All clear! No active attack incidents grouped.
                    </td>
                  </tr>
                ) : (
                  incidents.slice(0, 5).map((inc) => {
                    const sev = inc.severity.toLowerCase() as Severity;
                    const color = severityColors[sev] || '#6b7280';
                    return (
                      <tr
                        key={inc.id}
                        onClick={() => navigate(`/incidents/${inc.id}`)}
                        className="hover:bg-white/5 cursor-pointer transition-colors"
                      >
                        <td className="py-4">
                          <span
                            className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border"
                            style={{
                              color,
                              borderColor: `${color}40`,
                              backgroundColor: `${color}10`,
                            }}
                          >
                            {inc.severity}
                          </span>
                        </td>
                        <td className="py-4">
                          <p className="font-bold text-slate-200 max-w-xs truncate">{inc.title}</p>
                          <p className="text-[11px] text-slate-500 font-mono flex items-center space-x-1 mt-0.5">
                            <Clock className="h-3 w-3" />
                            <span>{new Date(inc.created_at).toLocaleTimeString()}</span>
                          </p>
                        </td>
                        <td className="py-4 text-xs font-mono text-slate-400">{inc.affected_user}</td>
                        <td className="py-4 text-right">
                          <button className="text-xs font-bold text-indigo-400 hover:text-indigo-300 transition-colors">
                            Investigate
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* AI Autonomous Reasoning Panel */}
        <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-xl flex flex-col">
          <div className="flex items-center justify-between border-b border-slate-800/60 pb-4 mb-4">
            <div className="flex items-center space-x-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                <Brain className="h-4 w-4" />
              </span>
              <div>
                <h2 className="font-bold text-slate-200">Autonomous AI Analyst</h2>
                <p className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">
                  L2 Reasoning Pipeline
                </p>
              </div>
            </div>
            <button
              onClick={() => setAiExpanded(!aiExpanded)}
              className="text-slate-400 hover:text-white transition-colors"
            >
              {aiExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>
          </div>

          {aiExpanded && (
            <div className="flex-1 flex flex-col justify-between">
              {aiAnalysis ? (
                <div className="space-y-4">
                  {/* Alert Info Title */}
                  <div className="p-3.5 rounded-xl border border-indigo-500/20 bg-indigo-500/5">
                    <p className="text-[11px] font-bold uppercase tracking-wider text-indigo-400">
                      Currently Correlating
                    </p>
                    <h4 className="font-extrabold text-slate-200 text-sm mt-0.5">
                      {latestAiAlert?.event_type} (Rule {latestAiAlert?.rule_id})
                    </h4>
                    <p className="text-xs text-slate-400 mt-1 font-mono">{latestAiAlert?.raw_message}</p>
                  </div>

                  {/* AI Explanation */}
                  <div>
                    <h5 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1 flex items-center space-x-1.5">
                      <span>Threat explanation</span>
                    </h5>
                    <p className="text-xs text-slate-300 leading-relaxed font-sans">{aiAnalysis.explanation}</p>
                  </div>

                  {/* MITRE Badges */}
                  {aiAnalysis.mitre_techniques && aiAnalysis.mitre_techniques.length > 0 && (
                    <div>
                      <h5 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5">
                        MITRE ATT&CK Techniques Map
                      </h5>
                      <div className="flex flex-wrap gap-2">
                        {aiAnalysis.mitre_techniques.map((t, idx) => (
                          <span
                            key={idx}
                            className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-md border border-slate-700 bg-slate-800 text-slate-300 shadow-sm"
                          >
                            {t.id} — {t.name}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Next Step Prediction */}
                  <div className="p-3 bg-red-950/10 border border-red-500/20 rounded-xl">
                    <p className="text-[10px] font-mono font-bold uppercase tracking-widest text-red-400">
                      Predictive Attacker Path
                    </p>
                    <p className="text-xs text-slate-300 mt-0.5 leading-relaxed">
                      {aiAnalysis.next_step_prediction}
                    </p>
                  </div>
                </div>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-center text-slate-500 space-y-3 py-12">
                  <Brain className="h-10 w-10 text-slate-700 animate-pulse" />
                  <div>
                    <p className="text-sm font-semibold text-slate-400">No autonomous analysis yet</p>
                    <p className="text-xs text-slate-500 max-w-xs mt-1 leading-relaxed">
                      Run any simulation sequence to fire security rules and see full reasoning logs.
                    </p>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Mitigation Actions shortcuts */}
      <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-xl">
        <div className="flex items-center space-x-2.5 border-b border-slate-800/60 pb-4 mb-4">
          <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <ShieldAlert className="h-4 w-4" />
          </span>
          <div>
            <h2 className="font-bold text-slate-200">Recommended Responses & Mitigations</h2>
            <p className="text-xs text-slate-400">
              Select an ingested threat alert to dispatch orchestrated mock SOAR block scripts.
            </p>
          </div>
        </div>

        {/* Selected target alert dropdown if multiple available */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div className="flex items-center space-x-3 bg-slate-950/60 border border-slate-800 px-4 py-2.5 rounded-xl">
            <span className="text-xs font-semibold text-slate-400">Target Context:</span>
            {latestAiAlert ? (
              <div className="flex items-center space-x-3 text-xs">
                <span className="font-bold text-slate-200 font-mono">
                  {latestAiAlert.event_type} ({latestAiAlert.user})
                </span>
                <span className="font-mono text-slate-500">{latestAiAlert.ip_address}</span>
              </div>
            ) : (
              <span className="text-xs text-slate-600 font-mono">No target loaded. Inject a scenario.</span>
            )}
          </div>
          {latestAiAlert && (
            <div className="flex flex-wrap gap-2 text-xs">
              <span className="flex items-center space-x-1 bg-slate-850 px-2 py-1 rounded text-slate-400 font-mono">
                <User className="h-3 w-3" />
                <span>{latestAiAlert.user}</span>
              </span>
              <span className="flex items-center space-x-1 bg-slate-850 px-2 py-1 rounded text-slate-400 font-mono">
                <Globe className="h-3 w-3" />
                <span>{latestAiAlert.ip_address} ({latestAiAlert.location?.country || 'RO'})</span>
              </span>
              <span className="flex items-center space-x-1 bg-slate-850 px-2 py-1 rounded text-slate-400 font-mono">
                <Monitor className="h-3 w-3" />
                <span>{latestAiAlert.device}</span>
              </span>
            </div>
          )}
        </div>

        {/* Response actions grid */}
        <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
          {[
            { id: 'block_ip', label: 'Block Attacker IP', desc: 'Perimeter firewall' },
            { id: 'disable_account', label: 'Disable Account', desc: 'IAM authorization' },
            { id: 'revoke_token', label: 'Revoke Token', desc: 'Session token' },
            { id: 'force_mfa_reset', label: 'Force MFA Reset', desc: 'Account verification' },
            { id: 'isolate_device', label: 'Isolate Endpoint', desc: 'Device containment' },
            { id: 'quarantine_process', label: 'Quarantine Process', desc: 'Process execution' },
          ].map((act) => (
            <button
              key={act.id}
              onClick={() => handleExecuteAction(act.id)}
              disabled={!latestAiAlert || acting !== null}
              className="flex flex-col items-center justify-center p-4 rounded-xl border border-white/5 bg-slate-950/60 hover:bg-slate-900/60 hover:border-slate-700/60 active:scale-95 hover:scale-[1.01] transition-all disabled:opacity-30 disabled:pointer-events-none text-center"
            >
              <span className="text-xs font-bold text-slate-200">{act.label}</span>
              <span className="text-[10px] text-slate-500 font-medium mt-1 uppercase tracking-wide">
                {act.desc}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Simulator controls at bottom */}
      <SimulatorPanel />
    </div>
  );
}
