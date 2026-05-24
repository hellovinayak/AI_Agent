import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, Search, Filter, Clock, Eye, AlertCircle } from 'lucide-react';
import { api } from '../services/api';
import { useStore } from '../stores/useStore';
import { Incident, Severity } from '../types';

export function Incidents() {
  const navigate = useNavigate();
  const { incidents, setIncidents } = useStore();

  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  useEffect(() => {
    async function loadIncidents() {
      setLoading(true);
      try {
        const res = await api.getIncidents(page, 20);
        setIncidents(res.incidents);
        setTotal(res.total);
      } catch (err) {
        console.error('Failed to fetch incidents list:', err);
      } finally {
        setLoading(false);
      }
    }
    loadIncidents();
  }, [page, setIncidents]);

  // Client-side filter matching to avoid DB delays during quick navigation
  const filteredIncidents = incidents.filter((inc) => {
    const sevMatch = severityFilter === 'all' || inc.severity?.toLowerCase() === severityFilter.toLowerCase();
    const statMatch = statusFilter === 'all' || inc.status?.toLowerCase() === statusFilter.toLowerCase();
    return sevMatch && statMatch;
  });

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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between space-y-4 md:space-y-0">
        <div>
          <h1 className="text-3xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-white via-slate-100 to-slate-400 tracking-tight">
            Security Incidents
          </h1>
          <p className="text-sm text-slate-400">
            Correlated multi-alert cyber attack timelines grouped by source IP or target credentials.
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-4 shadow-lg flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-4 w-full md:w-auto">
          {/* Severity filter dropdown */}
          <div className="flex items-center space-x-2">
            <span className="text-xs text-slate-500 font-semibold uppercase tracking-wider">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-xs font-semibold rounded-xl px-3 py-2 text-slate-300 focus:outline-none focus:border-indigo-500 transition-colors"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {/* Status filter dropdown */}
          <div className="flex items-center space-x-2">
            <span className="text-xs text-slate-500 font-semibold uppercase tracking-wider">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-xs font-semibold rounded-xl px-3 py-2 text-slate-300 focus:outline-none focus:border-indigo-500 transition-colors"
            >
              <option value="all">All States</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>
        </div>

        {/* Counter */}
        <div className="text-xs font-semibold text-slate-400">
          Showing {filteredIncidents.length} of {total} correlated incidents
        </div>
      </div>

      {/* Incidents Table / Grid */}
      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[...Array(6)].map((_, i) => (
            <div
              key={i}
              className="h-48 rounded-2xl bg-slate-900/40 border border-slate-850 animate-pulse"
            />
          ))}
        </div>
      ) : filteredIncidents.length === 0 ? (
        <div className="bg-slate-900/30 border border-slate-800/40 backdrop-blur-md rounded-2xl p-16 flex flex-col items-center justify-center text-center text-slate-500 max-w-2xl mx-auto shadow-md">
          <span className="flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-800 text-slate-600 mb-4 border border-slate-700/60 shadow-lg">
            <ShieldAlert className="h-6 w-6" />
          </span>
          <h3 className="text-lg font-bold text-slate-300">All Security Clearances Clear</h3>
          <p className="text-xs text-slate-500 max-w-sm mt-1.5 leading-relaxed">
            No active grouped attack incidents found. If you just reset the system, fire up the threat simulator to ingest security logs.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredIncidents.map((inc) => {
            const sev = (inc.severity || 'low').toLowerCase() as Severity;
            const color = severityColors[sev] || '#6b7280';
            return (
              <div
                key={inc.id}
                onClick={() => navigate(`/incidents/${inc.id}`)}
                className="group flex flex-col justify-between p-6 rounded-2xl border border-white/5 bg-slate-900/60 hover:bg-slate-900/80 backdrop-blur-md cursor-pointer transition-all hover:scale-[1.01] hover:border-slate-800 shadow-xl relative overflow-hidden"
              >
                {/* Decorative glow corner based on severity */}
                <div
                  className="absolute -top-16 -right-16 h-32 w-32 rounded-full opacity-10 blur-2xl transition-opacity group-hover:opacity-20"
                  style={{ backgroundColor: color }}
                />

                <div className="space-y-4">
                  {/* Top: Badges */}
                  <div className="flex items-center justify-between">
                    <span
                      className="text-[10px] font-black uppercase tracking-widest px-2.5 py-0.5 rounded border shadow-sm"
                      style={{
                        color,
                        borderColor: `${color}40`,
                        backgroundColor: `${color}10`,
                      }}
                    >
                      {inc.severity}
                    </span>
                    <span
                      className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${
                        statusColors[inc.status?.toLowerCase()] || 'text-slate-400 border-slate-700 bg-slate-800'
                      }`}
                    >
                      {inc.status}
                    </span>
                  </div>

                  {/* Title */}
                  <div>
                    <h3 className="font-extrabold text-slate-200 text-base leading-snug group-hover:text-white transition-colors">
                      {inc.title}
                    </h3>
                    <p className="text-xs text-slate-500 font-mono flex items-center space-x-1.5 mt-1.5">
                      <Clock className="h-3.5 w-3.5" />
                      <span>{new Date(inc.created_at).toLocaleDateString()} at {new Date(inc.created_at).toLocaleTimeString()}</span>
                    </p>
                  </div>

                  {/* Affected targets details */}
                  <div className="space-y-1.5 border-t border-slate-800/60 pt-3 text-xs font-mono">
                    <div className="flex justify-between">
                      <span className="text-slate-500 font-semibold">User Target:</span>
                      <span className="text-slate-300 font-bold">{inc.affected_user}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500 font-semibold">Target IP Address:</span>
                      <span className="text-slate-300 font-bold">{inc.affected_ip}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500 font-semibold">Total Alert Events:</span>
                      <span className="text-indigo-400 font-extrabold">{inc.alert_ids?.length || 1}</span>
                    </div>
                  </div>
                </div>

                <div className="flex justify-end items-center mt-5 pt-3 border-t border-slate-800/40 text-xs font-bold text-indigo-400 group-hover:text-indigo-300 transition-colors">
                  <div className="flex items-center space-x-1">
                    <span>Investigate Chain</span>
                    <Eye className="h-3.5 w-3.5" />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Pagination controls */}
      {!loading && total > 20 && (
        <div className="flex items-center justify-between border-t border-slate-850 pt-6">
          <button
            onClick={() => setPage(Math.max(1, page - 1))}
            disabled={page === 1}
            className="px-4 py-2 border border-slate-800 rounded-xl text-xs font-bold hover:bg-slate-900 disabled:opacity-30 disabled:pointer-events-none transition-colors"
          >
            Previous Page
          </button>
          <div className="text-xs font-mono text-slate-500 font-semibold">
            Page {page} of {Math.ceil(total / 20)}
          </div>
          <button
            onClick={() => setPage(page + 1)}
            disabled={page >= Math.ceil(total / 20)}
            className="px-4 py-2 border border-slate-800 rounded-xl text-xs font-bold hover:bg-slate-900 disabled:opacity-30 disabled:pointer-events-none transition-colors"
          >
            Next Page
          </button>
        </div>
      )}
    </div>
  );
}
