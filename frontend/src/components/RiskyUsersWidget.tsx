import React, { useState, useEffect } from 'react';
import { ShieldAlert, Activity, User, AlertTriangle } from 'lucide-react';
import { api } from '../services/api';

export function RiskyUsersWidget() {
  const [riskyUsers, setRiskyUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadRiskyUsers() {
      try {
        const response = await api.getRiskyUsers();
        setRiskyUsers(response);
      } catch (error) {
        console.error("Failed to load risky users:", error);
      } finally {
        setLoading(false);
      }
    }
    
    loadRiskyUsers();
    const intervalId = setInterval(loadRiskyUsers, 10000); // refresh every 10s
    return () => clearInterval(intervalId);
  }, []);

  return (
    <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-xl flex flex-col h-full">
      <div className="flex items-center justify-between border-b border-slate-800/60 pb-4 mb-4">
        <div className="flex items-center space-x-2.5">
          <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-orange-500/10 text-orange-400 border border-orange-500/20">
            <AlertTriangle className="h-4 w-4" />
          </span>
          <div>
            <h2 className="font-bold text-slate-200">Risky Entities</h2>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">
              Adaptive Persona Leaderboard
            </p>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto pr-2 space-y-3">
        {loading && riskyUsers.length === 0 ? (
          <div className="flex items-center justify-center h-32">
            <Activity className="h-6 w-6 text-slate-600 animate-pulse" />
          </div>
        ) : riskyUsers.length === 0 ? (
          <div className="text-center py-6 text-slate-500 text-sm">
            No entities with significant deviations detected.
          </div>
        ) : (
          riskyUsers.map((user, i) => (
            <div key={user.entity_id} className="p-3 bg-slate-950/60 border border-slate-800 rounded-xl flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className={`flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold ${
                  i === 0 ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                  i === 1 ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                  'bg-slate-800 text-slate-400 border border-slate-700'
                }`}>
                  #{i + 1}
                </div>
                <div>
                  <h4 className="text-xs font-bold text-slate-200 flex items-center space-x-1.5">
                    {user.entity_type === 'user' ? <User className="h-3 w-3 text-slate-500" /> : null}
                    <span>{user.entity_id}</span>
                  </h4>
                  <div className="flex space-x-3 mt-1">
                    <span className="text-[10px] font-mono text-slate-500">
                      Observed: {user.observation_days}d
                    </span>
                    {user.confirmed_incidents > 0 && (
                      <span className="text-[10px] font-mono text-red-400 font-bold">
                        Incidents: {user.confirmed_incidents}
                      </span>
                    )}
                  </div>
                </div>
              </div>
              <div className="text-right">
                <div className={`text-lg font-bold font-mono ${
                  user.risk_score > 0.7 ? 'text-red-400' :
                  user.risk_score > 0.4 ? 'text-orange-400' : 'text-slate-300'
                }`}>
                  {(user.risk_score * 100).toFixed(0)}
                </div>
                <div className="text-[9px] uppercase tracking-widest text-slate-500">Risk Score</div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
