import React, { useState } from 'react';
import toast from 'react-hot-toast';
import { ShieldAlert, Play, RotateCcw, Flame, Skull, UserCheck, Key, Users, PlaneTakeoff, Radio, GlobeLock, CloudCog, ShieldHalf, FolderArchive, Droplets } from 'lucide-react';
import { api } from '../services/api';
import { useStore } from '../stores/useStore';

export function SimulatorPanel() {
  const [running, setRunning] = useState<string | null>(null);
  const [resetting, setResetting] = useState(false);
  const clearAll = useStore((state) => state.clearAll);

  const scenarios = [
    {
      id: 'bruteforce',
      name: 'Brute Force Attack',
      icon: Flame,
      color: 'from-amber-600 to-red-600 shadow-red-950/40',
      action: api.simulateBruteForce,
    },
    {
      id: 'malware',
      name: 'Malware Execution',
      icon: Skull,
      color: 'from-purple-600 to-indigo-600 shadow-indigo-950/40',
      action: api.simulateMalware,
    },
    {
      id: 'insider',
      name: 'Insider Threat',
      icon: UserCheck,
      color: 'from-emerald-600 to-teal-600 shadow-emerald-950/40',
      action: api.simulateInsiderThreat,
    },
    {
      id: 'api',
      name: 'API Token Abuse',
      icon: Key,
      color: 'from-blue-600 to-cyan-600 shadow-blue-950/40',
      action: api.simulateApiAbuse,
    },
    {
      id: 'pass_spray',
      name: 'Password Spraying',
      icon: Users,
      color: 'from-orange-600 to-amber-600 shadow-orange-950/40',
      action: api.simulatePasswordSpraying,
    },
    {
      id: 'impossible_travel',
      name: 'Impossible Travel',
      icon: PlaneTakeoff,
      color: 'from-violet-600 to-fuchsia-600 shadow-violet-950/40',
      action: api.simulateImpossibleTravel,
    },
    {
      id: 'beaconing',
      name: 'C2 Beaconing',
      icon: Radio,
      color: 'from-pink-600 to-rose-600 shadow-pink-950/40',
      action: api.simulateBeaconing,
    },
    {
      id: 'dns_tunnel',
      name: 'DNS Tunneling',
      icon: GlobeLock,
      color: 'from-sky-600 to-blue-600 shadow-sky-950/40',
      action: api.simulateDnsTunneling,
    },
    {
      id: 'cloud_meta',
      name: 'Cloud Metadata',
      icon: CloudCog,
      color: 'from-indigo-600 to-blue-600 shadow-indigo-950/40',
      action: api.simulateCloudMetadata,
    },
    {
      id: 'iam_priv',
      name: 'IAM Privilege',
      icon: ShieldHalf,
      color: 'from-yellow-600 to-orange-600 shadow-yellow-950/40',
      action: api.simulateIamPrivilege,
    },
    {
      id: 'staging_exfil',
      name: 'Staging Exfil',
      icon: FolderArchive,
      color: 'from-lime-600 to-green-600 shadow-lime-950/40',
      action: api.simulateStagingExfiltration,
    },
    {
      id: 'slow_drip',
      name: 'Slow-Drip Exfil',
      icon: Droplets,
      color: 'from-cyan-600 to-teal-600 shadow-cyan-950/40',
      action: api.simulateSlowDrip,
    },
    {
      id: 'honeypot',
      name: 'Honeypot Trap',
      icon: ShieldAlert,
      color: 'from-rose-600 to-pink-600 shadow-rose-950/40',
      action: api.simulateHoneypot,
    },
    {
      id: 'benign',
      name: 'Simulate Benign Traffic',
      icon: Users,
      color: 'from-emerald-500 to-green-500 shadow-emerald-950/40',
      action: api.simulateBenign,
    },
  ];

  const handleSimulate = async (scenario: typeof scenarios[0]) => {
    setRunning(scenario.id);
    const loadingToast = toast.loading(`Triggering ${scenario.name}...`);
    try {
      const res = await scenario.action();
      toast.success(
        <div>
          <p className="font-semibold">{scenario.name} Started</p>
          <p className="text-xs text-slate-300">Job: {res.job_id} is running in background.</p>
        </div>,
        { id: loadingToast }
      );
    } catch (err: any) {
      toast.error(`Simulation failed: ${err.message || err}`, { id: loadingToast });
    } finally {
      setRunning(null);
    }
  };

  const handleReset = async () => {
    if (!confirm('Are you sure you want to clear all simulation database records and reset the metrics?')) {
      return;
    }
    setResetting(true);
    const resetToast = toast.loading('Clearing demo data...');
    try {
      await api.resetDemoData();
      clearAll();
      toast.success('Demo environment reset successfully!', { id: resetToast });
    } catch (err: any) {
      toast.error(`Failed to reset: ${err.message || err}`, { id: resetToast });
    } finally {
      setResetting(false);
    }
  };

  return (
    <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-2xl">
      <div className="flex items-center space-x-3 mb-6">
        <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
          <ShieldAlert className="h-4 w-4" />
        </span>
        <div>
          <h3 className="font-bold text-slate-200">Threat Simulator</h3>
          <p className="text-xs text-slate-400">Autonomously inject logs & test responses</p>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {scenarios.map((sc) => {
          const Icon = sc.icon;
          const isCurrent = running === sc.id;
          return (
            <button
              key={sc.id}
              onClick={() => handleSimulate(sc)}
              disabled={running !== null || resetting}
              className={`group flex items-center justify-between p-4 rounded-xl border border-white/5 bg-gradient-to-br ${sc.color
                } hover:scale-[1.02] active:scale-[0.98] transition-all duration-200 shadow-lg text-left disabled:opacity-50 disabled:scale-100 disabled:pointer-events-none`}
            >
              <div className="flex items-center space-x-3">
                <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-white/10 text-white border border-white/10 group-hover:rotate-6 transition-transform">
                  <Icon className="h-5 w-5" />
                </span>
                <div>
                  <p className="text-xs font-semibold text-white/70 uppercase tracking-wider">Simulate</p>
                  <p className="text-sm font-bold text-white leading-tight">{sc.name.split(' ')[0]} {sc.name.split(' ').slice(1).join(' ')}</p>
                </div>
              </div>
              <span className="flex h-7 w-7 items-center justify-center rounded-full bg-white/10 text-white">
                {isCurrent ? (
                  <div className="h-3 w-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  <Play className="h-3 w-3 fill-current" />
                )}
              </span>
            </button>
          );
        })}
      </div>

      <div className="flex items-center justify-between mt-6 pt-4 border-t border-slate-800/40">
        <p className="text-xs text-slate-500">
          * Simulations stream events in real time through the WebSocket.
        </p>
        <button
          onClick={handleReset}
          disabled={running !== null || resetting}
          className="flex items-center space-x-2 px-4 py-2 text-xs font-semibold text-rose-400 bg-rose-500/10 border border-rose-500/20 hover:bg-rose-500/20 rounded-xl transition-all active:scale-95 disabled:opacity-50 disabled:pointer-events-none"
        >
          {resetting ? (
            <div className="h-3.5 w-3.5 border-2 border-rose-400 border-t-transparent rounded-full animate-spin" />
          ) : (
            <RotateCcw className="h-3.5 w-3.5" />
          )}
          <span>Reset Environment</span>
        </button>
      </div>
    </div>
  );
}
