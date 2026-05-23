import React, { useState } from 'react';
import toast from 'react-hot-toast';
import { Settings as SettingsIcon, Brain, Network, Moon, RotateCcw, Save } from 'lucide-react';
import { api } from '../services/api';
import { useStore } from '../stores/useStore';

export function Settings() {
  const clearAll = useStore((state) => state.clearAll);
  const [resetting, setResetting] = useState(false);

  // Load / Save states locally in localStorage to persist configurations
  const [provider, setProvider] = useState<string>(
    localStorage.getItem('sentinel_ai_provider') || 'mock'
  );
  const [openaiKey, setOpenaiKey] = useState<string>(
    localStorage.getItem('sentinel_openai_key') || ''
  );
  const [claudeKey, setClaudeKey] = useState<string>(
    localStorage.getItem('sentinel_claude_key') || ''
  );

  const [backendUrl, setBackendUrl] = useState<string>(
    localStorage.getItem('sentinel_backend_url') || 'http://localhost:8000'
  );
  const [wsUrl, setWsUrl] = useState<string>(
    localStorage.getItem('sentinel_ws_url') || 'ws://localhost:8000/ws/live-alerts'
  );

  const handleSaveAIConfig = (e: React.FormEvent) => {
    e.preventDefault();
    localStorage.setItem('sentinel_ai_provider', provider);
    localStorage.setItem('sentinel_openai_key', openaiKey);
    localStorage.setItem('sentinel_claude_key', claudeKey);
    toast.success('AI configurations updated successfully. Refresh browser to bind.');
  };

  const handleSaveConnection = (e: React.FormEvent) => {
    e.preventDefault();
    localStorage.setItem('sentinel_backend_url', backendUrl);
    localStorage.setItem('sentinel_ws_url', wsUrl);
    toast.success('API endpoints overrides saved. Refresh to re-initialize connections.');
  };

  const handleResetData = async () => {
    if (!confirm('Are you sure you want to completely purge the alerts, logs, and incidents database?')) {
      return;
    }
    setResetting(true);
    const purgeToast = toast.loading('Purging environment database...');
    try {
      await api.resetDemoData();
      clearAll();
      toast.success('Database purge completed!', { id: purgeToast });
    } catch (err: any) {
      toast.error(`Purge failed: ${err.message || err}`, { id: purgeToast });
    } finally {
      setResetting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-white via-slate-100 to-slate-400 tracking-tight flex items-center space-x-2">
          <span>Environment Settings</span>
        </h1>
        <p className="text-sm text-slate-400">
          Configure API key providers, customize ingestion sockets, or completely purge operational databases.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Section 1: AI Provider */}
        <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex items-center space-x-2.5 border-b border-slate-800/60 pb-3">
            <Brain className="h-5 w-5 text-indigo-400" />
            <h3 className="font-bold text-slate-200">AI Reasoning Provider</h3>
          </div>

          <form onSubmit={handleSaveAIConfig} className="space-y-4 text-xs font-semibold text-slate-300">
            <div className="space-y-1">
              <label className="block text-[10px] text-slate-500 uppercase tracking-wider">Active Engine</label>
              <select
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 transition-colors"
              >
                <option value="mock">Autonomous Mock fallback (Default)</option>
                <option value="openai">OpenAI GPT Engine (Direct API)</option>
                <option value="claude">Anthropic Claude Engine (Direct API)</option>
              </select>
            </div>

            {provider === 'openai' && (
              <div className="space-y-1">
                <label className="block text-[10px] text-slate-500 uppercase tracking-wider">OpenAI API Key</label>
                <input
                  type="password"
                  value={openaiKey}
                  onChange={(e) => setOpenaiKey(e.target.value)}
                  placeholder="sk-proj-..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-slate-200 placeholder-slate-650 focus:outline-none focus:border-indigo-500 font-mono transition-colors"
                />
              </div>
            )}

            {provider === 'claude' && (
              <div className="space-y-1">
                <label className="block text-[10px] text-slate-500 uppercase tracking-wider">Anthropic API Key</label>
                <input
                  type="password"
                  value={claudeKey}
                  onChange={(e) => setClaudeKey(e.target.value)}
                  placeholder="sk-ant-..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-slate-200 placeholder-slate-650 focus:outline-none focus:border-indigo-500 font-mono transition-colors"
                />
              </div>
            )}

            <button
              type="submit"
              className="flex items-center space-x-1.5 px-4 py-2.5 bg-indigo-600 hover:bg-indigo-500 hover:scale-[1.01] active:scale-95 text-white font-bold rounded-xl transition-all shadow-md shadow-indigo-950/20"
            >
              <Save className="h-3.5 w-3.5" />
              <span>Save AI Selection</span>
            </button>
          </form>
        </div>

        {/* Section 2: Ingestion and Web Sockets */}
        <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex items-center space-x-2.5 border-b border-slate-800/60 pb-3">
            <Network className="h-5 w-5 text-emerald-400" />
            <h3 className="font-bold text-slate-200">API Endpoint Controls</h3>
          </div>

          <form onSubmit={handleSaveConnection} className="space-y-4 text-xs font-semibold text-slate-300">
            <div className="space-y-1">
              <label className="block text-[10px] text-slate-500 uppercase tracking-wider">Backend Base REST URL</label>
              <input
                type="text"
                value={backendUrl}
                onChange={(e) => setBackendUrl(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-slate-200 font-mono focus:outline-none focus:border-emerald-500 transition-colors"
              />
            </div>

            <div className="space-y-1">
              <label className="block text-[10px] text-slate-500 uppercase tracking-wider">WebSocket Streaming URI</label>
              <input
                type="text"
                value={wsUrl}
                onChange={(e) => setWsUrl(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-slate-200 font-mono focus:outline-none focus:border-emerald-500 transition-colors"
              />
            </div>

            <button
              type="submit"
              className="flex items-center space-x-1.5 px-4 py-2.5 bg-emerald-600 hover:bg-emerald-500 hover:scale-[1.01] active:scale-95 text-white font-bold rounded-xl transition-all shadow-md shadow-emerald-950/20"
            >
              <Save className="h-3.5 w-3.5" />
              <span>Override Connection</span>
            </button>
          </form>
        </div>

        {/* Section 3: Visual styling themes */}
        <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex items-center space-x-2.5 border-b border-slate-800/60 pb-3">
            <Moon className="h-5 w-5 text-purple-400" />
            <h3 className="font-bold text-slate-200">Visual Styling Preferences</h3>
          </div>

          <div className="text-xs font-semibold space-y-3.5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-300">Monospace Terminal Elements</p>
                <p className="text-[10px] text-slate-500 mt-0.5">Use JetBrains Mono inside panels</p>
              </div>
              <input
                type="checkbox"
                defaultChecked
                disabled
                className="h-4 w-4 bg-slate-950 border border-slate-800 text-indigo-500 rounded focus:ring-0 disabled:opacity-50"
              />
            </div>
            
            <div className="flex items-center justify-between border-t border-slate-850 pt-3">
              <div>
                <p className="text-slate-300">Glassmorphism effects</p>
                <p className="text-[10px] text-slate-500 mt-0.5">Blur underlying grid panels</p>
              </div>
              <input
                type="checkbox"
                defaultChecked
                disabled
                className="h-4 w-4 bg-slate-950 border border-slate-800 text-indigo-500 rounded focus:ring-0 disabled:opacity-50"
              />
            </div>
          </div>
        </div>

        {/* Section 4: Demo resets */}
        <div className="bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex items-center space-x-2.5 border-b border-slate-800/60 pb-3">
            <RotateCcw className="h-5 w-5 text-rose-400" />
            <h3 className="font-bold text-slate-200">Database Purge Controls</h3>
          </div>

          <div className="space-y-4">
            <p className="text-xs text-slate-400 leading-relaxed">
              Completely wipe the tables containing ingested alerts, log entries, response actions history, and reset the metrics to baseline defaults.
            </p>
            <button
              onClick={handleResetData}
              disabled={resetting}
              className="flex items-center space-x-1.5 px-4 py-2.5 bg-rose-600 hover:bg-rose-500 hover:scale-[1.01] active:scale-95 text-white font-bold rounded-xl transition-all shadow-md shadow-rose-950/20 disabled:opacity-50"
            >
              {resetting ? (
                <div className="h-3.5 w-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <RotateCcw className="h-3.5 w-3.5" />
              )}
              <span>Purge SQLite Tables</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
