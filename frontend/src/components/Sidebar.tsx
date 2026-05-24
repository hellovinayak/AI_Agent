import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  AlertTriangle,
  Network,
  Bot,
  Settings as SettingsIcon,
  Shield,
  Menu,
} from 'lucide-react';
import { useStore } from '../stores/useStore';

export function Sidebar() {
  const { connectionStatus, sidebarCollapsed, toggleSidebar } = useStore();

  const navItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    { name: 'Incidents', path: '/incidents', icon: AlertTriangle },
    { name: 'Threat Graph', path: '/threat-graph', icon: Network },
    { name: 'AI Copilot', path: '/ai-copilot', icon: Bot },
    { name: 'Settings', path: '/settings', icon: SettingsIcon },
  ];

  return (
    <>
      {/* Desktop Sidebar */}
      <aside
        className={`hidden md:flex flex-col fixed top-0 left-0 h-screen transition-all duration-300 z-30 border-r border-slate-800/40 bg-slate-950/80 backdrop-blur-md ${
          sidebarCollapsed ? 'w-20' : 'w-64'
        }`}
      >
        {/* Brand / Logo */}
        <div className="flex items-center justify-between h-20 px-6 border-b border-slate-800/40">
          <div className="flex items-center space-x-3 overflow-hidden">
            <span className="flex-shrink-0 flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 shadow-[0_0_15px_rgba(99,102,241,0.15)]">
              <Shield className="h-5 w-5" />
            </span>
            {!sidebarCollapsed && (
              <span className="font-bold text-lg tracking-wide text-transparent bg-clip-text bg-gradient-to-r from-white via-slate-200 to-slate-400">
                SHIELDX
              </span>
            )}
          </div>
          <button
            onClick={toggleSidebar}
            className="text-slate-400 hover:text-white transition-colors"
          >
            <Menu className="h-5 w-5" />
          </button>
        </div>

        {/* Navigation Items */}
        <nav className="flex-1 px-4 py-6 space-y-2 overflow-y-auto">
          {navItems.map((item) => (
            <NavLink
              key={item.name}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center space-x-4 px-4 py-3.5 rounded-xl font-medium transition-all duration-200 group relative ${
                  isActive
                    ? 'text-emerald-400 bg-emerald-500/10 border-l-2 border-emerald-500 shadow-[0_0_15px_rgba(16,185,129,0.05)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/5 border-l-2 border-transparent'
                }`
              }
            >
              <item.icon className="h-5 w-5 flex-shrink-0 group-hover:scale-105 transition-transform" />
              {!sidebarCollapsed && <span className="text-sm">{item.name}</span>}
              {sidebarCollapsed && (
                <div className="absolute left-full ml-4 px-2 py-1 bg-slate-900 border border-slate-800 text-xs font-semibold rounded-md opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity whitespace-nowrap shadow-xl z-50">
                  {item.name}
                </div>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Connection Status & Version */}
        <div className="p-4 border-t border-slate-800/40">
          <div className="flex items-center justify-between rounded-xl bg-slate-900/40 p-3 border border-slate-800/30">
            {!sidebarCollapsed && <span className="text-xs text-slate-400 font-medium">Status</span>}
            <div className="flex items-center space-x-2">
              <span
                className={`h-2.5 w-2.5 rounded-full ${
                  connectionStatus === 'connected'
                    ? 'bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)] animate-pulse'
                    : connectionStatus === 'connecting'
                    ? 'bg-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.5)]'
                    : 'bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]'
                }`}
              />
              {!sidebarCollapsed && (
                <span className="text-xs font-semibold text-slate-300 capitalize">
                  {connectionStatus}
                </span>
              )}
            </div>
          </div>
          {!sidebarCollapsed && (
            <div className="mt-3 text-center">
              <span className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">
                v1.0.0 — MVP
              </span>
            </div>
          )}
        </div>
      </aside>

      {/* Mobile Bottom Navigation Bar */}
      <div className="md:hidden fixed bottom-0 left-0 right-0 h-16 bg-slate-950/90 backdrop-blur-lg border-t border-slate-800/60 flex justify-around items-center px-4 z-40 shadow-2xl">
        {navItems.map((item) => (
          <NavLink
            key={item.name}
            to={item.path}
            className={({ isActive }) =>
              `flex flex-col items-center justify-center space-y-1 transition-colors ${
                isActive ? 'text-emerald-400 font-semibold' : 'text-slate-400'
              }`
            }
          >
            <item.icon className="h-5 w-5" />
            <span className="text-[9px] tracking-tight">{item.name}</span>
          </NavLink>
        ))}
      </div>
    </>
  );
}
