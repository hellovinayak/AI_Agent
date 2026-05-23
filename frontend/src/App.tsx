import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';

import { Sidebar } from './components/Sidebar';
import { Dashboard } from './pages/Dashboard';
import { Incidents } from './pages/Incidents';
import { IncidentDetail } from './pages/IncidentDetail';
import { ThreatGraph } from './pages/ThreatGraph';
import { AICopilot } from './pages/AICopilot';
import { Settings } from './pages/Settings';

import { useWebSocket } from './hooks/useWebSocket';
import { useStore } from './stores/useStore';

function AppContent() {
  // Initialize the WebSocket telemetry listener
  useWebSocket();
  const sidebarCollapsed = useStore((state) => state.sidebarCollapsed);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex font-sans">
      {/* Sidebar Nav */}
      <Sidebar />

      {/* Main Content panel */}
      <main
        className={`flex-1 min-w-0 transition-all duration-300 p-6 md:p-8 pb-24 md:pb-8 ${
          sidebarCollapsed ? 'md:ml-20' : 'md:ml-64'
        }`}
      >
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="/threat-graph" element={<ThreatGraph />} />
          <Route path="/ai-copilot" element={<AICopilot />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>

      {/* Global Real-time Threat Toaster */}
      <Toaster position="top-right" reverseOrder={false} />
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}
