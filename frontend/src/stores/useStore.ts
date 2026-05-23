import { create } from 'zustand';
import { Alert, Incident, LogEntry, ConnectionStatus } from '../types';

interface State {
  alerts: Alert[];
  incidents: Incident[];
  logs: LogEntry[];
  riskScore: number;
  fpSuppressed: number;
  connectionStatus: ConnectionStatus;
  sidebarCollapsed: boolean;

  setAlerts: (alerts: Alert[]) => void;
  addAlert: (alert: Alert) => void;
  
  setIncidents: (incidents: Incident[]) => void;
  addIncident: (incident: Incident) => void;
  updateIncident: (incident: Incident) => void;

  setLogs: (logs: LogEntry[]) => void;
  addLog: (log: LogEntry) => void;

  setRiskScore: (score: number) => void;
  setFpSuppressed: (count: number) => void;
  incrementFpSuppressed: () => void;
  
  setConnectionStatus: (status: ConnectionStatus) => void;
  toggleSidebar: () => void;
  clearAll: () => void;
}

export const useStore = create<State>((set) => ({
  alerts: [],
  incidents: [],
  logs: [],
  riskScore: 0,
  fpSuppressed: 0,
  connectionStatus: 'disconnected',
  sidebarCollapsed: false,

  setAlerts: (alerts) => set({ alerts }),
  addAlert: (alert) =>
    set((state) => {
      const exists = state.alerts.some((a) => a.id === alert.id);
      let updatedAlerts;
      if (exists) {
        updatedAlerts = state.alerts.map((a) => (a.id === alert.id ? alert : a));
      } else {
        updatedAlerts = [alert, ...state.alerts];
      }
      return { alerts: updatedAlerts };
    }),

  setIncidents: (incidents) => set({ incidents }),
  addIncident: (incident) =>
    set((state) => {
      const exists = state.incidents.some((i) => i.id === incident.id);
      let updatedIncidents;
      if (exists) {
        updatedIncidents = state.incidents.map((i) => (i.id === incident.id ? incident : i));
      } else {
        updatedIncidents = [incident, ...state.incidents];
      }
      return { incidents: updatedIncidents };
    }),
  updateIncident: (incident) =>
    set((state) => ({
      incidents: state.incidents.map((i) => (i.id === incident.id ? incident : i)),
    })),

  setLogs: (logs) => set({ logs }),
  addLog: (log) =>
    set((state) => {
      // Avoid duplicate logs in short windows
      const isDuplicate = state.logs.slice(0, 5).some((l) => l.raw_message === log.raw_message && l.timestamp === log.timestamp);
      if (isDuplicate) return {};
      return {
        logs: [log, ...state.logs].slice(0, 200),
      };
    }),

  setRiskScore: (riskScore) => set({ riskScore }),
  setFpSuppressed: (fpSuppressed) => set({ fpSuppressed }),
  incrementFpSuppressed: () => set((state) => ({ fpSuppressed: state.fpSuppressed + 1 })),

  setConnectionStatus: (connectionStatus) => set({ connectionStatus }),
  toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
  clearAll: () => set({ alerts: [], incidents: [], logs: [], riskScore: 0, fpSuppressed: 0 }),
}));
