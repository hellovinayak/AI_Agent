import { Alert, Incident, AIAnalysis, ResponseAction } from '../types';

// Read API URL from Vite environment, default to localhost:8000
const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers || {}),
    },
    ...options,
  });

  if (!response.ok) {
    let errorDetail = 'Unknown API error';
    try {
      const errorJson = await response.json();
      errorDetail = errorJson.detail || JSON.stringify(errorJson);
    } catch {
      errorDetail = response.statusText;
    }
    throw new Error(errorDetail);
  }

  return response.json() as Promise<T>;
}

export const api = {
  getHealth: () => request<{ status: string; db: string; uptime: number; version: string }>('/api/health'),

  getAlerts: (page = 1, pageSize = 20, severity?: string, status?: string) => {
    const params = new URLSearchParams({
      page: page.toString(),
      page_size: pageSize.toString(),
    });
    if (severity) params.append('severity', severity);
    if (status) params.append('status', status);
    return request<{ alerts: Alert[]; total: number; page: number }>(`/api/alerts?${params.toString()}`);
  },

  getAlert: (id: string) => request<Alert>(`/api/alerts/${id}`),

  getIncidents: (page = 1, pageSize = 20) => {
    const params = new URLSearchParams({
      page: page.toString(),
      page_size: pageSize.toString(),
    });
    return request<{ incidents: Incident[]; total: number; page: number }>(`/api/incidents?${params.toString()}`);
  },

  getIncident: (id: string) => request<Incident>(`/api/incidents/${id}`),

  generateIncidentReport: (id: string) => request<{ incident_id: string; report: string }>(`/api/incidents/${id}/report`, {
    method: 'POST',
  }),

  // Simulation Triggers
  simulateBruteForce: () => request<{ job_id: string; status: string; scenario: string }>('/api/simulate/bruteforce', {
    method: 'POST',
  }),

  simulateMalware: () => request<{ job_id: string; status: string; scenario: string }>('/api/simulate/malware', {
    method: 'POST',
  }),

  simulateInsiderThreat: () => request<{ job_id: string; status: string; scenario: string }>('/api/simulate/insider-threat', {
    method: 'POST',
  }),

  simulateApiAbuse: () => request<{ job_id: string; status: string; scenario: string }>('/api/simulate/api-abuse', {
    method: 'POST',
  }),

  simulatePasswordSpraying: () => request<{ job_id: string; status: string; scenario: string }>('/api/simulate/password-spraying', {
    method: 'POST',
  }),

  simulateImpossibleTravel: () => request<{ job_id: string; status: string; scenario: string }>('/api/simulate/impossible-travel', {
    method: 'POST',
  }),

  simulateBeaconing: () => request<{ job_id: string; status: string; scenario: string }>('/api/simulate/beaconing', {
    method: 'POST',
  }),

  simulateDnsTunneling: () => request<{ job_id: string; status: string; scenario: string }>('/api/simulate/dns-tunneling', {
    method: 'POST',
  }),

  simulateCloudMetadata: () => request<{ job_id: string; status: string; scenario: string }>('/api/simulate/cloud-metadata', {
    method: 'POST',
  }),

  simulateIamPrivilege: () => request<{ job_id: string; status: string; scenario: string }>('/api/simulate/iam-privilege', {
    method: 'POST',
  }),

  simulateStagingExfiltration: () => request<{ job_id: string; status: string; scenario: string }>('/api/simulate/staging-exfiltration', {
    method: 'POST',
  }),

  simulateSlowDrip: () => request<{ job_id: string; status: string; scenario: string }>('/api/simulate/slow-drip', {
    method: 'POST',
  }),

  simulateHoneypot: () => request<{ job_id: string; status: string; scenario: string }>('/api/simulate/honeypot', {
    method: 'POST',
  }),

  // AI Reasoning & Analysis
  analyzeAlert: (alertId: string) => request<AIAnalysis>('/api/ai/analyze', {
    method: 'POST',
    body: JSON.stringify({ alert_id: alertId }),
  }),

  chatWithAI: (message: string, context?: { incident_id?: string }) => request<{ reply: string; context_used: any[] }>('/api/ai/chat', {
    method: 'POST',
    body: JSON.stringify({ message, context }),
  }),

  // Responder Actions
  executeAction: (actionType: string, target: string, incidentId?: string, alertId?: string) => request<ResponseAction>('/api/respond/action', {
    method: 'POST',
    body: JSON.stringify({
      action_type: actionType,
      target,
      incident_id: incidentId,
      alert_id: alertId,
    }),
  }),

  // Demo Reset
  resetDemoData: () => request<{ cleared: boolean; deleted_rows: Record<string, number> }>('/api/demo/reset', {
    method: 'DELETE',
  }),
};
