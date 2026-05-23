// ========== CORE MODELS (ALIGNED WITH FASTAPI) ==========

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type IncidentStatus = 'open' | 'investigating' | 'resolved';
export type ConnectionStatus = 'connecting' | 'connected' | 'disconnected';

export interface MITRETechnique {
  id: string;
  name: string;
}

export interface AIAnalysis {
  explanation: string;
  narrative: string;
  severity_reasoning: string;
  mitre_tactics: string[];
  mitre_techniques: MITRETechnique[];
  recommended_actions: string[];
  business_impact: string;
  next_step_prediction: string;
  generated_by: 'openai' | 'claude' | 'mock';
  generated_at: string;
}

export interface Alert {
  id: string;
  timestamp: string;
  rule_id: string;
  event_type: string;
  user: string;
  ip_address: string;
  location: Record<string, string>;
  device: string;
  severity: Severity;
  raw_message: string;
  confidence_score: number;
  adjusted_severity?: string;
  fp_reason?: string;
  status: 'open' | 'suppressed' | 'in_incident';
  ai_analysis?: AIAnalysis;
  incident_id?: string;
}

export interface TimelineEvent {
  timestamp: string;
  event_type: string;
  description: string;
  severity: string;
  alert_id?: string;
}

export interface ResponseAction {
  id: string;
  action_type: string;
  target: string;
  executed_at: string;
  executed_by: string;
  status: 'simulated' | 'pending' | 'executed' | 'failed';
  incident_id?: string;
  alert_id?: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: string;
  status: IncidentStatus;
  created_at: string;
  updated_at: string;
  affected_user: string;
  affected_ip: string;
  alert_ids: string[];
  timeline: TimelineEvent[];
  ai_narrative: string;
  mitre_tactics: string[];
  recommended_actions: string[];
  business_impact: string;
  response_actions_taken: ResponseAction[];
}

export interface LogEntry {
  id?: number;
  timestamp: string;
  user_name?: string;  // Sometimes user_name in DB
  user?: string;       // Sometimes user in model
  ip_address: string;
  location: string | Record<string, string>;
  device: string;
  event_type: string;
  severity: string;
  raw_message: string;
  simulation_type?: string;
}

// ========== WEBSOCKET MESSAGE TYPES ==========

export interface NewLogMessage {
  type: 'new_log';
  data: LogEntry;
}

export interface NewAlertMessage {
  type: 'new_alert';
  data: Alert;
}

export interface IncidentUpdateMessage {
  type: 'incident_update';
  data: Incident;
}

export interface RiskScoreUpdateMessage {
  type: 'risk_score_update';
  data: {
    risk_score: number;
  };
}

export interface FPSuppressedMessage {
  type: 'fp_suppressed';
  data: Alert;
}

export type WSMessage =
  | NewLogMessage
  | NewAlertMessage
  | IncidentUpdateMessage
  | RiskScoreUpdateMessage
  | FPSuppressedMessage;

// ========== API REQUEST/RESPONSE TYPES ==========

export interface PaginatedResponse<T> {
  alerts?: T[];      // For list_alerts
  incidents?: T[];   // For list_incidents
  total: number;
  page: number;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}
