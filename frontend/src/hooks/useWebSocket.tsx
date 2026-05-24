import React, { useEffect, useRef, useCallback } from 'react';
import toast from 'react-hot-toast';
import { useStore } from '../stores/useStore';
import { WSMessage } from '../types';

const WS_URL = (import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/live-alerts').replace(/\/$/, '');

export function useWebSocket() {
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const reconnectDelayRef = useRef<number>(1000); // Start reconnect at 1s
  
  const {
    addAlert,
    addIncident,
    addLog,
    setRiskScore,
    incrementFpSuppressed,
    setConnectionStatus,
  } = useStore();

  const connect = useCallback(() => {
    // Clean up any existing socket
    if (socketRef.current) {
      try {
        socketRef.current.close();
      } catch {}
      socketRef.current = null;
    }

    setConnectionStatus('connecting');
    logger('Connecting to WebSocket...');

    const socket = new WebSocket(WS_URL);
    socketRef.current = socket;

    socket.onopen = () => {
      logger('WebSocket connected successfully');
      setConnectionStatus('connected');
      reconnectDelayRef.current = 1000; // Reset exponential backoff
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }
    };

    socket.onmessage = (event) => {
      try {
        const message: WSMessage = JSON.parse(event.data);
        
        switch (message.type) {
          case 'new_log':
            addLog(message.data);
            break;

          case 'new_alert':
            addAlert(message.data);
            // Trigger customized toast based on alert severity
            showNotificationToast(
              `New Alert: ${message.data.event_type}`,
              message.data.severity,
              `Rule ${message.data.rule_id} triggered on ${message.data.user || 'Unknown User'}`
            );
            break;

          case 'incident_update':
            addIncident(message.data);
            showNotificationToast(
              `Incident Updated: ${message.data.title}`,
              message.data.severity as any,
              `Status: ${message.data.status.toUpperCase()} | ${message.data.affected_user}`
            );
            break;

          case 'risk_score_update':
            setRiskScore(message.data.risk_score);
            break;

          case 'fp_suppressed':
            addAlert(message.data);
            incrementFpSuppressed();
            toast.custom(
              (t) => (
                <div
                  className={`${
                    t.visible ? 'animate-enter' : 'animate-leave'
                  } max-w-md w-full bg-slate-900/90 border border-emerald-500/30 backdrop-blur-md shadow-lg rounded-lg pointer-events-auto flex ring-1 ring-black ring-opacity-5`}
                >
                  <div className="flex-1 w-0 p-4">
                    <div className="flex items-start">
                      <div className="flex-shrink-0 pt-0.5">
                        <span className="flex h-8 w-8 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-400">
                          🛡️
                        </span>
                      </div>
                      <div className="ml-3 flex-1">
                        <p className="text-sm font-semibold text-emerald-400">
                          False Positive Suppressed
                        </p>
                        <p className="mt-1 text-xs text-slate-300">
                          {message.data.event_type} ({message.data.rule_id}) was downgraded. {message.data.fp_reason || ''}
                        </p>
                      </div>
                    </div>
                  </div>
                  <div className="flex border-l border-slate-800">
                    <button
                      onClick={() => toast.dismiss(t.id)}
                      className="w-full border border-transparent rounded-none rounded-r-lg p-4 flex items-center justify-center text-sm font-medium text-slate-400 hover:text-slate-300 focus:outline-none"
                    >
                      Dismiss
                    </button>
                  </div>
                </div>
              ),
              { duration: 4000 }
            );
            break;

          case 'stats_update':
            logger('Stats update received', message.data);
            useStore.getState().setFpSuppressed(message.data.suppressed_alerts);
            useStore.getState().setSystemStats({
              ingestion_health: message.data.ingestion_health,
              health_status: message.data.health_status,
              events_per_second: message.data.events_per_second
            });
            break;

          default:
            logger('Unhandled WS message type', message);
        }
      } catch (err) {
        logger('Error parsing WS message', err);
      }
    };

    socket.onerror = (err) => {
      logger('WebSocket error encountered', err);
      setConnectionStatus('disconnected');
    };

    socket.onclose = () => {
      logger('WebSocket closed connection');
      setConnectionStatus('disconnected');
      
      // Reconnect with exponential backoff
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      
      logger(`Reconnecting in ${reconnectDelayRef.current}ms...`);
      reconnectTimeoutRef.current = setTimeout(() => {
        reconnectDelayRef.current = Math.min(reconnectDelayRef.current * 2, 30000);
        connect();
      }, reconnectDelayRef.current) as any;
    };
  }, [addAlert, addIncident, addLog, setRiskScore, incrementFpSuppressed, setConnectionStatus]);

  useEffect(() => {
    connect();

    return () => {
      if (socketRef.current) {
        socketRef.current.close();
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, [connect]);

  const reconnect = useCallback(() => {
    reconnectDelayRef.current = 1000;
    connect();
  }, [connect]);

  return { reconnect };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function logger(...args: any[]) {
  console.log('[WebSocket]', ...args);
}

function showNotificationToast(title: string, severity: 'critical' | 'high' | 'medium' | 'low', body: string) {
  const durationMap = {
    critical: 8000,
    high: 6000,
    medium: 4000,
    low: 4000,
  };

  const borderMap = {
    critical: 'border-red-500/50 bg-red-950/20 text-red-400',
    high: 'border-orange-500/50 bg-orange-950/20 text-orange-400',
    medium: 'border-amber-500/50 bg-amber-950/20 text-amber-400',
    low: 'border-blue-500/50 bg-blue-950/20 text-blue-400',
  };

  const emojiMap = {
    critical: '🚨',
    high: '⚠️',
    medium: '⚡',
    low: 'ℹ️',
  };

  toast.custom(
    (t) => (
      <div
        className={`${
          t.visible ? 'animate-enter' : 'animate-leave'
        } max-w-md w-full bg-slate-900/90 border backdrop-blur-md shadow-lg rounded-lg pointer-events-auto flex ring-1 ring-black ring-opacity-5 ${
          borderMap[severity] || borderMap.low
        }`}
      >
        <div className="flex-1 w-0 p-4">
          <div className="flex items-start">
            <div className="flex-shrink-0 pt-0.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-full bg-white/5">
                {emojiMap[severity] || emojiMap.low}
              </span>
            </div>
            <div className="ml-3 flex-1">
              <p className={`text-sm font-semibold capitalize ${
                severity === 'critical' ? 'text-red-400' :
                severity === 'high' ? 'text-orange-400' :
                severity === 'medium' ? 'text-amber-400' : 'text-blue-400'
              }`}>
                {title}
              </p>
              <p className="mt-1 text-xs text-slate-300">
                {body}
              </p>
            </div>
          </div>
        </div>
        <div className="flex border-l border-white/10">
          <button
            onClick={() => toast.dismiss(t.id)}
            className="w-full border border-transparent rounded-none rounded-r-lg p-4 flex items-center justify-center text-sm font-medium text-slate-400 hover:text-slate-200 focus:outline-none"
          >
            Close
          </button>
        </div>
      </div>
    ),
    { duration: durationMap[severity] || 4000 }
  );
}
