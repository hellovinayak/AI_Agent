import React, { useEffect, useState, useMemo, useRef } from 'react';
import { Network, X, Activity, User, Globe, Monitor } from 'lucide-react';
import ForceGraph2D from 'react-force-graph-2d';
import { useStore } from '../stores/useStore';
import { api } from '../services/api';

interface GraphNode {
  id: string;
  label: string;
  val: number; // size
  color: string;
  type: 'user' | 'ip' | 'device' | 'resource';
}

interface GraphLink {
  source: string;
  target: string;
  color: string;
  label: string;
}

export function ThreatGraph() {
  const { alerts, setAlerts } = useStore();
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 500 });

  // Handle resizing of the graph canvas
  useEffect(() => {
    if (containerRef.current) {
      setDimensions({
        width: containerRef.current.clientWidth,
        height: containerRef.current.clientHeight || 500,
      });
    }
    const handleResize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: containerRef.current.clientHeight || 500,
        });
      }
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // Fetch initial alerts on mount
  useEffect(() => {
    async function loadAlerts() {
      try {
        const res = await api.getAlerts(1, 100);
        setAlerts(res.alerts);
      } catch (err) {
        console.error('Failed to load alerts for graph:', err);
      }
    }
    loadAlerts();
  }, [setAlerts]);

  // Compute node-link representation from non-suppressed alerts
  const graphData = useMemo(() => {
    const activeAlerts = alerts.filter((a) => a.status !== 'suppressed');
    
    const nodeMap = new Map<string, GraphNode>();
    const links: GraphLink[] = [];

    const colors = {
      user: '#3b82f6', // blue
      ip: '#f97316', // orange
      device: '#8b5cf6', // purple
      resource: '#10b981', // green
    };

    activeAlerts.forEach((alert) => {
      const userNodeId = `user:${alert.user}`;
      const ipNodeId = `ip:${alert.ip_address}`;
      const deviceNodeId = `device:${alert.device}`;

      // User node
      if (!nodeMap.has(userNodeId)) {
        nodeMap.set(userNodeId, {
          id: userNodeId,
          label: alert.user,
          val: 12,
          color: colors.user,
          type: 'user',
        });
      } else {
        nodeMap.get(userNodeId)!.val += 2;
      }

      // Attacking IP node
      if (!nodeMap.has(ipNodeId)) {
        nodeMap.set(ipNodeId, {
          id: ipNodeId,
          label: alert.ip_address,
          val: 10,
          color: colors.ip,
          type: 'ip',
        });
      } else {
        nodeMap.get(ipNodeId)!.val += 1.5;
      }

      // Device node
      if (!nodeMap.has(deviceNodeId)) {
        nodeMap.set(deviceNodeId, {
          id: deviceNodeId,
          label: alert.device,
          val: 8,
          color: colors.device,
          type: 'device',
        });
      } else {
        nodeMap.get(deviceNodeId)!.val += 1;
      }

      // Links: IP -> User & User -> Device
      links.push({
        source: ipNodeId,
        target: userNodeId,
        color: alert.severity === 'critical' ? 'rgba(239, 68, 68, 0.4)' : 'rgba(249, 115, 22, 0.4)',
        label: `${alert.event_type} (${alert.rule_id})`,
      });

      links.push({
        source: userNodeId,
        target: deviceNodeId,
        color: 'rgba(99, 102, 241, 0.3)',
        label: 'escalation_path',
      });
    });

    return {
      nodes: Array.from(nodeMap.values()),
      links,
    };
  }, [alerts]);

  // Find alerts related to the selected entity node
  const relatedAlerts = useMemo(() => {
    if (!selectedNode) return [];
    const name = selectedNode.label;
    return alerts.filter(
      (a) =>
        a.status !== 'suppressed' &&
        (a.user === name || a.ip_address === name || a.device === name)
    );
  }, [selectedNode, alerts]);

  return (
    <div className="flex flex-col h-[calc(100vh-80px)] space-y-4">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-white via-slate-100 to-slate-400 tracking-tight">
          Threat Vector Topology
        </h1>
        <p className="text-sm text-slate-400">
          Node-link force graph maps of attacker source IPs targeting assets, devices, and directory accounts.
        </p>
      </div>

      <div className="flex-1 flex flex-col lg:flex-row gap-6 min-h-0">
        {/* Canvas Graph View Container */}
        <div
          ref={containerRef}
          className="flex-1 bg-slate-950 border border-slate-900 rounded-2xl relative overflow-hidden shadow-2xl min-h-[300px]"
        >
          {/* Key / Legend indicator */}
          <div className="absolute top-4 left-4 z-10 flex flex-wrap gap-3 bg-slate-900/80 border border-slate-800/80 backdrop-blur px-4 py-2.5 rounded-xl shadow-lg text-[10px] font-semibold text-slate-400 select-none">
            <div className="flex items-center space-x-1.5">
              <span className="h-2 w-2 rounded-full bg-blue-500" />
              <span>User Target</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="h-2 w-2 rounded-full bg-orange-500" />
              <span>Attacker IP</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="h-2 w-2 rounded-full bg-purple-500" />
              <span>Affected Device</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              <span>Resource Asset</span>
            </div>
          </div>

          {/* Physical canvas */}
          {graphData.nodes.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center text-slate-500 space-y-3">
              <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-slate-900 text-slate-700 border border-slate-800/60 animate-pulse">
                <Network className="h-6 w-6" />
              </span>
              <div>
                <p className="text-sm font-semibold text-slate-400">No threat vectors correlated yet</p>
                <p className="text-xs text-slate-500 max-w-sm mt-1.5 leading-relaxed">
                  Start any telemetry simulations to feed the pipeline. The graph automatically aggregates entities and displays links.
                </p>
              </div>
            </div>
          ) : (
            <ForceGraph2D
              graphData={graphData}
              width={dimensions.width}
              height={dimensions.height}
              backgroundColor="#020617"
              nodeRelSize={1.5}
              linkWidth={1.5}
              linkColor={(link: any) => link.color}
              nodeColor={(node: any) => node.color}
              nodeLabel={(node: any) => `${node.type.toUpperCase()}: ${node.label}`}
              onNodeClick={(node: any) => setSelectedNode(node)}
              cooldownTicks={100}
            />
          )}
        </div>

        {/* Selected Entity side-panel Drawer */}
        {selectedNode && (
          <div className="w-full lg:w-96 bg-slate-900/60 border border-slate-800/60 backdrop-blur-md rounded-2xl p-6 shadow-2xl flex flex-col h-full lg:max-h-full">
            {/* Drawer Title Header */}
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-4 mb-4">
              <div className="flex items-center space-x-2.5">
                <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                  {selectedNode.type === 'user' ? (
                    <User className="h-4 w-4" />
                  ) : selectedNode.type === 'ip' ? (
                    <Globe className="h-4 w-4" />
                  ) : (
                    <Monitor className="h-4 w-4" />
                  )}
                </span>
                <div>
                  <h3 className="font-bold text-slate-200 truncate max-w-[180px]">{selectedNode.label}</h3>
                  <p className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">
                    {selectedNode.type} Entity
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-500 hover:text-white transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            {relatedAlerts[0] && relatedAlerts[0].persona_score !== undefined && (
              <div className="mb-4 p-4 bg-slate-950/60 border border-slate-800 rounded-xl space-y-3">
                <div className="flex justify-between items-center mb-1">
                  <h4 className="text-[10px] font-mono font-bold text-indigo-400 uppercase tracking-widest">
                    Behavioral Persona
                  </h4>
                  <span className="text-xs font-bold text-slate-300">
                    Score: <span className={relatedAlerts[0].persona_score! > 0.6 ? 'text-red-400' : 'text-emerald-400'}>{relatedAlerts[0].persona_score}</span>
                  </span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed font-sans border-l-2 border-indigo-500/30 pl-3">
                  {relatedAlerts[0].persona_explanation}
                </p>
                {relatedAlerts[0].persona_deviations && relatedAlerts[0].persona_deviations.length > 0 && (
                  <div className="mt-2 space-y-1.5">
                    {relatedAlerts[0].persona_deviations.map((dev: any, i: number) => (
                      <div key={i} className="text-[10px] bg-slate-900 px-2 py-1.5 rounded flex items-start gap-2">
                        <span className="text-red-400 mt-0.5">⚠</span>
                        <span className="text-slate-300 font-medium">{dev.description}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* List of related alerts */}
            <div className="flex-1 overflow-y-auto pr-1 space-y-3 scrollbar-thin">
              <h4 className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-widest flex items-center space-x-1.5">
                <Activity className="h-3 w-3" />
                <span>Associated Incidents ({relatedAlerts.length})</span>
              </h4>

              {relatedAlerts.length === 0 ? (
                <p className="text-xs text-slate-500 py-6 select-none font-semibold text-center">
                  No active related alert triggers found.
                </p>
              ) : (
                relatedAlerts.map((alert) => (
                  <div
                    key={alert.id}
                    className="p-3 bg-slate-950/60 border border-slate-850 hover:border-slate-700/60 rounded-xl transition-colors space-y-2 text-xs"
                  >
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] font-bold text-slate-500 font-mono">
                        Rule {alert.rule_id}
                      </span>
                      <span
                        className="text-[9px] font-black uppercase px-2 py-0.5 rounded border"
                        style={{
                          color:
                            alert.severity === 'critical'
                              ? '#ef4444'
                              : alert.severity === 'high'
                              ? '#f97316'
                              : '#f59e0b',
                          borderColor:
                            alert.severity === 'critical'
                              ? 'rgba(239, 68, 68, 0.2)'
                              : 'rgba(249, 115, 22, 0.2)',
                          backgroundColor:
                            alert.severity === 'critical'
                              ? 'rgba(239, 68, 68, 0.05)'
                              : 'rgba(249, 115, 22, 0.05)',
                        }}
                      >
                        {alert.severity}
                      </span>
                    </div>
                    <p className="font-extrabold text-slate-200 leading-snug">{alert.event_type}</p>
                    <p className="text-[10px] text-slate-400 font-mono">{alert.raw_message}</p>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
