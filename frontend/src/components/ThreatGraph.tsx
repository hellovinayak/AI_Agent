import React, { useEffect, useState, useRef, useCallback } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

const NODE_COLORS: Record<string, any> = {
  user:    { fill: '#1a2a4a', stroke: '#4da6ff', glow: 'rgba(77,166,255,0.4)' },
  ip:      { fill: '#3a1010', stroke: '#ff3b3b', glow: 'rgba(255,59,59,0.5)' },
  service: { fill: '#1a2a1a', stroke: '#00ff88', glow: 'rgba(0,255,136,0.3)' },
  device:  { fill: '#1a2a1a', stroke: '#00ff88', glow: 'rgba(0,255,136,0.3)' },
  alert:   { fill: '#2a1a3a', stroke: '#b06bff', glow: 'rgba(176,107,255,0.3)' }
};

export function ThreatGraph({ incidentId }: { incidentId: string }) {
  const [graphData, setGraphData]     = useState<any>({ nodes: [], links: [] });
  const [frames, setFrames]           = useState<any[]>([]);
  const [frameIdx, setFrameIdx]       = useState(0);
  const [isPlaying, setIsPlaying]     = useState(false);
  const [speed, setSpeed]             = useState(1);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [loading, setLoading]         = useState(true);
  const [error, setError]             = useState<string | null>(null);
  const fgRef   = useRef<any>(null);
  const timerRef = useRef<any>(null);

  // ── Fetch graph data ────────────────────────────────────────────────────
  useEffect(() => {
    if (!incidentId) return;
    setLoading(true);
    setError(null);
    const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');
    fetch(`${API_BASE_URL}/api/incidents/${incidentId}/graph`)
      .then(r => {
        if (!r.ok) throw new Error(`API ${r.status}`);
        return r.json();
      })
      .then(data => {
        // Build animation frames from alert timeline
        const frames = buildFrames(data);
        setFrames(frames);
        setGraphData(frames[0] || { nodes: [], links: [] });
        setFrameIdx(0);
        setLoading(false);
      })
      .catch(err => {
        console.error('Graph fetch failed:', err);
        // Fall back to demo data so screen is never black
        const demo = buildDemoData();
        const frames = buildFrames(demo);
        setFrames(frames);
        setGraphData(frames[0]);
        setFrameIdx(0);
        setLoading(false);
        setError('Using demo data — backend unavailable');
      });
  }, [incidentId]);

  // ── Build animation frames ──────────────────────────────────────────────
  function buildFrames(data: any) {
    const { nodes, edges, alerts } = data;
    if (!alerts?.length) return [{ nodes: nodes || [], links: edges || [] }];
    // Each frame reveals alerts up to index i
    return alerts.map((_: any, i: number) => {
      const visibleAlerts = alerts.slice(0, i + 1);
      const visibleEntityIds = new Set(
        visibleAlerts.flatMap((a: any) => a.entities || [])
      );
      
      // Deep clone links to prevent react-force-graph from mutating the original source/target IDs
      const frameLinks = (edges || [])
        .filter((e: any) => {
          const sourceId = typeof e.source === 'object' ? e.source.id : e.source;
          const targetId = typeof e.target === 'object' ? e.target.id : e.target;
          return visibleEntityIds.has(sourceId) && visibleEntityIds.has(targetId);
        })
        .map((e: any) => ({ ...e })); // clone edge so D3 doesn't overwrite original strings

      // Don't clone nodes, ForceGraph needs object identity to retain physics coordinates across frames
      const frameNodes = (nodes || [])
        .filter((n: any) => visibleEntityIds.has(n.id));

      return {
        nodes: frameNodes,
        links: frameLinks,
        currentAlert: alerts[i]
      };
    });
  }

  // ── Playback ────────────────────────────────────────────────────────────
  useEffect(() => {
    if (isPlaying) {
      timerRef.current = setInterval(() => {
        setFrameIdx(prev => {
          const next = prev + 1;
          if (next >= frames.length) {
            setIsPlaying(false);
            return prev;
          }
          setGraphData(frames[next]);
          return next;
        });
      }, 1200 / speed);
    } else {
      clearInterval(timerRef.current);
    }
    return () => clearInterval(timerRef.current);
  }, [isPlaying, speed, frames]);

  const scrubTo = useCallback((idx: number) => {
    const i = Math.min(Math.max(0, idx), frames.length - 1);
    setFrameIdx(i);
    setGraphData(frames[i] || { nodes: [], links: [] });
  }, [frames]);

  // ── Custom node renderer ────────────────────────────────────────────────
  const paintNode = useCallback((node: any, ctx: any, globalScale: number) => {
    const c = NODE_COLORS[node.type] || NODE_COLORS.alert;
    const r = 12 + (node.risk || 0.5) * 8;
    const nx = node.x || 0;
    const ny = node.y || 0;

    // Glow
    const grd = ctx.createRadialGradient(nx, ny, 0, nx, ny, r * 2.5);
    grd.addColorStop(0, c.glow);
    grd.addColorStop(1, 'transparent');
    ctx.beginPath();
    ctx.arc(nx, ny, r * 2.5, 0, Math.PI * 2);
    ctx.fillStyle = grd;
    ctx.fill();

    // Circle
    ctx.beginPath();
    ctx.arc(nx, ny, r, 0, Math.PI * 2);
    ctx.fillStyle = c.fill;
    ctx.fill();
    ctx.strokeStyle = c.stroke;
    ctx.lineWidth = selectedNode?.id === node.id ? 3 : 1.5;
    ctx.stroke();

    // Risk arc
    ctx.beginPath();
    ctx.arc(nx, ny, r + 3, -Math.PI/2,
            -Math.PI/2 + (node.risk || 0.5) * Math.PI * 2);
    ctx.strokeStyle = (node.risk || 0) > 0.7 ? '#ff3b3b' :
                      (node.risk || 0) > 0.4 ? '#ffd60a' : '#00ff88';
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // Label
    if (globalScale > 0.8) {
      ctx.font = `${11 / globalScale}px monospace`;
      ctx.textAlign = 'center';
      ctx.fillStyle = 'rgba(255,255,255,0.85)';
      ctx.fillText(node.label || node.id, nx, ny + r + 12);
    }
  }, [selectedNode]);

  const paintLink = useCallback((link: any, ctx: any) => {
    const isKC = link.type === 'kill_chain';
    ctx.strokeStyle = isKC ? 'rgba(255,59,59,0.7)' : 'rgba(77,166,255,0.35)';
    ctx.lineWidth   = isKC ? 2.5 : 1.5;
    if (!isKC) ctx.setLineDash([4, 6]);
    ctx.stroke();
    ctx.setLineDash([]);
  }, []);

  // ── Demo data fallback (screen is NEVER black) ──────────────────────────
  function buildDemoData() {
    return {
      nodes: [
        { id: 'admin', label: 'admin@corp.com', type: 'user', risk: 0.97 },
        { id: 'attacker_ip', label: '185.220.101.42', type: 'ip', risk: 1.0 },
        { id: 'auth_svc', label: 'Auth Service', type: 'service', risk: 0.65 },
        { id: 'db', label: 'PostgreSQL DB', type: 'service', risk: 0.88 }
      ],
      edges: [
        { source: 'attacker_ip', target: 'admin', type: 'kill_chain' },
        { source: 'admin', target: 'auth_svc', type: 'relation' },
        { source: 'admin', target: 'db', type: 'kill_chain' }
      ],
      alerts: [
        { time: 0,   entities: ['attacker_ip', 'admin'],
          label: 'DET-001 Brute Force' },
        { time: 60,  entities: ['attacker_ip', 'admin', 'auth_svc'],
          label: 'DET-002 Geo Anomaly' },
        { time: 140, entities: ['admin', 'auth_svc', 'db'],
          label: 'DET-008 Priv Escalation' },
        { time: 280, entities: ['admin', 'db'],
          label: 'DET-005 DB Dump' }
      ]
    };
  }

  const styles: any = {
    wrapper:     { position: 'relative', width: '100%', height: '500px',
                   background: '#060810', borderRadius: 12, overflow: 'hidden',
                   display: 'flex', flexDirection: 'column' },
    graphArea:   { flex: 1, minHeight: 0, position: 'relative', height: '100%' },
    emptyState:  { position: 'absolute', inset: 0, display: 'flex',
                   alignItems: 'center', justifyContent: 'center',
                   color: '#4a5568', fontFamily: 'monospace', fontSize: 13 },
    loading:     { display: 'flex', flexDirection: 'column', alignItems: 'center',
                   justifyContent: 'center', height: '500px', gap: 12,
                   background: '#060810', color: '#4a5568', borderRadius: 12 },
    loadingText: { fontFamily: 'monospace', fontSize: 12 },
    spinner:     { width: 24, height: 24, border: '2px solid #1a2a3a',
                   borderTop: '2px solid #4da6ff', borderRadius: '50%',
                   animation: 'spin 0.8s linear infinite' },
    errorBanner: { background: 'rgba(255,140,0,0.1)', color: '#ff8c00',
                   padding: '6px 16px', fontSize: 11, fontFamily: 'monospace',
                   borderBottom: '1px solid rgba(255,140,0,0.2)' },
    playbar:     { display: 'flex', alignItems: 'center', gap: 10,
                   padding: '10px 16px', background: 'rgba(13,17,23,0.95)',
                   borderTop: '1px solid rgba(255,255,255,0.06)',
                   flexShrink: 0 },
    playBtn:     { width: 32, height: 32, borderRadius: '50%',
                   background: '#00d4ff', border: 'none', cursor: 'pointer',
                   fontSize: 12, display: 'flex', alignItems: 'center',
                   justifyContent: 'center', flexShrink: 0 },
    timeLabel:   { fontFamily: 'monospace', fontSize: 11, color: '#4a5568',
                   minWidth: 160, whiteSpace: 'nowrap' },
    slider:      { flex: 1, accentColor: '#00d4ff', cursor: 'pointer' },
    speedBtn:    { padding: '3px 10px', borderRadius: 12, border: '1px solid #1a2a3a',
                   background: 'transparent', color: '#4a5568', fontSize: 10,
                   cursor: 'pointer', fontFamily: 'monospace' },
    speedBtnActive: { borderColor: '#00d4ff', color: '#00d4ff' },
    nodePanel:   { position: 'absolute', top: 12, right: 12, width: 200,
                   background: 'rgba(13,17,23,0.95)', border: '1px solid rgba(255,255,255,0.08)',
                   borderRadius: 8, padding: 14, fontFamily: 'monospace' },
    nodePanelTitle: { fontSize: 11, fontWeight: 700, color: '#e8eaf0',
                      marginBottom: 6 },
    nodeMeta:    { fontSize: 10, color: '#4a5568', lineHeight: 1.7,
                   whiteSpace: 'pre-line' },
    closeBtn:    { position: 'absolute', top: 8, right: 8, background: 'none',
                   border: 'none', color: '#4a5568', cursor: 'pointer', fontSize: 12 }
  };

  if (loading) return (
    <div style={styles.loading}>
      <div style={styles.spinner} />
      <span style={styles.loadingText}>Building threat graph...</span>
    </div>
  );

  return (
    <div style={styles.wrapper}>
      {error && <div style={styles.errorBanner}>{error}</div>}

      {/* Graph canvas — explicit height is critical */}
      <div style={styles.graphArea}>
        {graphData?.nodes?.length === 0 ? (
          <div style={styles.emptyState}>
            No entities to display yet — press Play
          </div>
        ) : (
          <ForceGraph2D
            ref={fgRef}
            key={`${incidentId}-${frameIdx}`}
            graphData={graphData}
            nodeCanvasObject={paintNode}
            nodeCanvasObjectMode={() => 'replace'}
            linkCanvasObject={paintLink}
            linkCanvasObjectMode={() => 'replace'}
            linkDirectionalArrowLength={6}
            linkDirectionalArrowRelPos={0.85}
            linkDirectionalParticles={3}
            linkDirectionalParticleSpeed={0.005}
            linkDirectionalParticleColor={(link: any) =>
              link.type === 'kill_chain' ? '#ff3b3b' : '#4da6ff'}
            backgroundColor="#060810"
            onNodeClick={node => setSelectedNode(node)}
            cooldownTicks={80}
            onEngineStop={() => fgRef.current?.zoomToFit(300, 60)}
          />
        )}
      </div>

      {/* Playback bar */}
      <div style={styles.playbar}>
        <button style={styles.playBtn}
          onClick={() => {
            if (frameIdx >= frames.length - 1) scrubTo(0);
            setIsPlaying(p => !p);
          }}>
          {isPlaying ? '⏸' : '▶'}
        </button>
        <span style={styles.timeLabel}>
          Step {frameIdx + 1}/{frames.length}
          {frames[frameIdx]?.currentAlert &&
            ` · ${frames[frameIdx].currentAlert.label}`}
        </span>
        <input type="range" min={0} max={Math.max(0, frames.length - 1)}
          value={frameIdx} style={styles.slider}
          onChange={e => { setIsPlaying(false); scrubTo(+e.target.value); }} />
        {[1, 2, 4].map(s => (
          <button key={s} style={{
            ...styles.speedBtn,
            ...(speed === s ? styles.speedBtnActive : {})
          }} onClick={() => setSpeed(s)}>{s}×</button>
        ))}
      </div>

      {/* Selected node panel */}
      {selectedNode && (
        <div style={styles.nodePanel}>
          <div style={styles.nodePanelTitle}>
            {selectedNode.type?.toUpperCase()} · {selectedNode.label}
          </div>
          <div style={{
            color: (selectedNode.risk || 0) > 0.7 ? '#ff3b3b' : '#00ff88',
            fontSize: 12, marginBottom: 6
          }}>
            Risk: {((selectedNode.risk || 0) * 100).toFixed(0)}%
          </div>
          {selectedNode.meta && (
            <div style={styles.nodeMeta}>{selectedNode.meta}</div>
          )}
          <button style={styles.closeBtn}
            onClick={() => setSelectedNode(null)}>✕</button>
        </div>
      )}
    </div>
  );
}
