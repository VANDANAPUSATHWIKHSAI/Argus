import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';

const DEFAULT_TENANT_ID = import.meta.env.VITE_TENANT_ID || 'default';

const ICONS = {
  finding: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>,
  device: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12.01" y2="21"></line></svg>,
  user: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>,
  network: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>,
  process: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>,
  evidence: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
};

export default function ForensicGraph({ caseId }) {
  const navigate = useNavigate();
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [scale, setScale] = useState(1.0);
  const [loading, setLoading] = useState(false);
  const [isGraphPartial, setIsGraphPartial] = useState(false);

  let currentUser = null;
  try {
    currentUser = JSON.parse(localStorage.getItem('argus_user'));
  } catch (e) {}
  const isAnalyst = currentUser?.role === 'analyst';

  useEffect(() => {
    if (!caseId) {
      setNodes([]);
      setEdges([]);
      setSelectedNodeId(null);
      setIsGraphPartial(false);
      return;
    }

    let isMounted = true;
    async function loadGraphData() {
      setLoading(true);
      try {
        const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
        const token = localStorage.getItem('argus_token');
        const headers = {
          'X-Tenant-ID': DEFAULT_TENANT_ID,
          ...(token ? { 'Authorization': `Bearer ${token}` } : {})
        };

        // Fetch evidence and agents first to quickly verify if correlation is available
        const [evidenceRes, agentsRes] = await Promise.all([
          fetch(`${baseUrl}/evidence/case/${caseId}`, { headers }).catch(() => null),
          fetch(`${baseUrl}/cases/${caseId}/agents`, { headers }).catch(() => null)
        ]);

        let rawEvidence = [];
        if (evidenceRes && evidenceRes.ok) {
          const data = await evidenceRes.json();
          rawEvidence = Array.isArray(data) ? data : (data.data || []);
        }

        let agentData = null;
        if (agentsRes && agentsRes.ok) {
          agentData = await agentsRes.json();
        }

        if (!isMounted) return;

        // Verify if Agent Swarm (Agent 02) has actually produced correlation data
        const agentStatus = (agentData?.status || '').toUpperCase();
        const a2Status = (agentData?.stage_statuses?.agent2 || '').toUpperCase();
        const agent2Signals = agentData?.agent2?.signals || {};
        const agentRels = agent2Signals.relationships || [];
        const agentCommunities = agent2Signals.graph_communities || [];
        const claims = agentData?.claims || [];

        const isAgentCorrelated = Boolean(
          (agentStatus === 'COMPLETED' || agentStatus === 'SUCCESS' || a2Status === 'COMPLETED') &&
          (agentRels.length > 0 || agentCommunities.length > 0 || claims.some(c => (c.evidence_ids?.length > 1 || c.cited_evidence_ids?.length > 1)))
        );

        // Extract finding IDs evaluated or cited by agents
        const relevantFindingIds = new Set();
        agentRels.forEach(r => {
          if (r.source) relevantFindingIds.add(String(r.source));
          if (r.target) relevantFindingIds.add(String(r.target));
        });
        claims.forEach(c => {
          (c.evidence_ids || []).forEach(id => relevantFindingIds.add(String(id)));
          (c.cited_evidence_ids || []).forEach(id => relevantFindingIds.add(String(id)));
        });

        let rawFindings = [];
        let partialFlag = false;

        // If agents have not correlated findings, skip finding query to prevent lag but keep evidence nodes
        if (!isAgentCorrelated) {
          rawFindings = [];
        } else if (relevantFindingIds.size > 0) {
          // Explicit graph query targeting the exact findings correlated by the agents (bounded to 50)
          const targetIds = Array.from(relevantFindingIds).slice(0, 50);
          if (relevantFindingIds.size > 50) partialFlag = true;
          const idsQuery = encodeURIComponent(targetIds.join(','));
          const findingsRes = await fetch(`${baseUrl}/cases/${caseId}/findings?ids=${idsQuery}`, { headers }).catch(() => null);
          if (findingsRes && findingsRes.ok) {
            const data = await findingsRes.json();
            rawFindings = Array.isArray(data) ? data : (data.data || []);
          }
        } else {
          // Correlated swarm completed with no specific cross-finding claims: fetch initial bounded findings
          const findingsRes = await fetch(`${baseUrl}/cases/${caseId}/findings?limit=15`, { headers }).catch(() => null);
          if (findingsRes && findingsRes.ok) {
            const data = await findingsRes.json();
            rawFindings = Array.isArray(data) ? data : (data.data || []);
          }
        }

        if (!isMounted) return;

        const generatedNodes = [];
        const generatedEdges = [];
        const evidenceMap = new Map();

        // 1. Evidence nodes ALWAYS render even if agents have not yet run!
        evidenceListToNodes(rawEvidence, generatedNodes, evidenceMap);

        // 2. Correlated finding nodes and relationships
        if (rawFindings.length > 0) {
          buildAgentDrivenGraph(rawFindings, agentData, generatedNodes, generatedEdges, evidenceMap);
        }

        // 3. Position nodes dynamically avoiding overlap
        positionGraphNodes(generatedNodes, generatedEdges);

        setNodes(generatedNodes);
        setEdges(generatedEdges);
        setIsGraphPartial(partialFlag);
        if (generatedNodes.length > 0) {
          setSelectedNodeId(generatedNodes[0].id);
        } else {
          setSelectedNodeId(null);
        }
      } catch (err) {
        console.error('Failed to load graph data:', err);
        if (isMounted) {
          setNodes([]);
          setEdges([]);
          setSelectedNodeId(null);
          setIsGraphPartial(false);
        }
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    loadGraphData();
    return () => { isMounted = false; };
  }, [caseId]);

  const nodeMap = useMemo(() => {
    const map = new Map();
    for (let i = 0; i < nodes.length; i++) {
      map.set(nodes[i].id, nodes[i]);
    }
    return map;
  }, [nodes]);

  const selectedNode = selectedNodeId ? (nodeMap.get(selectedNodeId) || null) : null;

  // Directly connected neighbors
  const { activeNodeIds, activeEdgeIds } = useMemo(() => {
    const aNodeIds = new Set();
    const aEdgeIds = new Set();
    if (selectedNodeId) {
      aNodeIds.add(selectedNodeId);
      edges.forEach(e => {
        if (e.source === selectedNodeId || e.target === selectedNodeId) {
          aNodeIds.add(e.source);
          aNodeIds.add(e.target);
          aEdgeIds.add(`edge-${e.source}-${e.target}`);
        }
      });
    }
    return { activeNodeIds: aNodeIds, activeEdgeIds: aEdgeIds };
  }, [selectedNodeId, edges]);

  return (
    <div className={`main-grid ${selectedNode ? 'has-selection' : ''}`} style={{ flexShrink: 0 }}>
      <div className="panel-card map-panel">
        <div className="panel-header">
          <div>
            <h3>Investigation Map</h3>
            <p>Explore the relationships between evidence, users, devices, and network activity.</p>
          </div>
          <div className="panel-actions">
            <button className="btn btn-primary">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
              Graph View
            </button>
            {!isAnalyst && (
              <button className="btn btn-outline" onClick={() => navigate('/timeline')}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                Timeline View
              </button>
            )}
          </div>
        </div>

        <div className="graph-container" onClick={() => setSelectedNodeId(null)}>
          <div className="graph-legend">
            <div className="legend-item"><div className="legend-dot legend-evidence"></div> Evidence</div>
            <div className="legend-item"><div className="legend-dot legend-device"></div> Device</div>
            <div className="legend-item"><div className="legend-dot legend-user"></div> User</div>
            <div className="legend-item"><div className="legend-dot legend-process"></div> Process</div>
            <div className="legend-item"><div className="legend-dot legend-network"></div> Network</div>
            <div className="legend-item"><div className="legend-dot legend-finding"></div> Finding</div>
            {isGraphPartial && (
              <div className="legend-item" style={{ color: 'var(--orange)', fontWeight: 600 }}>
                • Showing 50 correlated findings
              </div>
            )}
          </div>

          <div className="graph-controls" onClick={(e) => e.stopPropagation()}>
            <button className="btn btn-icon" onClick={() => setScale(s => Math.min(s + 0.2, 2.5))}><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg></button>
            <button className="btn btn-icon" onClick={() => setScale(s => Math.max(s - 0.2, 0.4))}><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="5" y1="12" x2="19" y2="12"></line></svg></button>
            <button className="btn btn-outline" onClick={() => { setScale(1.0); setSelectedNodeId(null); }} style={{ background: 'var(--bg-card)' }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ marginRight: '6px' }}><polyline points="8 3 3 3 3 8"></polyline><polyline points="16 3 21 3 21 8"></polyline><polyline points="8 21 3 21 3 16"></polyline><polyline points="16 21 21 21 21 16"></polyline></svg>
              <span>Fit View</span>
            </button>
          </div>

          {/* SVG Canvas for Edges */}
          <svg className="graph-svg" viewBox="0 0 1000 600" style={{ transform: `scale(${scale})`, transformOrigin: 'center center', transition: 'transform 0.3s ease' }}>
            <defs>
              <marker id="arrow" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--border-strong)" />
              </marker>
              <marker id="arrow-blue" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--blue)" />
              </marker>
              <marker id="arrow-teal" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--teal)" />
              </marker>
              <marker id="arrow-purple" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--purple)" />
              </marker>
              <marker id="arrow-orange" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--orange)" />
              </marker>
              <marker id="arrow-red" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--red)" />
              </marker>
            </defs>

            {edges.map((edge, idx) => {
              const srcNode = nodeMap.get(edge.source);
              const tgtNode = nodeMap.get(edge.target);
              if (!srcNode || !tgtNode) return null;

              const x1 = srcNode.x * 10;
              const y1 = srcNode.y * 6;
              const x2 = tgtNode.x * 10;
              const y2 = tgtNode.y * 6;

              const dx = x2 - x1;
              const dy = y2 - y1;
              const cx = x1 + dx * 0.5 - dy * 0.2;
              const cy = y1 + dy * 0.5 + dx * 0.2;
              const pathData = `M ${x1} ${y1} Q ${cx} ${cy} ${x2} ${y2}`;

              const edgeId = `edge-${edge.source}-${edge.target}-${idx}`;
              const isHighlighted = activeEdgeIds.has(`edge-${edge.source}-${edge.target}`);
              const isDimmed = selectedNodeId && !isHighlighted;

              let markerName = 'arrow';
              if (edge.color === 'var(--blue)') markerName = 'arrow-blue';
              if (edge.color === 'var(--teal)') markerName = 'arrow-teal';
              if (edge.color === 'var(--purple)') markerName = 'arrow-purple';
              if (edge.color === 'var(--orange)') markerName = 'arrow-orange';
              if (edge.color === 'var(--red)') markerName = 'arrow-red';

              return (
                <g key={edgeId}>
                  <path
                    d={pathData}
                    stroke={edge.color || 'var(--border-strong)'}
                    strokeWidth={isHighlighted ? '4' : '2.5'}
                    fill="none"
                    opacity={isDimmed ? '0.2' : (isHighlighted ? '1' : '0.6')}
                    markerEnd={`url(#${markerName})`}
                    style={{ transition: 'all 0.3s ease' }}
                  />
                </g>
              );
            })}
          </svg>

          {/* HTML Overlay for Nodes */}
          <div className="graph-html" style={{ transform: `scale(${scale})`, transformOrigin: 'center center', transition: 'transform 0.3s ease' }}>
            {loading ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)' }}>
                Loading forensic graph...
              </div>
            ) : nodes.length === 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', fontWeight: 500, fontSize: '14px', padding: '40px', textAlign: 'center' }}>
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ marginBottom: '12px', opacity: 0.5 }}><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                <div style={{ fontWeight: 600, marginBottom: '4px' }}>No Graph Data Available</div>
                <div style={{ fontSize: '13px', maxWidth: '320px' }}>Upload evidence artifacts to generate findings and view the execution graph.</div>
              </div>
            ) : (
              nodes.map(node => {
                const isSelected = selectedNodeId === node.id;
                const isDimmed = selectedNodeId && !activeNodeIds.has(node.id);
                let nodeClass = `node node-type-${node.type} ${node.critical ? 'node-critical' : ''}`;
                if (isSelected) nodeClass += ' selected';
                else if (isDimmed) nodeClass += ' dimmed';

                let borderColor = 'var(--border-strong)';
                if (node.type === 'device') borderColor = 'var(--teal)';
                else if (node.type === 'user') borderColor = 'var(--purple)';
                else if (node.type === 'network') borderColor = 'var(--cyan)';
                else if (node.type === 'finding') borderColor = 'var(--red)';
                else if (node.type === 'evidence') borderColor = 'var(--blue)';
                else if (node.type === 'process') borderColor = 'var(--orange)';

                return (
                  <div
                    key={node.id}
                    className={nodeClass}
                    style={{ left: `${node.x}%`, top: `${node.y}%` }}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedNodeId(node.id);
                    }}
                  >
                    <div className="node-circle" style={{ borderColor, color: borderColor }}>
                      {ICONS[node.type] || ICONS.finding}
                    </div>
                    <div className="node-label">
                      <strong>{node.label}</strong>
                      <span>{node.sublabel}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* Node Details Panel */}
      <aside className="details-panel">
        <div className="panel-header">
          <h3>Node Details</h3>
          <div className="panel-actions">
            {selectedNode && (
              <button
                className="close-details-btn"
                title="Close Details"
                aria-label="Close Details"
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  setSelectedNodeId(null);
                }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            )}
          </div>
        </div>

        {selectedNode ? (
          <div className="details-content">
            <div className="details-header">
              <div className="details-icon" style={{ borderColor: selectedNode.details.badgeColor, color: selectedNode.details.badgeColor, backgroundColor: selectedNode.details.badgeBg }}>
                {ICONS[selectedNode.type] || ICONS.finding}
              </div>
              <div className="details-title-wrap">
                <div className="details-heading-line">
                  <h4 title={selectedNode.details.title}>{selectedNode.details.title}</h4>
                  <span className="details-badge" style={{ backgroundColor: selectedNode.details.badgeBg, color: selectedNode.details.badgeColor }}>
                    {selectedNode.details.badge}
                  </span>
                </div>
                <p>{selectedNode.details.subtitle}</p>
              </div>
            </div>

            <div className="details-tabs">
              <div className="tab active">Overview</div>
            </div>

            <p className="details-desc">{selectedNode.details.desc}</p>

            <div className="details-list">
              {selectedNode.details.list.map((item, idx) => (
                <div key={idx} className="details-row">
                  <span>{item.k}</span>
                  <span style={item.color ? { color: item.color } : {}}>{item.v}</span>
                </div>
              ))}
            </div>

            <div className="risk-score-wrap">
              <div className="risk-header">
                <span>Risk Score</span>
                <strong>{selectedNode.details.risk} / 100</strong>
              </div>
              <div className="risk-bar-bg">
                <div className="risk-bar-fill" style={{ width: `${selectedNode.details.risk}%`, backgroundColor: selectedNode.details.badgeColor }}></div>
              </div>
            </div>

            {!isAnalyst && (
              <button
                className="btn btn-outline"
                onClick={() => navigate('/timeline')}
                style={{ width: '100%', justifyContent: 'center', color: 'var(--blue)', borderColor: 'var(--blue-light)', marginTop: 'auto' }}
              >
                View in Timeline →
              </button>
            )}
          </div>
        ) : (
          <div style={{ padding: '32px 24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '14px' }}>
            Click on any graph node to inspect details and risk breakdown.
          </div>
        )}
      </aside>
    </div>
  );
}

function evidenceListToNodes(evidenceList, nodes, evidenceMap) {
  evidenceList.forEach((ev, idx) => {
    const evId = String(ev.id || ev.evidence_id || `evidence-${idx}`);
    const evName = String(ev.filename || evId);
    const evNodeId = `ev-${idx}`;

    // Map canonical ID first
    evidenceMap.set(evId.toLowerCase(), evNodeId);
    if (ev.id) evidenceMap.set(String(ev.id).toLowerCase(), evNodeId);
    if (ev.evidence_id) evidenceMap.set(String(ev.evidence_id).toLowerCase(), evNodeId);
    // Filename fallback (only if not already registered)
    if (ev.filename) {
      const fnKey = String(ev.filename).toLowerCase();
      if (!evidenceMap.has(fnKey)) {
        evidenceMap.set(fnKey, evNodeId);
      }
    }

    nodes.push({
      id: evNodeId,
      type: 'evidence',
      label: evName,
      sublabel: ev.status ? `Status: ${ev.status}` : 'Artifact',
      critical: false,
      details: {
        title: evName,
        subtitle: 'Evidence · Artifact',
        desc: `Uploaded file artifact. Status: ${ev.status || 'processed'}.`,
        badge: 'Evidence',
        badgeColor: 'var(--blue)',
        badgeBg: 'var(--blue-light)',
        list: [
          { k: 'Filename', v: evName },
          { k: 'Status', v: ev.status || 'N/A' },
          { k: 'Type', v: ev.type || 'File' }
        ],
        risk: 50
      }
    });
  });
}

function buildAgentDrivenGraph(findings, agentData, nodes, edges, evidenceMap) {
  const findingMap = new Map();
  const agent2Signals = agentData?.agent2?.signals || {};
  const agentRels = agent2Signals.relationships || [];
  const claims = agentData?.claims || [];

  // Extract set of finding IDs actually cited or correlated by the agents
  const relevantFindingIds = new Set();
  agentRels.forEach(r => {
    if (r.source) relevantFindingIds.add(String(r.source));
    if (r.target) relevantFindingIds.add(String(r.target));
  });
  claims.forEach(c => {
    (c.evidence_ids || []).forEach(id => relevantFindingIds.add(String(id)));
    (c.cited_evidence_ids || []).forEach(id => relevantFindingIds.add(String(id)));
  });

  // Filter to findings evaluated by the agents
  const candidateFindings = relevantFindingIds.size > 0
    ? findings.filter(f => relevantFindingIds.has(String(f.finding_id || f.id)))
    : findings.slice(0, 12);

  candidateFindings.forEach((f, idx) => {
    const fId = f.finding_id || f.id || `f-${idx}`;
    findingMap.set(fId, f);
    const layer = (f.layer || 'finding').toLowerCase();
    const nodeType = ['device', 'user', 'network', 'process', 'evidence'].includes(layer) ? layer : 'finding';
    const sev = (f.severity || 'medium').toLowerCase();
    const isCritical = sev === 'critical' || sev === 'high';
    const conf = Math.round((f.confidence > 1 ? f.confidence : f.confidence * 100) || 75);

    nodes.push({
      id: fId,
      type: nodeType,
      label: f.fact ? (f.fact.length > 30 ? f.fact.substring(0, 27) + '...' : f.fact) : fId,
      sublabel: `${sev.toUpperCase()} · ${conf}% conf`,
      critical: isCritical,
      details: {
        title: f.fact || fId,
        subtitle: `Finding · ${f.layer ? f.layer.toUpperCase() : 'GENERAL'}`,
        desc: f.fact || 'No description recorded.',
        badge: sev.toUpperCase(),
        badgeColor: isCritical ? 'var(--red)' : (sev === 'medium' ? 'var(--orange)' : 'var(--blue)'),
        badgeBg: isCritical ? 'var(--red-light)' : (sev === 'medium' ? 'var(--orange-light)' : 'var(--blue-light)'),
        list: [
          { k: 'Finding ID', v: fId },
          { k: 'Layer', v: f.layer || 'N/A' },
          { k: 'MITRE Mapping', v: f.mitre_mapping || 'None' },
          { k: 'Evidence Reference', v: f.evidence_reference || 'N/A' }
        ],
        risk: conf
      }
    });

    const evRefs = Array.isArray(f.evidence_reference)
      ? f.evidence_reference
      : (f.evidence_reference ? [f.evidence_reference] : []);
    evRefs.forEach(ref => {
      if (typeof ref === 'string') {
        const cleanRef = ref.replace(/^ref:/i, '').trim().toLowerCase();
        const targetEvNodeId = evidenceMap.get(cleanRef) || evidenceMap.get(ref.toLowerCase());
        if (targetEvNodeId) {
          edges.push({
            source: fId,
            target: targetEvNodeId,
            label: 'derived from',
            color: 'var(--blue)'
          });
        }
      }
    });
  });

  // Real Agent 2 deterministic relationships
  agentRels.forEach(rel => {
    if (rel.source && rel.target && findingMap.has(rel.source) && findingMap.has(rel.target)) {
      edges.push({
        source: rel.source,
        target: rel.target,
        label: rel.relationship_type || 'correlated with',
        color: 'var(--purple)'
      });
    }
  });

  // Real Claim co-citations: connect findings proved to belong to the same attack claim
  claims.forEach(c => {
    const fIds = (c.evidence_ids || []).filter(id => findingMap.has(id));
    for (let i = 0; i < fIds.length - 1; i++) {
      edges.push({
        source: fIds[i],
        target: fIds[i + 1],
        label: c.agent_id ? `${c.agent_id} correlation` : 'correlated with',
        color: 'var(--orange)'
      });
    }
  });
}

function positionGraphNodes(nodes, edges) {
  const total = nodes.length;
  if (total === 0) return;
  if (total === 1) {
    nodes[0].x = 50;
    nodes[0].y = 50;
    return;
  }

  const evidenceNodes = nodes.filter(n => n.type === 'evidence');
  const otherNodes = nodes.filter(n => n.type !== 'evidence');

  if (evidenceNodes.length > 0) {
    evidenceNodes.forEach((n, i) => {
      n.x = Math.round(20 + (60 / Math.max(1, evidenceNodes.length - 1)) * i);
      n.y = otherNodes.length === 0 ? 50 : 20;
    });
  }

  if (otherNodes.length > 0) {
    const centerX = 50;
    const centerY = evidenceNodes.length === 0 ? 50 : 58;
    const useMultiRing = otherNodes.length > 12;

    otherNodes.forEach((n, i) => {
      const angle = (2 * Math.PI * i) / otherNodes.length;
      let radiusX = 35;
      let radiusY = 28;

      if (useMultiRing) {
        const isOuter = i % 2 === 1;
        radiusX = isOuter ? 38 : 24;
        radiusY = isOuter ? 30 : 19;
      }

      n.x = Math.round(centerX + radiusX * Math.cos(angle));
      n.y = Math.round(centerY + radiusY * Math.sin(angle));
    });
  }
}
