import React, { useState, useEffect } from 'react';
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

  useEffect(() => {
    if (!caseId) {
      setNodes([]);
      setEdges([]);
      setSelectedNodeId(null);
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

        const [findingsRes, evidenceRes] = await Promise.all([
          fetch(`${baseUrl}/cases/${caseId}/findings`, { headers }).catch(() => null),
          fetch(`${baseUrl}/evidence/case/${caseId}`, { headers }).catch(() => null)
        ]);

        let rawFindings = [];
        if (findingsRes && findingsRes.ok) {
          const data = await findingsRes.json();
          rawFindings = Array.isArray(data) ? data : (data.data || []);
        }

        let rawEvidence = [];
        if (evidenceRes && evidenceRes.ok) {
          const data = await evidenceRes.json();
          rawEvidence = Array.isArray(data) ? data : (data.data || []);
        }

        if (!isMounted) return;

        const generatedNodes = [];
        const generatedEdges = [];
        const evidenceMap = new Map();

        evidenceListToNodes(rawEvidence, generatedNodes, evidenceMap);
        findingsToNodesAndEdges(rawFindings, generatedNodes, generatedEdges, evidenceMap);

        // Calculate positions
        const total = generatedNodes.length;
        if (total > 0) {
          generatedNodes.forEach((n, i) => {
            const col = i % 4;
            const row = Math.floor(i / 4);
            const maxCols = Math.min(total, 4);
            n.x = maxCols > 1 ? Math.round(15 + (70 / (maxCols - 1)) * col) : 50;
            n.y = total === 1 ? 50 : Math.round(25 + row * 30);
          });
        }

        setNodes(generatedNodes);
        setEdges(generatedEdges);
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
        }
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    loadGraphData();
    return () => { isMounted = false; };
  }, [caseId]);

  const selectedNode = nodes.find(n => n.id === selectedNodeId);

  // Directly connected neighbors
  const activeNodeIds = new Set();
  const activeEdgeIds = new Set();
  if (selectedNodeId) {
    activeNodeIds.add(selectedNodeId);
    edges.forEach(e => {
      if (e.source === selectedNodeId || e.target === selectedNodeId) {
        activeNodeIds.add(e.source);
        activeNodeIds.add(e.target);
        activeEdgeIds.add(`edge-${e.source}-${e.target}`);
      }
    });
  }

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
            <button className="btn btn-outline" onClick={() => navigate('/timeline')}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
              Timeline View
            </button>
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

            {edges.map(edge => {
              const srcNode = nodes.find(n => n.id === edge.source);
              const tgtNode = nodes.find(n => n.id === edge.target);
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

              const edgeId = `edge-${edge.source}-${edge.target}`;
              const isHighlighted = activeEdgeIds.has(edgeId);
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

            <button
              className="btn btn-outline"
              onClick={() => navigate('/timeline')}
              style={{ width: '100%', justifyContent: 'center', color: 'var(--blue)', borderColor: 'var(--blue-light)', marginTop: 'auto' }}
            >
              View in Timeline →
            </button>
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
    const evName = ev.filename || ev.id || `evidence-${idx}`;
    const evNodeId = `ev-${idx}`;
    evidenceMap.set(evName.toLowerCase(), evNodeId);

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

function findingsToNodesAndEdges(findings, nodes, edges, evidenceMap) {
  findings.forEach((f, idx) => {
    const fId = f.finding_id || f.id || `f-${idx}`;
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

    if (f.evidence_reference) {
      const targetEvNodeId = evidenceMap.get(f.evidence_reference.toLowerCase());
      if (targetEvNodeId) {
        edges.push({
          source: fId,
          target: targetEvNodeId,
          label: 'derived from',
          color: 'var(--blue)'
        });
      }
    }

    if (idx > 0) {
      const prevFId = findings[idx - 1].finding_id || findings[idx - 1].id || `f-${idx - 1}`;
      edges.push({
        source: prevFId,
        target: fId,
        label: 'correlated with',
        color: isCritical ? 'var(--red)' : 'var(--orange)'
      });
    }
  });
}
