// ==========================================================================
// ARGUS - Digital Forensics Interactive Graph Engine
// ==========================================================================

class ArgusGraphRenderer {
  constructor() {
    this.nodes = [
      {
        id: 'n1', type: 'finding', label: 'Suspicious Login', sublabel: 'Initial Access',
        x: 50, y: 50,
        icon: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>',
        critical: true,
        details: {
          title: 'Suspicious Login', subtitle: 'Event · Initial Access',
          desc: 'Unusual login behavior detected, indicating possible credential compromise and use of automated tools.',
          badge: 'High Risk', badgeColor: 'var(--red)', badgeBg: 'var(--red-light)',
          list: [
            { k: 'Type', v: 'Credential Harvesting' },
            { k: 'First Seen', v: 'Nov 14, 2024 09:32 AM' },
            { k: 'Associated User', v: 'john.doe@company.com' },
            { k: 'Source IP', v: '🇺🇸 185.199.110.23', color: 'var(--blue)' }
          ],
          risk: 92
        }
      },
      {
        id: 'n2', type: 'device', label: 'DESKTOP-7G2K', sublabel: 'Windows 11',
        x: 25, y: 40,
        icon: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>',
        details: {
          title: 'DESKTOP-7G2K', subtitle: 'Device · Workstation',
          desc: 'Corporate workstation assigned to the engineering department. Shows signs of recent unauthorized software execution.',
          badge: 'Compromised', badgeColor: 'var(--teal)', badgeBg: 'var(--teal-light)',
          list: [
            { k: 'Type', v: 'Windows 11' },
            { k: 'First Seen', v: 'Nov 14, 2024 08:15 AM' },
            { k: 'User', v: 'john.doe@company.com' },
            { k: 'IP Address', v: '10.0.4.102' }
          ],
          risk: 45
        }
      },
      {
        id: 'n3', type: 'user', label: 'john.doe@company.com', sublabel: '2 accounts',
        x: 50, y: 20,
        icon: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>',
        details: {
          title: 'John Doe', subtitle: 'User · Engineering Dept',
          desc: 'Senior developer account with access to production environments and code repositories.',
          badge: 'At Risk', badgeColor: 'var(--purple)', badgeBg: 'var(--purple-light)',
          list: [
            { k: 'Type', v: 'Domain User' },
            { k: 'First Seen', v: 'Active' },
            { k: 'User', v: 'john.doe@company.com' },
            { k: 'IP Address', v: 'N/A' }
          ],
          risk: 60
        }
      },
      {
        id: 'n4', type: 'network', label: '185.199.110.23', sublabel: '2 connections',
        x: 76, y: 37,
        icon: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>',
        details: {
          title: '185.199.110.23', subtitle: 'Network · External IP',
          desc: 'Known tor exit node or proxy IP associated with credential stuffing attacks in the past 30 days.',
          badge: 'Malicious', badgeColor: 'var(--cyan)', badgeBg: 'var(--cyan-light)',
          list: [
            { k: 'Type', v: 'External IP' },
            { k: 'First Seen', v: 'Nov 14, 2024 09:32 AM' },
            { k: 'User', v: 'N/A' },
            { k: 'IP Address', v: '185.199.110.23' }
          ],
          risk: 85
        }
      },
      {
        id: 'n5', type: 'finding', label: 'Credential Harvesting', sublabel: 'High Confidence',
        x: 76, y: 63,
        icon: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>',
        details: {
          title: 'Credential Harvesting', subtitle: 'Finding · Discovery',
          desc: 'Automated script attempting to dump LSASS memory to extract plaintext credentials.',
          badge: 'Critical', badgeColor: 'var(--red)', badgeBg: 'var(--red-light)',
          list: [
            { k: 'Type', v: 'Execution' },
            { k: 'First Seen', v: 'Nov 14, 2024 09:35 AM' },
            { k: 'User', v: 'SYSTEM' },
            { k: 'IP Address', v: 'Local' }
          ],
          risk: 95
        }
      },
      {
        id: 'n6', type: 'process', label: 'powershell.exe', sublabel: '5 related files',
        x: 50, y: 80,
        icon: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>',
        details: {
          title: 'powershell.exe', subtitle: 'Process · Execution',
          desc: 'Executed with bypassed execution policy.',
          badge: 'Suspicious', badgeColor: 'var(--orange)', badgeBg: 'var(--orange-light)',
          list: [
            { k: 'PID', v: '8432' },
            { k: 'Parent Process', v: 'winword.exe' },
            { k: 'Related Files', v: '5' }
          ],
          risk: 75
        }
      },
      {
        id: 'n7', type: 'evidence', label: 'suspicious.ps1', sublabel: '3 detections',
        x: 24, y: 63,
        icon: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>',
        details: {
          title: 'suspicious.ps1', subtitle: 'Evidence · File',
          desc: 'Obfuscated PowerShell script dropped in Temp directory. Contains encoded Base64 commands.',
          badge: 'Evidence', badgeColor: 'var(--blue)', badgeBg: 'var(--blue-light)',
          list: [
            { k: 'Type', v: 'File' },
            { k: 'First Seen', v: 'Nov 14, 2024 09:33 AM' },
            { k: 'User', v: 'john.doe@company.com' },
            { k: 'IP Address', v: 'Local' }
          ],
          risk: 88
        }
      }
    ];

    this.edges = [
      { source: 'n3', target: 'n2', label: 'logged in from', color: 'var(--teal)' },
      { source: 'n2', target: 'n7', label: 'contains', color: 'var(--blue)' },
      { source: 'n7', target: 'n6', label: 'executed by', color: 'var(--orange)' },
      { source: 'n3', target: 'n1', label: 'associated with', color: 'var(--purple)' },
      { source: 'n1', target: 'n4', label: 'connected to', color: 'var(--blue)' },
      { source: 'n1', target: 'n5', label: 'supports', color: 'var(--red)' }
    ];

    this.selectedNodeId = null;
    this.scale = 1.0;
  }

  init() {
    // Add SVG definitions for arrowheads
    const svgContainer = document.getElementById('graph-svg');
    if (svgContainer) {
      svgContainer.innerHTML = `
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
      `;
    }

    this.renderGraph();
    this.bindEvents();
    
    // Select a node by default to show the new deep path highlighting
    setTimeout(() => this.selectNode('n6'), 100);
    
    // Re-render on container resize to fix absolute coordinates even when panel opens
    const container = document.getElementById('graph-container');
    if (container) {
      const resizeObserver = new ResizeObserver(() => {
        this.renderGraph();
        if(this.selectedNodeId) this.selectNode(this.selectedNodeId);
      });
      resizeObserver.observe(container);
    }
  }

  renderGraph() {
    const htmlContainer = document.getElementById('graph-html');
    const svgContainer = document.getElementById('graph-svg');
    
    if (!htmlContainer || !svgContainer) return;

    // Keep defs
    const defs = svgContainer.querySelector('defs');
    svgContainer.innerHTML = '';
    if(defs) svgContainer.appendChild(defs);
    htmlContainer.innerHTML = '';

    const width = svgContainer.clientWidth || 800;
    const height = svgContainer.clientHeight || 600;

    const getX = (p) => (p / 100) * width;
    const getY = (p) => (p / 100) * height;

    // Draw Edges (SVG)
    this.edges.forEach(edge => {
      const source = this.nodes.find(n => n.id === edge.source);
      const target = this.nodes.find(n => n.id === edge.target);
      
      const x1 = getX(source.x);
      const y1 = getY(source.y);
      const x2 = getX(target.x);
      const y2 = getY(target.y);
      
      const midX = (x1 + x2) / 2;
      const midY = (y1 + y2) / 2;
      
      const dx = x2 - x1;
      const dy = y2 - y1;
      const cx = x1 + dx * 0.5 - dy * 0.2;
      const cy = y1 + dy * 0.5 + dx * 0.2;
      
      const pathData = `M ${x1} ${y1} Q ${cx} ${cy} ${x2} ${y2}`;

      // Thick Colored Path
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('id', `edge-${source.id}-${target.id}`);
      path.setAttribute('class', 'edge');
      path.setAttribute('d', pathData);
      path.setAttribute('stroke', edge.color || 'var(--border-strong)');
      path.setAttribute('stroke-width', '2.5');
      path.setAttribute('fill', 'none');
      path.setAttribute('opacity', '0.6');
      
      let markerName = 'arrow';
      if(edge.color === 'var(--blue)') markerName = 'arrow-blue';
      if(edge.color === 'var(--teal)') markerName = 'arrow-teal';
      if(edge.color === 'var(--purple)') markerName = 'arrow-purple';
      if(edge.color === 'var(--orange)') markerName = 'arrow-orange';
      if(edge.color === 'var(--red)') markerName = 'arrow-red';
      
      path.setAttribute('marker-end', `url(#${markerName})`);
      svgContainer.appendChild(path);

      // Animated Dot (hidden by default)
      const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      dot.setAttribute('id', `dot-${source.id}-${target.id}`);
      dot.setAttribute('r', '4');
      dot.setAttribute('fill', edge.color || 'var(--blue)');
      dot.style.display = 'none';
      
      const animate = document.createElementNS('http://www.w3.org/2000/svg', 'animateMotion');
      animate.setAttribute('dur', '2s');
      animate.setAttribute('repeatCount', 'indefinite');
      animate.setAttribute('path', pathData);
      dot.appendChild(animate);
      svgContainer.appendChild(dot);
      
      // Draw HTML Label (pill style)
      const labelX = (x1 + 2 * cx + x2) / 4;
      const labelY = (y1 + 2 * cy + y2) / 4;
      
      const labelEl = document.createElement('div');
      labelEl.className = 'edge-label';
      labelEl.id = `label-${source.id}-${target.id}`;
      labelEl.textContent = edge.label;
      labelEl.style.left = `${labelX}px`;
      labelEl.style.top = `${labelY}px`;
      labelEl.style.color = edge.color || 'var(--text-main)';
      labelEl.style.borderColor = edge.color || 'var(--border-subtle)';
      htmlContainer.appendChild(labelEl);
    });

    // Draw Nodes (HTML)
    this.nodes.forEach(node => {
      const el = document.createElement('div');
      el.className = `node node-type-${node.type} ${node.critical ? 'node-critical' : ''}`;
      el.id = `node-${node.id}`;
      el.style.left = `${getX(node.x)}px`;
      el.style.top = `${getY(node.y)}px`;
      
      // Assign border colors directly for default view
      let borderColor = 'var(--border-strong)';
      if(node.type === 'device') borderColor = 'var(--teal)';
      else if(node.type === 'user') borderColor = 'var(--purple)';
      else if(node.type === 'network') borderColor = 'var(--cyan)';
      else if(node.type === 'finding') borderColor = 'var(--red)';
      else if(node.type === 'evidence') borderColor = 'var(--blue)';
      else if(node.type === 'process') borderColor = 'var(--orange)';

      el.innerHTML = `
        <div class="node-circle" style="border-color: ${borderColor}; color: ${borderColor}">${node.icon}</div>
        <div class="node-label">
          <strong>${node.label}</strong>
          <span>${node.sublabel}</span>
        </div>
      `;
      
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        this.selectNode(node.id);
      });
      
      htmlContainer.appendChild(el);
    });

    // Reset selection on background click
    document.getElementById('graph-container').addEventListener('click', () => {
      this.clearSelection();
    });
  }

  selectNode(nodeId) {
    this.selectedNodeId = nodeId;
    
    const activeNodes = new Set([nodeId]);
    const activeEdges = new Set();
    
    // Highlight directly connected neighbors
    this.edges.forEach(edge => {
      if(edge.source === nodeId || edge.target === nodeId) {
        activeNodes.add(edge.source);
        activeNodes.add(edge.target);
        activeEdges.add(`edge-${edge.source}-${edge.target}`);
      }
    });

    // Update Node Classes
    this.nodes.forEach(node => {
      const el = document.getElementById(`node-${node.id}`);
      if (!el) return;
      
      let baseClass = `node node-type-${node.type} ${node.critical ? 'node-critical' : ''}`;
      if (node.id === nodeId) {
        el.className = `${baseClass} selected`;
      } else if (activeNodes.has(node.id)) {
        el.className = baseClass;
      } else {
        el.className = `${baseClass} dimmed`;
      }
    });

    // Update Edge and Label Classes
    this.edges.forEach(edge => {
      const pathId = `edge-${edge.source}-${edge.target}`;
      const path = document.getElementById(pathId);
      const label = document.getElementById(`label-${edge.source}-${edge.target}`);
      const dot = document.getElementById(`dot-${edge.source}-${edge.target}`);
      
      if (activeEdges.has(pathId)) {
        if(path) {
          path.classList.add('highlighted');
          path.classList.remove('dimmed');
          path.setAttribute('opacity', '1');
          path.setAttribute('stroke-width', '4');
        }
        if(label) {
          label.classList.add('highlighted');
          label.classList.remove('dimmed');
        }
        // Show animated dot
        if(dot) dot.style.display = 'block';
      } else {
        if(path) {
          path.classList.add('dimmed');
          path.classList.remove('highlighted');
          path.setAttribute('opacity', '0.2');
          path.setAttribute('stroke-width', '2.5');
        }
        if(label) {
          label.classList.add('dimmed');
          label.classList.remove('highlighted');
        }
        // Hide animated dot
        if(dot) dot.style.display = 'none';
      }
    });

    this.updateDetailsPanel(nodeId);
  }

  clearSelection() {
    this.selectedNodeId = null;
    this.nodes.forEach(node => {
      let baseClass = `node node-type-${node.type} ${node.critical ? 'node-critical' : ''}`;
      document.getElementById(`node-${node.id}`).className = baseClass;
    });
    this.edges.forEach(edge => {
      const pathId = `edge-${edge.source}-${edge.target}`;
      const path = document.getElementById(pathId);
      const label = document.getElementById(`label-${edge.source}-${edge.target}`);
      const dot = document.getElementById(`dot-${edge.source}-${edge.target}`);
      
      if(path) {
        path.classList.remove('highlighted', 'dimmed');
        path.setAttribute('opacity', '0.6');
        path.setAttribute('stroke-width', '2.5');
      }
      
      if(label) label.classList.remove('highlighted', 'dimmed');
      if(dot) dot.style.display = 'none';
    });
    
    const mainGrid = document.getElementById('main-grid');
    if(mainGrid) mainGrid.classList.remove('has-selection');
  }

  updateDetailsPanel(nodeId) {
    const node = this.nodes.find(n => n.id === nodeId);
    if (!node) return;

    const mainGrid = document.getElementById('main-grid');
    if (mainGrid) {
      mainGrid.classList.add('has-selection');
    }

    const iconEl = document.getElementById('details-icon');
    if (!iconEl) return;
    
    iconEl.innerHTML = node.icon;
    iconEl.style.borderColor = node.details.badgeColor;
    iconEl.style.color = node.details.badgeColor;
    iconEl.style.backgroundColor = node.details.badgeBg;

    document.getElementById('details-title').textContent = node.details.title;
    document.getElementById('details-subtitle').textContent = node.details.subtitle;
    document.getElementById('details-desc').textContent = node.details.desc;

    const badgeEl = document.getElementById('details-badge');
    badgeEl.innerHTML = `<div style="background-color: ${node.details.badgeBg}; color: ${node.details.badgeColor}; padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600;">${node.details.badge}</div>`;

    document.getElementById('details-risk-val').textContent = `${node.details.risk} / 100`;
    const riskFill = document.getElementById('details-risk-fill');
    riskFill.style.width = `${node.details.risk}%`;
    riskFill.style.backgroundColor = node.details.badgeColor;

    const listContainer = document.getElementById('details-list');
    listContainer.innerHTML = '';
    node.details.list.forEach(item => {
      listContainer.innerHTML += `
        <div class="details-row">
          <span>${item.k}</span>
          <span style="${item.color ? `color: ${item.color};` : ''}">${item.v}</span>
        </div>
      `;
    });
  }

  bindEvents() {
    const fitBtn = document.getElementById('btn-fit-view');
    const zoomInBtn = document.getElementById('btn-zoom-in');
    const zoomOutBtn = document.getElementById('btn-zoom-out');

    if(fitBtn) {
      this.isFitView = false;
      this.defaultScale = 1.0;
      fitBtn.addEventListener('click', () => {
        this.clearSelection();
        if (this.isFitView) {
          this.setZoom(this.defaultScale);
          this.isFitView = false;
          const label = fitBtn.querySelector('.fit-view-label');
          if (label) label.textContent = ' Fit View';
        } else {
          this.fitToView();
          this.isFitView = true;
          const label = fitBtn.querySelector('.fit-view-label');
          if (label) label.textContent = ' Reset View';
        }
      });
    }
    
    if (zoomInBtn) {
      zoomInBtn.addEventListener('click', () => this.setZoom(this.scale + 0.2));
    }
    
    if (zoomOutBtn) {
      zoomOutBtn.addEventListener('click', () => this.setZoom(this.scale - 0.2));
    }
  }

  fitToView() {
    const container = document.getElementById('graph-container');
    const htmlContainer = document.getElementById('graph-html');
    if (!container || !htmlContainer) return;
    
    const containerRect = container.getBoundingClientRect();
    const nodes = htmlContainer.querySelectorAll('.node');
    if (nodes.length === 0) return;
    
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    nodes.forEach(node => {
      const rect = node.getBoundingClientRect();
      const x = rect.left - containerRect.left + rect.width / 2;
      const y = rect.top - containerRect.top + rect.height / 2;
      minX = Math.min(minX, x);
      minY = Math.min(minY, y);
      maxX = Math.max(maxX, x);
      maxY = Math.max(maxY, y);
    });
    
    const contentWidth = (maxX - minX) + 120;
    const contentHeight = (maxY - minY) + 120;
    const scaleX = containerRect.width / contentWidth;
    const scaleY = containerRect.height / contentHeight;
    const fitScale = Math.min(scaleX, scaleY, 1.5);
    
    this.setZoom(Math.max(0.5, fitScale));
  }

  setZoom(newScale) {
    this.scale = Math.max(0.3, Math.min(newScale, 2.5));
    const svgContainer = document.getElementById('graph-svg');
    const htmlContainer = document.getElementById('graph-html');
    if (svgContainer && htmlContainer) {
      svgContainer.style.transition = 'transform 0.3s ease';
      htmlContainer.style.transition = 'transform 0.3s ease';
      svgContainer.style.transform = `scale(${this.scale})`;
      svgContainer.style.transformOrigin = 'center center';
      htmlContainer.style.transform = `scale(${this.scale})`;
      htmlContainer.style.transformOrigin = 'center center';
    }
  }
}

window.onload = async () => {
  // Check for active case
  const caseId = localStorage.getItem('active_case_id');
  const caseName = localStorage.getItem('active_case_name');
  const caseDesc = localStorage.getItem('active_case_desc');
  
  const activeContent = document.getElementById('dashboard-active-content');
  const emptyState = document.getElementById('dashboard-empty-state');
  
  if (!caseId || caseId === '00000000-0000-0000-0000-000000000001' || (!caseName || caseName === 'Case 00000000')) {
    // Show empty state
    if (activeContent) activeContent.style.display = 'none';
    if (emptyState) emptyState.style.display = 'block';
  } else {
    // Show active case
    if (activeContent) activeContent.style.display = 'flex';
    if (emptyState) emptyState.style.display = 'none';
    
    // Update labels
    const elCaseId = document.getElementById('dashboard-case-id');
    const elCaseName = document.getElementById('dashboard-case-name');
    const elCaseDesc = document.getElementById('dashboard-case-desc');
    
    const formatId = (id) => id.length === 36 && id.includes('-') ? id.substring(0, 8) : id;
    if (elCaseId) elCaseId.textContent = formatId(caseId).toUpperCase();
    if (elCaseName) elCaseName.textContent = caseName;
    if (elCaseDesc) elCaseDesc.textContent = caseDesc || 'No description provided.';

    // Fetch case stats dynamically
    try {
      const response = await fetch(`http://localhost:8000/cases/${caseId}`, {
        headers: { 'X-Tenant-ID': 'dev-team' }
      });
      if (response.ok) {
        const stats = await response.json();
        const findingsResponse = await fetch(`http://localhost:8000/cases/${caseId}/findings`, {
          headers: { 'X-Tenant-ID': 'dev-team' }
        });
        let findingsCount = 0;
        if (findingsResponse.ok) {
          const findings = await findingsResponse.json();
          findingsCount = Array.isArray(findings) ? findings.length : (findings.data ? findings.data.length : 0);
        }

        // Update Stats Cards
        const elEndpoints = document.getElementById('dashboard-stat-endpoints');
        const elUsers = document.getElementById('dashboard-stat-users');
        const elNetwork = document.getElementById('dashboard-stat-network');
        const elFindings = document.getElementById('dashboard-stat-findings');
        
        if (elEndpoints) elEndpoints.textContent = stats.layer_breakdown?.endpoint || 0;
        if (elUsers) elUsers.textContent = stats.layer_breakdown?.auth || 0;
        if (elNetwork) elNetwork.textContent = stats.layer_breakdown?.network || 0;
        if (elFindings) elFindings.textContent = stats.total_findings || 0;

        const steps = document.querySelectorAll('.timeline-step');
        if (steps.length >= 5) {
          // Reset all
          steps.forEach(s => {
            s.classList.remove('step-completed', 'step-active');
            s.querySelector('.step-circle').innerHTML = '';
          });

          let completedCount = 0;
          let currentStepIdx = -1;
          const stageKeys = ['evidence_collection', 'analysis', 'correlation', 'findings', 'report'];
          const invProg = stats.investigation_progress;
          
          if (invProg) {
            stageKeys.forEach((key, idx) => {
              if (invProg[key] === 'completed') {
                completedCount++;
                steps[idx].classList.add('step-completed');
                steps[idx].querySelector('.step-circle').innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
              } else if (invProg[key] === 'in_progress') {
                if (currentStepIdx === -1) currentStepIdx = idx;
              }
            });
            
            if (currentStepIdx !== -1 && currentStepIdx < steps.length) {
              steps[currentStepIdx].classList.add('step-active');
            }
          }

          // Update progress bar
          const progressText = document.getElementById('timeline-progress-text');
          if (progressText) progressText.textContent = `${completedCount} of 5 completed`;
          const progressBar = document.getElementById('timeline-progress-bar');
          if (progressBar) progressBar.style.width = `${(completedCount / 5) * 100}%`;
        }
      }
    } catch (e) {
      console.error('Failed to fetch case progress', e);
    }
  }

  window.argusApp = new ArgusGraphRenderer();
  window.argusApp.init();
};

  
  
  // Toggle Password Visibility
  window.caseManager = window.caseManager || {};
  window.caseManager.togglePasswordVisibility = function(inputId) {
    const input = document.getElementById(inputId);
    const eyeIcon = document.getElementById(inputId + '-eye');
    if (!input || !eyeIcon) return;
    
    if (input.type === 'password') {
      input.type = 'text';
      // Change to crossed-out eye or similar (just using a different stroke color for simplicity)
      eyeIcon.style.color = 'var(--blue)';
    } else {
      input.type = 'password';
      eyeIcon.style.color = 'currentColor';
    }
  };

  // Update Password
  window.caseManager.updatePassword = async function() {
    const currentInput = document.getElementById('cp-current');
    const newInput = document.getElementById('cp-new');
    const confirmInput = document.getElementById('cp-confirm');
    const errorMsg = document.getElementById('cp-error-msg');
    const successMsg = document.getElementById('cp-success-msg');
    const btn = document.getElementById('cp-btn');
    
    const showError = (msg) => {
      if (errorMsg) {
        errorMsg.textContent = msg;
        errorMsg.style.display = 'block';
      } else {
        alert(msg);
      }
      if (successMsg) successMsg.style.display = 'none';
      if (btn) {
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.textContent = 'Update Password';
      }
    };
    
    const showSuccess = (msg) => {
      if (successMsg) {
        successMsg.querySelector('span').textContent = msg || 'Password updated successfully.';
        successMsg.style.display = 'flex';
      } else {
        alert(msg || 'Password updated successfully.');
      }
      if (errorMsg) errorMsg.style.display = 'none';
      if (btn) {
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.textContent = 'Update Password';
      }
      
      // Auto-hide success message after 4 seconds
      setTimeout(() => {
        if (successMsg) successMsg.style.display = 'none';
      }, 4000);
    };
    
    // Clear previous states
    if (errorMsg) errorMsg.style.display = 'none';
    if (successMsg) successMsg.style.display = 'none';
    
    const current = currentInput ? currentInput.value : '';
    const newPass = newInput ? newInput.value : '';
    const confirmPass = confirmInput ? confirmInput.value : '';
    
    if (!current || !newPass || !confirmPass) {
      showError('Please fill out all fields.');
      return;
    }
    
    if (newPass !== confirmPass) {
      showError('Passwords do not match.');
      return;
    }
    
    const token = localStorage.getItem('token');
    if (!token) {
      showError('You must be logged in to update your password.');
      return;
    }
    
    if (btn) {
      btn.disabled = true;
      btn.style.opacity = '0.7';
      btn.textContent = 'Updating...';
    }
    
    try {
      const res = await fetch('http://localhost:8000/auth/update-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({ current_password: current, new_password: newPass })
      });
      
      const data = await res.json();
      
      if (!res.ok) {
        showError(data.detail || 'Failed to update password.');
      } else {
        showSuccess(data.message || 'Password updated successfully.');
        if (currentInput) currentInput.value = '';
        if (newInput) newInput.value = '';
        if (confirmInput) confirmInput.value = '';
      }
    } catch (err) {
      console.error('Error updating password:', err);
      showError('An error occurred. Please try again.');
    }
  };
