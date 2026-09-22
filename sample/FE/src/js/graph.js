// ARGUS Interactive Forensic Knowledge Graph Engine
class ForensicKnowledgeGraph {
  constructor(canvasId, options = {}) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.options = Object.assign({
      onNodeSelect: null,
      particleSpeed: 0.005,
      nodeRadius: 24,
      nodeSpacing: 1.2
    }, options);

    this.nodes = [];
    this.edges = [];
    this.particles = [];
    this.selectedNode = null;
    this.hoveredNode = null;
    this.isDragging = false;
    this.dragNode = null;
    this.dragOffset = { x: 0, y: 0 };
    this.scale = 1;
    this.offset = { x: 0, y: 0 };
    this.isPanning = false;
    this.panStart = { x: 0, y: 0 };

    this.init();
  }

  init() {
    this.resize();
    window.addEventListener('resize', () => this.resize());
    this.bindEvents();
    this.loadData();
    this.animate();
  }

  resize() {
    if (!this.canvas) return;
    const rect = this.canvas.parentElement.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    this.canvas.width = rect.width * dpr;
    this.canvas.height = (rect.height || 420) * dpr;
    this.ctx.scale(dpr, dpr);
    this.width = rect.width;
    this.height = rect.height || 420;
    this.centerGraph();
  }

  loadData() {
    if (!window.ARGUS_DATA || !window.ARGUS_DATA.graphData) return;
    const rawData = window.ARGUS_DATA.graphData;
    
    // Normalize coordinates based on canvas dimension
    const w = this.width || 800;
    const h = this.height || 420;

    this.nodes = rawData.nodes.map((n, i) => {
      return {
        ...n,
        x: n.x ? (n.x / 1000) * w * 0.9 + 50 : Math.cos(i * (Math.PI * 2 / rawData.nodes.length)) * 180 + w / 2,
        y: n.y ? (n.y / 400) * h * 0.8 + 40 : Math.sin(i * (Math.PI * 2 / rawData.nodes.length)) * 140 + h / 2,
        radius: 20,
        pulse: Math.random() * Math.PI * 2
      };
    });

    this.edges = rawData.edges.map(e => {
      const source = this.nodes.find(n => n.id === e.source);
      const target = this.nodes.find(n => n.id === e.target);
      return {
        ...e,
        sourceNode: source,
        targetNode: target
      };
    }).filter(e => e.sourceNode && e.targetNode);

    // Create moving particles along edges
    this.particles = [];
    this.edges.forEach((edge, idx) => {
      for (let i = 0; i < 2; i++) {
        this.particles.push({
          edge: edge,
          progress: (i * 0.5 + Math.random() * 0.2) % 1,
          speed: 0.003 + Math.random() * 0.003,
          color: edge.sourceNode.color || '#00f0ff'
        });
      }
    });
  }

  centerGraph() {
    if (this.nodes.length === 0) return;
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    this.nodes.forEach(n => {
      if (n.x < minX) minX = n.x;
      if (n.x > maxX) maxX = n.x;
      if (n.y < minY) minY = n.y;
      if (n.y > maxY) maxY = n.y;
    });
    const centerX = (minX + maxX) / 2;
    const centerY = (minY + maxY) / 2;
    const dx = (this.width / 2) - centerX;
    const dy = (this.height / 2) - centerY;
    this.nodes.forEach(n => {
      n.x += dx * 0.2;
      n.y += dy * 0.2;
    });
  }

  bindEvents() {
    const getPos = (e) => {
      const rect = this.canvas.getBoundingClientRect();
      return {
        x: (e.clientX - rect.left - this.offset.x) / this.scale,
        y: (e.clientY - rect.top - this.offset.y) / this.scale
      };
    };

    this.canvas.addEventListener('mousedown', (e) => {
      const pos = getPos(e);
      const clickedNode = this.nodes.find(n => {
        const dist = Math.hypot(n.x - pos.x, n.y - pos.y);
        return dist <= n.radius + 8;
      });

      if (clickedNode) {
        this.isDragging = true;
        this.dragNode = clickedNode;
        this.selectedNode = clickedNode;
        this.dragOffset = { x: clickedNode.x - pos.x, y: clickedNode.y - pos.y };
        if (this.options.onNodeSelect) this.options.onNodeSelect(clickedNode);
      } else {
        this.isPanning = true;
        this.panStart = { x: e.clientX - this.offset.x, y: e.clientY - this.offset.y };
      }
    });

    window.addEventListener('mousemove', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      if (e.clientX < rect.left || e.clientX > rect.right || e.clientY < rect.top || e.clientY > rect.bottom) {
        if (!this.isDragging && !this.isPanning) return;
      }
      const pos = getPos(e);

      if (this.isDragging && this.dragNode) {
        this.dragNode.x = pos.x + this.dragOffset.x;
        this.dragNode.y = pos.y + this.dragOffset.y;
      } else if (this.isPanning) {
        this.offset.x = e.clientX - this.panStart.x;
        this.offset.y = e.clientY - this.panStart.y;
      } else {
        const hover = this.nodes.find(n => Math.hypot(n.x - pos.x, n.y - pos.y) <= n.radius + 6);
        this.hoveredNode = hover || null;
        this.canvas.style.cursor = hover ? 'pointer' : 'grab';
      }
    });

    window.addEventListener('mouseup', () => {
      this.isDragging = false;
      this.dragNode = null;
      this.isPanning = false;
    });

    this.canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
      const newScale = Math.min(Math.max(this.scale * zoomFactor, 0.6), 2.2);
      this.scale = newScale;
    }, { passive: false });
  }

  zoomIn() {
    this.scale = Math.min(this.scale * 1.2, 2.2);
  }

  zoomOut() {
    this.scale = Math.max(this.scale * 0.8, 0.6);
  }

  resetView() {
    this.scale = 1;
    this.offset = { x: 0, y: 0 };
    this.centerGraph();
  }

  getNodeIcon(type) {
    switch (type) {
      case 'user': return '👤';
      case 'email': return '✉️';
      case 'file': return '📄';
      case 'process': return '⚙️';
      case 'registry': return '🔑';
      case 'ip': return '🌐';
      case 'host': return '🖥️';
      default: return '📍';
    }
  }

  draw() {
    this.ctx.clearRect(0, 0, this.width, this.height);
    this.ctx.save();

    // Pan & Zoom transform
    this.ctx.translate(this.offset.x, this.offset.y);
    this.ctx.scale(this.scale, this.scale);

    // Draw cyber grid background inside canvas
    this.drawGrid();

    // Check if graph data is newly available or was cleared
    if (!window.ARGUS_DATA || !window.ARGUS_DATA.graphData) {
      this.nodes = [];
      this.edges = [];
      this.particles = [];
      this.ctx.font = '13px "Inter", sans-serif';
      this.ctx.fillStyle = 'rgba(148, 163, 184, 0.5)';
      this.ctx.textAlign = 'center';
      this.ctx.fillText('Awaiting forensic analysis — Attack graph will render when investigation executes.', this.width / 2, this.height / 2);
      this.ctx.restore();
      return;
    } else if (this.nodes.length === 0 && window.ARGUS_DATA.graphData) {
      this.loadData();
    }

    // 1. Draw Edges
    this.edges.forEach(edge => {
      const s = edge.sourceNode;
      const t = edge.targetNode;
      if (!s || !t) return;

      const isConnectedToSelected = this.selectedNode && (s.id === this.selectedNode.id || t.id === this.selectedNode.id);
      const isConnectedToHover = this.hoveredNode && (s.id === this.hoveredNode.id || t.id === this.hoveredNode.id);
      const isHighlighted = isConnectedToSelected || isConnectedToHover;

      this.ctx.beginPath();
      this.ctx.moveTo(s.x, s.y);
      this.ctx.lineTo(t.x, t.y);
      this.ctx.strokeStyle = isHighlighted ? 'rgba(0, 240, 255, 0.7)' : 'rgba(255, 255, 255, 0.12)';
      this.ctx.lineWidth = isHighlighted ? 2.5 : 1.2;
      if (isHighlighted) {
        this.ctx.shadowColor = '#00f0ff';
        this.ctx.shadowBlur = 8;
      } else {
        this.ctx.shadowBlur = 0;
      }
      this.ctx.stroke();
      this.ctx.shadowBlur = 0;

      // Draw edge label
      const midX = (s.x + t.x) / 2;
      const midY = (s.y + t.y) / 2;
      this.ctx.font = '10px "JetBrains Mono", monospace';
      this.ctx.fillStyle = isHighlighted ? '#00f0ff' : 'rgba(148, 163, 184, 0.75)';
      this.ctx.textAlign = 'center';
      this.ctx.fillText(edge.label, midX, midY - 6);
    });

    // 2. Draw Moving Data Flow Particles
    this.particles.forEach(p => {
      p.progress += p.speed;
      if (p.progress > 1) p.progress = 0;

      const s = p.edge.sourceNode;
      const t = p.edge.targetNode;
      if (!s || !t) return;

      const curX = s.x + (t.x - s.x) * p.progress;
      const curY = s.y + (t.y - s.y) * p.progress;

      this.ctx.beginPath();
      this.ctx.arc(curX, curY, 3, 0, Math.PI * 2);
      this.ctx.fillStyle = p.color;
      this.ctx.shadowColor = p.color;
      this.ctx.shadowBlur = 8;
      this.ctx.fill();
      this.ctx.shadowBlur = 0;
    });

    // 3. Draw Nodes
    this.nodes.forEach(node => {
      const isSelected = this.selectedNode && this.selectedNode.id === node.id;
      const isHovered = this.hoveredNode && this.hoveredNode.id === node.id;
      node.pulse += 0.04;

      // Outer glow circle
      if (isSelected || isHovered) {
        this.ctx.beginPath();
        const pulseSize = node.radius + (Math.sin(node.pulse) * 3 + 8);
        this.ctx.arc(node.x, node.y, pulseSize, 0, Math.PI * 2);
        this.ctx.strokeStyle = node.color || '#00f0ff';
        this.ctx.lineWidth = 2;
        this.ctx.shadowColor = node.color || '#00f0ff';
        this.ctx.shadowBlur = 16;
        this.ctx.stroke();
        this.ctx.shadowBlur = 0;
      }

      // Base Node Background
      const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
      this.ctx.beginPath();
      this.ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      this.ctx.fillStyle = isDark ? '#17233A' : '#0f172a';
      this.ctx.fill();
      this.ctx.strokeStyle = isSelected && isDark ? '#3B82F6' : (node.color || '#00f0ff');
      this.ctx.lineWidth = isSelected ? 3 : 2;
      this.ctx.stroke();

      // Node Icon / Emoji
      this.ctx.font = '14px sans-serif';
      this.ctx.textAlign = 'center';
      this.ctx.textBaseline = 'middle';
      this.ctx.fillText(this.getNodeIcon(node.type), node.x, node.y + 1);

      // Node Label
      this.ctx.font = isSelected ? 'bold 11px "Inter", sans-serif' : '11px "Inter", sans-serif';
      this.ctx.fillStyle = isSelected ? (isDark ? '#E6EDF7' : '#ffffff') : (isDark ? '#E6EDF7' : '#cbd5e1');
      this.ctx.textAlign = 'center';
      this.ctx.fillText(node.label, node.x, node.y + node.radius + 14);

      // Role subtitle
      this.ctx.font = '9px "JetBrains Mono", monospace';
      this.ctx.fillStyle = isDark ? '#94A3B8' : 'rgba(148, 163, 184, 0.7)';
      this.ctx.fillText(node.type.toUpperCase(), node.x, node.y + node.radius + 25);
    });

    this.ctx.restore();
  }

  drawGrid() {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const step = 40;
    this.ctx.strokeStyle = isDark ? 'rgba(38, 54, 80, 0.4)' : 'rgba(255, 255, 255, 0.02)';
    this.ctx.lineWidth = 1;

    const startX = -this.offset.x / this.scale;
    const startY = -this.offset.y / this.scale;
    const endX = (this.width - this.offset.x) / this.scale;
    const endY = (this.height - this.offset.y) / this.scale;

    this.ctx.beginPath();
    for (let x = Math.floor(startX / step) * step; x < endX; x += step) {
      this.ctx.moveTo(x, startY);
      this.ctx.lineTo(x, endY);
    }
    for (let y = Math.floor(startY / step) * step; y < endY; y += step) {
      this.ctx.moveTo(startX, y);
      this.ctx.lineTo(endX, y);
    }
    this.ctx.stroke();
  }

  animate() {
    this.draw();
    requestAnimationFrame(() => this.animate());
  }
}

window.ForensicKnowledgeGraph = ForensicKnowledgeGraph;
