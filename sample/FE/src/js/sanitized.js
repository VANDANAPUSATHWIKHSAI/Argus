class SanitizedApp {
  constructor() {
    this.findingsData = [];
    this.selectedId = null;
    this.init();
  }

  init() {
    // Basic UI wiring
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id');
    
    // Set active case name and ID from localStorage
    const caseId = localStorage.getItem('active_case_id');
    const caseName = localStorage.getItem('active_case_name');
    const elCaseId = document.getElementById('evidence-case-id');
    const elCaseName = document.getElementById('evidence-case-name');
    
    const formatId = (id) => id.length === 36 && id.includes('-') ? id.substring(0, 8) : id;
    if (elCaseId && caseId) elCaseId.textContent = `Case ${formatId(caseId)}`;
    if (elCaseName && caseName) elCaseName.textContent = caseName;

    if (caseId) {
      this.fetchFindings(caseId);
    }
  }

  async fetchFindings(caseId) {
    try {
      const response = await fetch(`${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}/cases/${caseId}/findings`, {
        headers: { 
          'X-Tenant-ID': 'dev-team',
          'Authorization': `Bearer ${localStorage.getItem('argus_token')}`
        }
      });
      if (!response.ok) throw new Error('Failed to fetch sanitized findings');
      
      const result = await response.json();
      const rawData = Array.isArray(result) ? result : (result.data || []);
      
      this.findingsData = rawData.map((f, i) => {
        // Prefer the full sanitized_context JSON object (set by gateway.sanitize_finding)
        // Fall back gracefully if not present (older API responses)
        const ctx = f.sanitized_context || null;
        return {
          id: f.finding_id || `finding-${i}`,
          // Display text: use sanitized (redacted) fact, not raw fact
          fact: (ctx && ctx.sanitized_fact) || f.sanitized_fact || f.fact || 'No data',
          layer: f.layer || 'Unknown',
          severity: (f.severity || 'info').toLowerCase(),
          confidence: f.confidence || 0.0,
          timestamp: f.timestamp ? new Date(f.timestamp).toLocaleString() : 'N/A',
          evidenceRef: Array.isArray(f.evidence_reference)
            ? f.evidence_reference.join(', ')
            : (f.evidence_reference || 'N/A'),
          injectionFlagged: (ctx && ctx.injection_flagged) || f.injection_flagged || false,
          injectionScore: (ctx && ctx.injection_score) || 0.0,
          sanitizationActions: (ctx && ctx.sanitization_actions) || [],
          redactionMetadata: (ctx && ctx.redaction_metadata) || {},
          xmlEvidenceBlock: (ctx && ctx.xml_evidence_block) || null,
          mitreMapping: (ctx && ctx.mitre_mapping) || f.mitre_mapping || null,
          // Store full context JSON for the details panel display
          sanitizedContext: ctx || {
            finding_id: f.finding_id,
            sanitized_fact: f.sanitized_fact || f.fact,
            injection_flagged: f.injection_flagged || false,
            sanitization_actions: [],
            note: 'sanitized_context not available — upgrade API response'
          }
        };
      });

      this.renderTable();
    } catch (error) {
      console.error('Error fetching sanitized findings:', error);
      const tbody = document.getElementById('sanitized-tbody');
      if (tbody) tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 40px; color: var(--red);">Error loading findings.</td></tr>';
    }
  }

  getSeverityBadge(severity) {
    if (severity === 'critical') return `<span style="background-color: var(--red-light); color: var(--red); padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600;">Critical</span>`;
    if (severity === 'high') return `<span style="background-color: var(--orange-light); color: var(--orange); padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600;">High</span>`;
    if (severity === 'medium') return `<span style="background-color: var(--yellow-light, #fef3c7); color: var(--yellow, #d97706); padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600;">Medium</span>`;
    return `<span style="background-color: var(--blue-light); color: var(--blue); padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600;">Info</span>`;
  }

  getInjectionBadge(flagged) {
    if (flagged) return `<span style="background-color: var(--red-light); color: var(--red); padding: 3px 8px; border-radius: 20px; font-size: 11px; font-weight: 600;">⚠ Injection Detected</span>`;
    return `<span style="background-color: var(--green-light, #e6f6ec); color: var(--green, #10b981); padding: 3px 8px; border-radius: 20px; font-size: 11px; font-weight: 600;">✓ Clean</span>`;
  }

  clearSelection() {
    this.selectedId = null;
    const detailsPanel = document.getElementById('details-panel');
    const mainGrid = document.getElementById('main-grid');
    if (detailsPanel) detailsPanel.style.display = 'none';
    if (mainGrid) mainGrid.style.gridTemplateColumns = '1fr';
    this.renderTable();
  }

  showDetails(item) {
    const detailsPanel = document.getElementById('details-panel');
    const mainGrid = document.getElementById('main-grid');
    
    if (detailsPanel && mainGrid) {
      detailsPanel.style.display = 'flex';
      mainGrid.style.gridTemplateColumns = '1fr 500px';
      
      const title = document.getElementById('details-title');
      const subtitle = document.getElementById('details-subtitle');
      const desc = document.getElementById('details-desc');
      const list = document.getElementById('details-list');
      const badge = document.getElementById('details-badge');
      
      if (title) title.textContent = `Finding: ${item.id}`;
      if (subtitle) subtitle.textContent = `Layer: ${item.layer}`;
      if (badge) badge.innerHTML = this.getSeverityBadge(item.severity) + '&nbsp;' + this.getInjectionBadge(item.injectionFlagged);
      
      // ── Main description: show the sanitized_context as formatted JSON ──
      if (desc) {
        const ctxJson = JSON.stringify(item.sanitizedContext, null, 2);
        desc.innerHTML = `
          <div style="font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.05em;">
            Sanitized Context (stored JSON)
          </div>
          <pre id="sanitized-json-block" style="white-space: pre-wrap; font-family: 'Courier New', monospace; font-size: 11.5px; background: var(--bg-app); padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-strong); max-height: 340px; overflow-y: auto; color: var(--text-main); line-height: 1.6;">${this._syntaxHighlight(ctxJson)}</pre>`;
      }
      
      // ── Metadata rows ──
      if (list) {
        const actions = item.sanitizationActions.length > 0
          ? item.sanitizationActions.map(a => `<code style="background: var(--bg-app); padding: 2px 6px; border-radius: 4px; font-size: 11px;">${a}</code>`).join(' ')
          : '<span style="color: var(--text-muted);">none</span>';
        
        const redactionKeys = Object.keys(item.redactionMetadata);
        const redactionSummary = redactionKeys.length > 0
          ? redactionKeys.map(k => `${k}×${item.redactionMetadata[k]}`).join(', ')
          : 'none';

        list.innerHTML = `
          <div class="details-row" style="display: flex; justify-content: space-between; font-size: 13px; padding-bottom: 12px; border-bottom: 1px dashed var(--border-subtle);">
            <span style="color: var(--text-muted);">Confidence</span>
            <span style="font-weight: 500; color: var(--text-main);">${Math.round(item.confidence * 100)}%</span>
          </div>
          <div class="details-row" style="display: flex; justify-content: space-between; font-size: 13px; padding-bottom: 12px; border-bottom: 1px dashed var(--border-subtle);">
            <span style="color: var(--text-muted);">Timestamp</span>
            <span style="font-weight: 500; color: var(--text-main);">${item.timestamp}</span>
          </div>
          <div class="details-row" style="display: flex; justify-content: space-between; font-size: 13px; padding-bottom: 12px; border-bottom: 1px dashed var(--border-subtle);">
            <span style="color: var(--text-muted);">Evidence Ref</span>
            <span style="font-weight: 500; color: var(--text-main); word-break: break-all; text-align: right; max-width: 60%;">${item.evidenceRef}</span>
          </div>
          <div class="details-row" style="display: flex; justify-content: space-between; font-size: 13px; padding-bottom: 12px; border-bottom: 1px dashed var(--border-subtle);">
            <span style="color: var(--text-muted);">MITRE ATT&amp;CK</span>
            <span style="font-weight: 500; color: var(--text-main);">${item.mitreMapping || '—'}</span>
          </div>
          <div class="details-row" style="display: flex; justify-content: space-between; font-size: 13px; padding-bottom: 12px; border-bottom: 1px dashed var(--border-subtle);">
            <span style="color: var(--text-muted);">Injection Score</span>
            <span style="font-weight: 500; color: ${item.injectionFlagged ? 'var(--red)' : 'var(--green, #10b981)'};">${(item.injectionScore * 100).toFixed(1)}%</span>
          </div>
          <div class="details-row" style="display: flex; justify-content: space-between; align-items: flex-start; font-size: 13px; padding-bottom: 12px; border-bottom: 1px dashed var(--border-subtle);">
            <span style="color: var(--text-muted); flex-shrink: 0; margin-right: 12px;">Actions Applied</span>
            <span style="font-weight: 500; color: var(--text-main); text-align: right;">${actions}</span>
          </div>
          <div class="details-row" style="display: flex; justify-content: space-between; font-size: 13px; padding-bottom: 12px; border-bottom: 1px dashed var(--border-subtle);">
            <span style="color: var(--text-muted);">PII Redacted</span>
            <span style="font-weight: 500; color: var(--text-main);">${redactionSummary}</span>
          </div>
        `;
      }
      
      // ── Download button: exports the full sanitized_context JSON ──
      let existingDownload = document.getElementById('download-fact-btn');
      if (existingDownload) existingDownload.remove();
      
      const downloadBtn = document.createElement('button');
      downloadBtn.id = 'download-fact-btn';
      downloadBtn.className = 'btn btn-primary';
      downloadBtn.style.cssText = 'width: 100%; justify-content: center; padding: 12px; font-weight: 600; margin-top: 16px; display: flex; align-items: center; gap: 8px; cursor: pointer;';
      downloadBtn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg> Download sanitized_context.json`;
      downloadBtn.onclick = () => {
        // Download the full structured sanitized_context JSON
        const blob = new Blob([JSON.stringify(item.sanitizedContext, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sanitized_context_${item.id.substring(0, 8)}.json`;
        a.click();
        URL.revokeObjectURL(url);
      };
      
      const oldBtn = document.querySelector('#details-content .btn-primary');
      if (oldBtn && oldBtn.id !== 'download-fact-btn') {
        oldBtn.replaceWith(downloadBtn);
      } else if (!oldBtn) {
        document.getElementById('details-content').appendChild(downloadBtn);
      }
    }
  }

  /** Minimal JSON syntax highlighter — colours keys, strings, numbers, booleans */
  _syntaxHighlight(json) {
    return json
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, (match) => {
        let cls = 'color: var(--blue);'; // number
        if (/^"/.test(match)) {
          if (/:$/.test(match)) {
            cls = 'color: var(--text-muted); font-weight: 600;'; // key
          } else {
            cls = 'color: var(--green, #10b981);'; // string value
          }
        } else if (/true|false/.test(match)) {
          cls = 'color: var(--orange);'; // boolean
        } else if (/null/.test(match)) {
          cls = 'color: var(--red);'; // null
        }
        return `<span style="${cls}">${match}</span>`;
      });
  }

  renderTable() {
    const tbody = document.getElementById('sanitized-tbody');
    const info = document.getElementById('pagination-info') || document.getElementById('sanitized-pagination-info');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    if (info) info.textContent = `Showing ${this.findingsData.length} sanitized findings`;

    if (this.findingsData.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 40px; color: var(--text-muted);">No sanitized findings available yet.</td></tr>';
      return;
    }

    this.findingsData.forEach(item => {
      const isSelected = item.id === this.selectedId;
      const tr = document.createElement('tr');
      if (isSelected) tr.classList.add('selected');
      
      // Show sanitized (redacted) fact text — NOT the raw fact
      const truncFact = item.fact.length > 80 ? item.fact.substring(0, 80) + '...' : item.fact;
      // Show injection status inline
      const injBadge = item.injectionFlagged
        ? `<span style="background:var(--red-light);color:var(--red);padding:2px 6px;border-radius:12px;font-size:10px;font-weight:600;margin-left:6px;">INJ</span>`
        : '';

      tr.innerHTML = `
        <td style="padding: 16px 24px;"><div class="custom-checkbox ${isSelected ? 'checked' : ''}"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg></div></td>
        <td style="padding: 16px 12px; font-family: monospace; font-size: 12px;">${truncFact}${injBadge}</td>
        <td style="padding: 16px 12px;"><span class="type-pill" style="background: var(--blue-light); color: var(--blue); padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; display: inline-block;">${item.layer}</span></td>
        <td style="padding: 16px 12px;">${item.evidenceRef}</td>
        <td style="padding: 16px 12px;">${Math.round(item.confidence * 100)}%</td>
        <td style="padding: 16px 12px;">${item.timestamp}</td>
        <td style="padding: 16px 12px;">${this.getSeverityBadge(item.severity)}</td>
      `;
      
      tr.addEventListener('click', () => {
        if (this.selectedId === item.id) {
          this.clearSelection();
        } else {
          this.selectedId = item.id;
          this.renderTable();
          this.showDetails(item);
        }
      });
      
      tbody.appendChild(tr);
    });
  }
}

const sanitizedApp = new SanitizedApp();
