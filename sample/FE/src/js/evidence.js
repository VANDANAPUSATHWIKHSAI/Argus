class EvidenceApp {
  constructor() {
    this.evidenceData = [];
    this.filteredData = [];
    this.selectedId = null;
    this.init();
  }

  async init() {
    this.renderTable();
    await this.fetchEvidence();
    this.initFilters();
  }

  detectType(filename) {
    const f = (filename || '').toLowerCase();
    if (f.endsWith('.ps1') || f.endsWith('.sh') || f.endsWith('.bat') || f.endsWith('.cmd') || f.endsWith('.py')) return 'Script';
    if (f.endsWith('.zip') || f.endsWith('.tar') || f.endsWith('.gz') || f.endsWith('.rar') || f.endsWith('.7z')) return 'Archive';
    if (f.endsWith('.evtx')) return 'EVTX';
    if (f.endsWith('.log') || f.endsWith('.txt') || f.endsWith('.syslog')) return 'Log';
    if (f.endsWith('.pcap') || f.endsWith('.pcapng') || f.endsWith('.cap')) return 'PCAP';
    if (f.includes('ntuser') || f.includes('sam') || f.includes('system') || f.includes('software') || f.endsWith('.dat') || f.endsWith('.hiv')) return 'Registry';
    if (f.endsWith('.e01') || f.endsWith('.raw') || f.endsWith('.img') || f.endsWith('.dd') || f.endsWith('.vmdk') || f.endsWith('.vhd')) return 'Disk Image';
    if (f.endsWith('.mem') || f.endsWith('.dmp') || f.endsWith('.bin')) return 'Memory';
    return 'File';
  }

  formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
  }

  initFilters() {
    const search   = document.getElementById('ev-search');
    const typeEl   = document.getElementById('ev-type-filter');
    const statusEl = document.getElementById('ev-status-filter');
    const sourceEl = document.getElementById('ev-source-filter');

    if (!search || !typeEl || !statusEl || !sourceEl) return;

    // Populate dynamic sources
    const sources = [...new Set(this.evidenceData.map(e => e.source).filter(Boolean))];
    sources.forEach(src => {
      const opt = document.createElement('option');
      opt.value = src; opt.textContent = src;
      sourceEl.appendChild(opt);
    });

    let debounceTimer;
    const applyFilters = () => {
      const q      = (search.value || '').toLowerCase();
      const type   = typeEl.value;
      const status = statusEl.value;
      const source = sourceEl.value;

      this.filteredData = this.evidenceData.filter(item => {
        if (q && !item.name.toLowerCase().includes(q) && !item.source.toLowerCase().includes(q)) return false;
        if (type   && item.type   !== type)   return false;
        if (status && item.status !== status) return false;
        if (source && item.source !== source) return false;
        return true;
      });

      this.renderTable();
    };

    search.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(applyFilters, 200);
    });
    typeEl.addEventListener('change',   applyFilters);
    statusEl.addEventListener('change', applyFilters);
    sourceEl.addEventListener('change', applyFilters);
  }

  async fetchEvidence() {
    try {
      let caseId   = localStorage.getItem('active_case_id');
      let caseName = localStorage.getItem('active_case_name');

      const activeContent = document.getElementById('evidence-active-content');
      const emptyState    = document.getElementById('evidence-empty-state');

      if (!caseId || caseId === '00000000-0000-0000-0000-000000000001') {
        if (activeContent) activeContent.style.display = 'none';
        if (emptyState)    emptyState.style.display    = 'block';
        return;
      }

      if (activeContent) activeContent.style.display = 'flex';
      if (emptyState)    emptyState.style.display    = 'none';

      const elCaseId   = document.getElementById('evidence-case-id');
      const elCaseName = document.getElementById('evidence-case-name');
      const formatId = id => id.length === 36 && id.includes('-') ? id.substring(0, 8) : id;
      if (elCaseId)   elCaseId.textContent   = `Case ${formatId(caseId)}`;
      if (elCaseName) elCaseName.textContent = caseName || 'Investigation';

      const response = await fetch(`http://localhost:8000/evidence/case/${caseId}`, {
        headers: { 'X-Tenant-ID': 'dev-team' }
      });
      if (!response.ok) throw new Error('Failed to fetch evidence');
      const result = await response.json();

      this.evidenceData = result.data.map(item => {
        const type = this.detectType(item.filename);
        return {
          id:         item.evidence_id,
          name:       item.filename,
          type,
          typeClass:  'type-file',
          source:     item.metadata?.host_id || item.uploaded_by || 'Unknown',
          size:       this.formatBytes(item.metadata?.size_bytes || 0),
          status:     item.status.charAt(0).toUpperCase() + item.status.slice(1).toLowerCase(),
          statusClass:`status-${item.status.toLowerCase()}`,
          added:      item.upload_timestamp ? new Date(item.upload_timestamp).toLocaleString() : 'N/A',
          risk:       'Medium',
          riskClass:  'risk-medium',
          desc:       item.metadata?.description || 'No description available.',
          sha:        item.sha256_hash,
          process:    'N/A',
          user:       item.uploaded_by || 'system',
          finding:    'N/A'
        };
      });

      // Summary stats
      let ingestedCount = 0, processingCount = 0, failedCount = 0, totalBytes = 0;
      result.data.forEach(item => {
        const s = (item.status || '').toLowerCase();
        if (s === 'ingested' || s === 'stored') ingestedCount++;
        else if (s === 'processing' || s === 'uploaded') processingCount++;
        else if (s === 'failed') failedCount++;
        totalBytes += (item.metadata?.size_bytes || 0);
      });
      this.updateSummaryStats(this.evidenceData.length, ingestedCount, processingCount, failedCount, totalBytes);

      // Start with unfiltered
      this.filteredData = [...this.evidenceData];
      this.renderTable();

      if (this.evidenceData.length > 0) {
        this.selectedId = this.evidenceData[0].id;
        this.updateDetailsPanel(this.selectedId);
      }
    } catch (error) {
      console.error('Error fetching evidence:', error);
    }
  }

  updateSummaryStats(totalItems, ingestedCount, processingCount, failedCount, totalBytes) {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('stat-total-items', totalItems);
    set('stat-ingested',    ingestedCount);
    set('stat-processing',  processingCount);
    set('stat-failed',      failedCount);
    set('stat-total-size',  this.formatBytes(totalBytes));
  }

  getStatusIcon(status) {
    if (status === 'Ingested')   return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>`;
    if (status === 'Processing') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>`;
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
  }

  renderTable() {
    const tbody = document.getElementById('evidence-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    const data = this.filteredData.length > 0 || this.evidenceData.length === 0 ? this.filteredData : this.filteredData;

    data.forEach(item => {
      const isSelected = item.id === this.selectedId;
      const tr = document.createElement('tr');
      if (isSelected) tr.classList.add('selected');

      tr.innerHTML = `
        <td><div class="custom-checkbox ${isSelected ? 'checked' : ''}"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg></div></td>
        <td>
          <div style="display: flex; align-items: center; gap: 8px;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--blue);"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
            <span style="font-weight: 500;">${item.name}</span>
          </div>
        </td>
        <td><span class="type-pill ${item.typeClass}">${item.type}</span></td>
        <td>${item.source}</td>
        <td>${item.size}</td>
        <td><span class="status-pill ${item.statusClass}">${this.getStatusIcon(item.status)} ${item.status}</span></td>
        <td>${item.added}</td>
        <td><span class="risk-pill ${item.riskClass}">${item.risk}</span></td>
        <td style="text-align: right;"><button class="btn-icon" style="display: inline-flex; width: 28px; height: 28px; border: none; box-shadow: none; background: transparent;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="1"></circle><circle cx="19" cy="12" r="1"></circle><circle cx="5" cy="12" r="1"></circle></svg></button></td>
      `;

      tr.addEventListener('click', () => {
        this.selectedId = item.id;
        this.renderTable();
        this.updateDetailsPanel(item.id);
      });

      tbody.appendChild(tr);
    });

    const count = data.length;
    const total = this.evidenceData.length;
    const elPagination = document.getElementById('pagination-info');
    if (elPagination) {
      if (count === 0) elPagination.textContent = 'No evidence items match your filters';
      else if (count < total) elPagination.textContent = `Showing ${count} of ${total} evidence items`;
      else elPagination.textContent = `Showing 1–${count} of ${count} evidence items`;
    }
  }

  updateDetailsPanel(id) {
    const item = this.evidenceData.find(e => e.id === id);
    if (!item) return;

    document.getElementById('main-grid').classList.add('has-selection');

    document.getElementById('details-title').textContent    = item.name;
    document.getElementById('details-subtitle').textContent = item.type;
    document.getElementById('details-badge').innerHTML      = `<div class="risk-pill ${item.riskClass}" style="margin-top: 4px;">${item.risk} Risk</div>`;
    document.getElementById('details-desc').textContent     = item.desc;

    const list = document.getElementById('details-list');
    list.innerHTML = `
      <div class="details-row" style="display: flex; justify-content: space-between; font-size: 13px; padding-bottom: 12px; border-bottom: 1px dashed var(--border-subtle);">
        <span style="color: var(--text-muted);">SHA-256</span>
        <span style="font-weight: 500; color: var(--text-main); font-family: monospace; font-size: 11px;">${item.sha}</span>
      </div>
      <div class="details-row" style="display: flex; justify-content: space-between; font-size: 13px; padding-bottom: 12px; border-bottom: 1px dashed var(--border-subtle);">
        <span style="color: var(--text-muted);">File Size</span>
        <span style="font-weight: 500; color: var(--text-main);">${item.size}</span>
      </div>
      <div class="details-row" style="display: flex; justify-content: space-between; font-size: 13px; padding-bottom: 12px; border-bottom: 1px dashed var(--border-subtle);">
        <span style="color: var(--text-muted);">File Type</span>
        <span style="font-weight: 500; color: var(--text-main);">${item.type}</span>
      </div>
      <div class="details-row" style="display: flex; justify-content: space-between; font-size: 13px; padding-bottom: 12px; border-bottom: 1px dashed var(--border-subtle);">
        <span style="color: var(--text-muted);">Collected From</span>
        <span style="font-weight: 500; color: var(--text-main);">${item.source}</span>
      </div>
      <div class="details-row" style="display: flex; justify-content: space-between; font-size: 13px; padding-bottom: 12px; border-bottom: 1px dashed var(--border-subtle);">
        <span style="color: var(--text-muted);">Uploaded</span>
        <span style="font-weight: 500; color: var(--text-main);">${item.added}</span>
      </div>
      <div class="details-row" style="display: flex; justify-content: space-between; font-size: 13px; padding-bottom: 12px; border-bottom: 1px dashed var(--border-subtle);">
        <span style="color: var(--text-muted);">Uploaded By</span>
        <span style="font-weight: 500; color: var(--text-main);">${item.user}</span>
      </div>
      <div class="details-row" style="display: flex; justify-content: space-between; font-size: 13px; padding-bottom: 12px; border-bottom: 1px dashed var(--border-subtle);">
        <span style="color: var(--text-muted);">Status</span>
        <span style="font-weight: 500; color: var(--text-main);">${item.status}</span>
      </div>
    `;
  }

  clearSelection() {
    this.selectedId = null;
    this.renderTable();
    document.getElementById('main-grid').classList.remove('has-selection');
  }
}

window.evidenceApp = new EvidenceApp();

