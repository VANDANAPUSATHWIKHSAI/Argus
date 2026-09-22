class UploadApp {
  constructor() {
    this.queue = [];
    this.isUploading = false;
    this.init();
  }

  init() {
    this.renderQueue();
    this.setupDropzone();
    this.setupActions();

    // Populate case details from localStorage
    const caseId = localStorage.getItem('active_case_id');
    const caseName = localStorage.getItem('active_case_name');
    const caseDesc = localStorage.getItem('active_case_desc');

    const formatId = (id) => id.length === 36 && id.includes('-') ? id.substring(0, 8) : id;
    const displayName = caseName || (caseId ? `Case ${formatId(caseId)}` : 'Case 00000000');
    const displayDesc = caseDesc || 'Default Investigation';

    const elCaseName = document.getElementById('upload-case-name');
    const elCaseDesc = document.getElementById('upload-case-desc');
    const elCaseFooter = document.getElementById('upload-case-footer-text');

    if (elCaseName) elCaseName.textContent = displayName;
    if (elCaseDesc) elCaseDesc.textContent = displayDesc;
    if (elCaseFooter) elCaseFooter.textContent = `All uploaded evidence will be automatically associated with ${displayName}.`;
  }

  formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
  }

  getIconForFile(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    if (['zip', 'rar', 'tar', 'gz'].includes(ext)) {
      return {
        icon: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>',
        color: 'var(--orange)',
        type: 'Archive'
      };
    }
    if (['ps1', 'exe', 'bat', 'sh'].includes(ext)) {
      return {
        icon: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>',
        color: 'var(--blue)',
        type: 'Executable / Script'
      };
    }
    if (['img', 'mem', 'dd'].includes(ext)) {
      return {
        icon: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg>',
        color: 'var(--purple)',
        type: 'Disk / Memory Dump'
      };
    }
    return {
      icon: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>',
      color: 'var(--blue)',
      type: 'File'
    };
  }

  addFiles(files, customRelativePath = null) {
    Array.from(files).forEach(file => {
      const fileInfo = this.getIconForFile(file.name);
      const relPath = customRelativePath || file.customRelativePath || file.webkitRelativePath || '';
      
      this.queue.push({
        id: 'file-' + Date.now() + Math.random().toString(36).substr(2, 9),
        file: file,
        name: relPath ? relPath : file.name,
        type: fileInfo.type,
        size: this.formatBytes(file.size),
        status: 'Ready',
        progress: 0,
        icon: fileInfo.icon,
        color: fileInfo.color,
        relativePath: relPath
      });
    });
    this.renderQueue();
  }

  getStatusBadge(item) {
    if (item.status === 'Ready') {
      return `<div style="display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; background-color: var(--green-light); color: var(--green);">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
        Ready
      </div>`;
    }
    if (item.status === 'Uploading') {
      return `<div style="display: flex; flex-direction: column; width: 150px;">
        <div style="display: flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; color: var(--blue); margin-bottom: 6px;">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
          Uploading ${item.progress}%
        </div>
        <div style="height: 4px; background: var(--border-strong); border-radius: 2px; overflow: hidden; width: 100%;">
          <div style="height: 100%; width: ${item.progress}%; background: var(--blue); transition: width 0.3s;"></div>
        </div>
      </div>`;
    }
    if (item.status === 'Queued') {
      return `<div style="display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; color: var(--text-muted);">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
        Queued
      </div>`;
    }
    if (item.status === 'Completed') {
      return `<div style="display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; background-color: var(--green-light); color: var(--green);">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
        Completed
      </div>`;
    }
    if (item.status === 'Failed') {
      return `<div style="display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; background-color: var(--red-light); color: var(--red);">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>
        Failed
      </div>`;
    }
    return '';
  }

  renderQueue() {
    const list = document.getElementById('queue-list');
    list.innerHTML = '';

    if (this.queue.length === 0) {
      list.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 40px; font-size: 14px;">Queue is empty.</div>';
      return;
    }

    this.queue.forEach(item => {
      const row = document.createElement('div');
      row.style.cssText = `
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 16px;
        background: white;
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-md);
        box-shadow: 0 1px 3px rgba(0,0,0,0.02);
      `;
      
      row.innerHTML = `
        <div style="display: flex; align-items: center; gap: 16px; flex: 1; min-width: 0;">
          <div style="width: 32px; height: 32px; border-radius: 6px; background: var(--bg-app); display: flex; align-items: center; justify-content: center; color: ${item.color}; border: 1px solid var(--border-strong); flex-shrink: 0;">
            ${item.icon}
          </div>
          <div style="display: flex; flex-direction: column; overflow: hidden; white-space: nowrap;">
            <span style="font-size: 14px; font-weight: 600; color: var(--text-main); margin-bottom: 4px; text-overflow: ellipsis; overflow: hidden;">${item.name}</span>
            <span style="font-size: 12px; color: var(--text-muted);">${item.type}</span>
          </div>
        </div>
        <div style="width: 100px; font-size: 13px; font-weight: 500; color: var(--text-main); text-align: right; margin-right: 16px;">
          ${item.size}
        </div>
        <div style="width: 180px; display: flex; align-items: center;">
          ${this.getStatusBadge(item)}
        </div>
        <div>
          <button class="btn-icon" style="color: var(--text-muted); width: 28px; height: 28px; border: 1px solid transparent;" onclick="uploadApp.removeItem('${item.id}')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
          </button>
        </div>
      `;
      list.appendChild(row);
    });
  }

  removeItem(id) {
    this.queue = this.queue.filter(item => item.id !== id);
    this.renderQueue();
  }

  setupDropzone() {
    const dropzone = document.getElementById('upload-dropzone');
    const fileInput = document.getElementById('file-input');
    const folderInput = document.getElementById('folder-input');
    const btnBrowseFiles = document.getElementById('btn-browse-files');
    const btnBrowseFolders = document.getElementById('btn-browse-folders');

    btnBrowseFiles.addEventListener('click', (e) => {
      e.stopPropagation();
      fileInput.click();
    });

    btnBrowseFolders.addEventListener('click', (e) => {
      e.stopPropagation();
      folderInput.click();
    });

    const handleFileSelect = (e) => {
      if (e.target.files.length > 0) {
        this.addFiles(e.target.files);
        e.target.value = ''; // Reset
      }
    };

    fileInput.addEventListener('change', handleFileSelect);
    folderInput.addEventListener('change', handleFileSelect);

    // Make the entire dropzone clickable for files by default
    dropzone.addEventListener('click', () => {
      fileInput.click();
    });

    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.style.borderColor = 'var(--blue)';
      dropzone.style.backgroundColor = 'var(--blue-light)';
    });
    dropzone.addEventListener('dragleave', (e) => {
      e.preventDefault();
      dropzone.style.borderColor = 'var(--blue)';
      dropzone.style.backgroundColor = 'white';
    });
    dropzone.addEventListener('drop', async (e) => {
      e.preventDefault();
      dropzone.style.borderColor = 'var(--blue)';
      dropzone.style.backgroundColor = 'white';
      
      if (e.dataTransfer.items) {
        const items = e.dataTransfer.items;
        for (let i = 0; i < items.length; i++) {
          const item = items[i].webkitGetAsEntry();
          if (item) {
            await this.traverseFileTree(item);
          }
        }
      } else if (e.dataTransfer.files.length > 0) {
        this.addFiles(e.dataTransfer.files);
      }
    });
  }

  async traverseFileTree(item, path = '') {
    if (item.isFile) {
      item.file(file => {
        const dt = new DataTransfer();
        dt.items.add(file);
        this.addFiles(dt.files, path + file.name);
      });
    } else if (item.isDirectory) {
      const dirReader = item.createReader();
      const readEntries = () => {
        dirReader.readEntries(async (entries) => {
          if (entries.length > 0) {
            for (const entry of entries) {
              await this.traverseFileTree(entry, path + item.name + '/');
            }
            readEntries();
          }
        });
      };
      readEntries();
    }
  }

  async uploadFile(item) {
    item.status = 'Uploading';
    item.progress = 10;
    this.renderQueue();

    const hostId = document.getElementById('source-device-input')?.value || 'DESKTOP-7G2K';

    const formData = new FormData();
    let caseId = localStorage.getItem('active_case_id') || '00000000-0000-0000-0000-000000000001';
    
    formData.append('file', item.file);
    formData.append('case_id', caseId);
    formData.append('uploaded_by', 'Analyst');
    formData.append('host_id', hostId);
    if (item.relativePath) {
      formData.append('relative_path', item.relativePath);
    }

    try {
      // Simulate progress for UI
      const progressInterval = setInterval(() => {
        if (item.progress < 90) {
          item.progress += 10;
          this.renderQueue();
        }
      }, 500);

      const response = await fetch('http://localhost:8000/evidence/upload', {
        method: 'POST',
        headers: {
          'X-Tenant-ID': 'dev-team'
        },
        body: formData
      });

      clearInterval(progressInterval);

      if (response.ok) {
        const resData = await response.json();
        if (resData.errors && resData.errors.length > 0) {
          item.status = 'Failed';
          console.error('Upload partial failure', resData.errors);
        } else {
          item.progress = 100;
          item.status = 'Completed';
        }
      } else {
        item.status = 'Failed';
        console.error('Upload failed', await response.text());
      }
    } catch (error) {
      item.status = 'Failed';
      console.error('Upload error', error);
    }
    
    this.renderQueue();
  }

  setupActions() {
    const btn = document.getElementById('btn-upload');
    btn.addEventListener('click', async () => {
      if (this.isUploading) return;
      
      const filesToUpload = this.queue.filter(item => item.status === 'Ready' || item.status === 'Queued' || item.status === 'Failed');
      
      if (filesToUpload.length === 0) return;

      this.isUploading = true;
      btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 8px; animation: spin 2s linear infinite;"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg> Uploading...`;
      
      for (const item of filesToUpload) {
        await this.uploadFile(item);
      }

      this.isUploading = false;
      const allDone = this.queue.every(item => item.status === 'Completed');
      const failedCount = this.queue.filter(item => item.status === 'Failed').length;
      
      if (allDone && this.queue.length > 0) {
        btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 8px;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg> Done`;
        btn.classList.add('btn-success');
        btn.style.backgroundColor = 'var(--green)';
        btn.style.borderColor = 'var(--green)';
      } else if (failedCount > 0) {
        btn.innerHTML = `Done (${failedCount} Failed) &rarr;`;
        btn.style.backgroundColor = 'var(--red)';
        btn.style.borderColor = 'var(--red)';
      } else {
        btn.innerHTML = `Upload & Analyze &rarr;`;
      }
    });
  }
}

const uploadApp = new UploadApp();
