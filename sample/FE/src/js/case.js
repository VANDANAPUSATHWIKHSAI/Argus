class CaseManager {
  constructor() {
    this.checkAuth();
    // this.initTheme();
    this.initSearch();
    this.initDropdown();
    this.renderUserInfo();
  }

  checkAuth() {
    const path = window.location.pathname.toLowerCase();
    if (path.endsWith('login.html')) {
      return;
    }
    const token = localStorage.getItem('argus_token');
    if (!token) {
      window.location.href = './login.html';
    }
  }

  renderUserInfo() {
    try {
      const userStr = localStorage.getItem('argus_user');
      if (userStr) {
        const user = JSON.parse(userStr);
        const nameEl = document.querySelector('.user-profile span');
        const udNameEl = document.querySelector('.ud-name');
        const udRoleEl = document.querySelector('.ud-role');
        const avatarEl = document.querySelector('.avatar');
        if (user.name) {
          if (nameEl) nameEl.textContent = user.name;
          if (udNameEl) udNameEl.textContent = user.name;
          if (avatarEl) avatarEl.textContent = user.name.charAt(0).toUpperCase();
        }
        if (user.role && udRoleEl) {
          udRoleEl.textContent = user.role;
        }
      }
    } catch(e) {
      console.error(e);
    }
  }

  logout() {
    localStorage.removeItem('argus_token');
    localStorage.removeItem('argus_user');
    window.location.href = './login.html';
  }

  initDropdown() {
    // Close dropdown when clicking anywhere outside
    document.addEventListener('click', (e) => {
      const profile = document.querySelector('.user-profile');
      const dropdown = document.getElementById('user-dropdown');
      if (profile && dropdown && !profile.contains(e.target)) {
        dropdown.classList.remove('open');
      }
    });
  }

  toggleUserDropdown(e) {
    e.stopPropagation();
    const dropdown = document.getElementById('user-dropdown');
    if (dropdown) dropdown.classList.toggle('open');
  }

  initSearch() {
    // Global Search Logic
    const searchInput = document.getElementById('global-search-input');
    if (searchInput) {
      document.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
          e.preventDefault();
          searchInput.focus();
        }
      });
      searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          const query = searchInput.value.trim();
          if (query) {
            alert(`Searching for: ${query}\n(Search integration coming soon)`);
          }
        }
      });
    }
  }

  initTheme() {
    // Handled by global script in head
  }

  toggleTheme() {
    // Handled by global window.toggleTheme
    if (window.toggleTheme) window.toggleTheme();
  }

  openCreateCaseModal() {
    const caseId = localStorage.getItem('active_case_id');
    const caseName = localStorage.getItem('active_case_name');
    if (caseId && caseId !== '00000000-0000-0000-0000-000000000001' && caseName && caseName !== 'Case 00000000') {
      document.getElementById('custom-alert-text').textContent = "You are currently working on a case. You cannot create a new one until this case is closed or cleared.";
      document.getElementById('custom-alert-modal').style.display = 'flex';
      return;
    }
    document.getElementById('create-case-modal').style.display = 'flex';
  }

  closeCase() {
    localStorage.removeItem('active_case_id');
    localStorage.removeItem('active_case_name');
    localStorage.removeItem('active_case_desc');
    window.location.reload();
  }

  updateModalFileText() {
    const fileInput = document.getElementById('modal-file-input');
    const folderInput = document.getElementById('modal-folder-input');
    let totalFiles = 0;
    if (fileInput && fileInput.files.length > 0) totalFiles += fileInput.files.length;
    if (folderInput && folderInput.files.length > 0) totalFiles += folderInput.files.length;
    
    const textEl = document.getElementById('modal-upload-text');
    if (textEl) {
      if (totalFiles === 0) textEl.textContent = 'No evidence selected';
      else if (totalFiles === 1) {
        const file = fileInput.files.length > 0 ? fileInput.files[0] : folderInput.files[0];
        textEl.textContent = file.name;
      }
      else textEl.textContent = totalFiles + ' files selected';
    }
  }

  async createCase() {
    const name = document.getElementById('create-case-name').value || 'New Case';
    const customIdElement = document.getElementById('create-case-id');
    const customId = customIdElement ? customIdElement.value.trim() : '';
    const desc = document.getElementById('create-case-desc').value || '';
    const analyst = document.getElementById('create-case-analyst').value || 'system';

    const payload = {
      name: name,
      description: desc,
      created_by: analyst
    };
    if (customId) {
      payload.case_id = customId;
    }
    
    const btn = document.getElementById('btn-create-case-submit');
    if (btn) btn.innerHTML = 'Creating...';
    
    try {
      const response = await fetch(`${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}/cases/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Tenant-ID': 'dev-team',
          'Authorization': `Bearer ${localStorage.getItem('argus_token')}`
        },
        body: JSON.stringify(payload)
      });
      
      if (!response.ok) {
        if (response.status === 409) {
          throw new Error('This Case ID is already present. Please use another.');
        }
        throw new Error('Failed to create case');
      }
      const data = await response.json();
      
      // Save new case ID and details
      localStorage.setItem('active_case_id', data.case_id);
      localStorage.setItem('active_case_name', name);
      localStorage.setItem('active_case_desc', desc);
      
      // Handle optional evidence upload
      const fileInput = document.getElementById('modal-file-input');
      const folderInput = document.getElementById('modal-folder-input');
      let allFiles = [];
      if (fileInput && fileInput.files.length > 0) {
        allFiles = allFiles.concat(Array.from(fileInput.files));
      }
      if (folderInput && folderInput.files.length > 0) {
        allFiles = allFiles.concat(Array.from(folderInput.files));
      }

      if (allFiles.length > 0) {
        if (btn) btn.innerHTML = 'Uploading Evidence...';
        
        for (let i = 0; i < allFiles.length; i++) {
          const file = allFiles[i];
          const formData = new FormData();
          formData.append('file', file);
          formData.append('case_id', data.case_id);
          formData.append('uploaded_by', analyst);
          formData.append('host_id', 'Unknown');
          if (file.webkitRelativePath) {
            formData.append('relative_path', file.webkitRelativePath);
          }
          
          await fetch(`${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}/evidence/upload`, {
            method: 'POST',
            headers: {
              'X-Tenant-ID': 'dev-team',
              'Authorization': `Bearer ${localStorage.getItem('argus_token')}`
            },
            body: formData
          });
        }
      }

      // Close modal
      document.getElementById('create-case-modal').style.display = 'none';
      if (btn) btn.innerHTML = 'Create Case';
      
      const alertEl = document.getElementById('custom-alert-text');
      if (alertEl) alertEl.textContent = 'Case created successfully! Evidence is now available.';
      const modalEl = document.getElementById('custom-alert-modal');
      if (modalEl) modalEl.style.display = 'flex';
      
      // Optionally reload the page to refresh the view with the new case
      setTimeout(() => {
        window.location.reload();
      }, 1500);
      
    } catch (err) {
      console.error(err);
      if (btn) btn.innerHTML = 'Create Case';
      
      const alertEl = document.getElementById('custom-alert-text');
      if (alertEl) {
          alertEl.textContent = err.message;
          const modalEl = document.getElementById('custom-alert-modal');
          if (modalEl) modalEl.style.display = 'flex';
      } else {
          alert('Error creating case: ' + err.message);
      }
    }
  }
}

window.caseManager = new CaseManager();
