import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import NotificationMenu from '../components/NotificationMenu';
import { queryCase } from '../js/api';
import '../css/style.css';

const Chatbot = () => {
  const navigate = useNavigate();
  const activeCaseId = localStorage.getItem('active_case_id');
  const activeCaseName = localStorage.getItem('active_case_name') || 'Current Case';

  const [messages, setMessages] = useState([
    {
      id: 'welcome',
      sender: 'assistant',
      text: activeCaseId 
        ? `Hello! I am your ARGUS Investigation Assistant grounded in FIR findings for Case ${activeCaseId} (${activeCaseName}). Ask me any question about findings, IOCs, timelines, or evidence relationships.`
        : `Welcome! Please select an active investigation case from the Dashboard to begin querying case evidence.`
    }
  ]);

  const [inputQuery, setInputQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'warning' });
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  const handleSendQuery = async (e) => {
    e.preventDefault();
    const queryText = inputQuery.trim();
    if (!queryText || loading) return;

    if (!activeCaseId) {
      setCustomAlert({
        isOpen: true,
        title: 'No Active Case',
        message: 'Please select an active investigation case from the Dashboard before querying the Assistant.',
        type: 'warning'
      });
      return;
    }

    const userMessage = {
      id: Date.now().toString(),
      sender: 'user',
      text: queryText
    };

    setMessages(prev => [...prev, userMessage]);
    setInputQuery('');
    setLoading(true);

    try {
      const res = await queryCase(activeCaseId, queryText);
      const assistantMessage = {
        id: (Date.now() + 1).toString(),
        sender: 'assistant',
        text: res.response || 'No response returned from Assistant.',
        injection_flagged: res.injection_flagged,
        injection_score: res.injection_score
      };
      setMessages(prev => [...prev, assistantMessage]);
    } catch (err) {
      console.error('Error querying assistant:', err);
      const errorMessage = {
        id: (Date.now() + 1).toString(),
        sender: 'assistant',
        isError: true,
        text: `Error querying Case ${activeCaseId}: ${err.message || 'Failed to connect to server.'}`
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  const closeAlert = () => setCustomAlert(prev => ({ ...prev, isOpen: false }));

  return (
    <div id="app-shell">
      <AlertModal 
        isOpen={customAlert.isOpen} 
        title={customAlert.title} 
        message={customAlert.message} 
        type={customAlert.type} 
        onClose={closeAlert} 
      />
      <Sidebar active="chatbot" />

      <main className="main-content" style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>
        {/* TOPBAR */}
        <header className="topbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--brand-blue)" strokeWidth="2">
              <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
            </svg>
            <span style={{ fontSize: '16px', fontWeight: '700', color: 'var(--text-main)' }}>
              ARGUS Investigation Assistant
            </span>
          </div>

          <div className="topbar-actions" style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <NotificationMenu />
            <div style={{ fontSize: '13px', fontWeight: '600', color: 'var(--brand-blue)', background: 'rgba(59,130,246,0.1)', padding: '6px 14px', borderRadius: '20px' }}>
              {activeCaseId ? `Case: ${activeCaseName} (${activeCaseId})` : 'No Case Selected'}
            </div>
          </div>
        </header>

        {/* CHAT CONTAINER */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '24px 40px', overflow: 'hidden' }}>
          {/* MESSAGES LIST */}
          <div style={{
            flex: 1,
            overflowY: 'auto',
            paddingRight: '12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '16px',
            marginBottom: '20px'
          }}>
            {messages.map((msg) => (
              <div 
                key={msg.id} 
                style={{
                  display: 'flex',
                  justifyContent: msg.sender === 'user' ? 'flex-end' : 'flex-start',
                  marginBottom: '4px'
                }}
              >
                <div style={{
                  maxWidth: '75%',
                  padding: '14px 18px',
                  borderRadius: msg.sender === 'user' ? '18px 18px 4px 18px' : '18px 18px 18px 4px',
                  background: msg.sender === 'user' ? 'var(--brand-blue)' : msg.isError ? 'rgba(239,68,68,0.15)' : 'var(--bg-card)',
                  color: msg.sender === 'user' ? '#ffffff' : msg.isError ? '#ef4444' : 'var(--text-main)',
                  border: msg.sender === 'user' ? 'none' : msg.isError ? '1px solid #ef4444' : '1px solid var(--border-color)',
                  boxShadow: '0 2px 8px rgba(0,0,0,0.15)',
                  fontSize: '14px',
                  lineHeight: '1.6',
                  whiteSpace: 'pre-wrap'
                }}>
                  <div style={{ fontSize: '11px', fontWeight: '700', marginBottom: '4px', opacity: 0.8, textTransform: 'uppercase' }}>
                    {msg.sender === 'user' ? 'Analyst' : 'ARGUS Assistant'}
                  </div>

                  {msg.injection_flagged && (
                    <div style={{ background: 'rgba(249, 115, 22, 0.2)', border: '1px solid #f97316', padding: '6px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: '700', color: '#f97316', marginBottom: '8px' }}>
                      ⚠️ PASSTHROUGH WARNING: Potential prompt injection detected in query context (score: {msg.injection_score})
                    </div>
                  )}

                  {msg.text}
                </div>
              </div>
            ))}

            {loading && (
              <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
                <div style={{
                  padding: '14px 20px',
                  borderRadius: '18px 18px 18px 4px',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-color)',
                  color: 'var(--text-muted)',
                  fontSize: '14px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px'
                }}>
                  <div className="spinner" style={{ width: '16px', height: '16px', borderWidth: '2px' }}></div>
                  Reasoning over case evidence...
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* INPUT FORM */}
          <form onSubmit={handleSendQuery} style={{ display: 'flex', gap: '12px' }}>
            <input 
              type="text" 
              placeholder={activeCaseId ? `Ask Assistant about Case ${activeCaseId}...` : 'Select an active case to ask questions...'}
              value={inputQuery}
              onChange={(e) => setInputQuery(e.target.value)}
              disabled={!activeCaseId || loading}
              style={{
                flex: 1,
                background: 'var(--bg-card)',
                color: 'var(--text-main)',
                border: '1px solid var(--border-color)',
                borderRadius: '12px',
                padding: '14px 20px',
                fontSize: '14px',
                outline: 'none'
              }}
            />
            <button 
              type="submit" 
              disabled={!activeCaseId || loading || !inputQuery.trim()}
              style={{
                background: 'var(--brand-blue)',
                color: '#ffffff',
                border: 'none',
                borderRadius: '12px',
                padding: '0 24px',
                fontSize: '14px',
                fontWeight: '600',
                cursor: (!activeCaseId || loading || !inputQuery.trim()) ? 'not-allowed' : 'pointer',
                opacity: (!activeCaseId || loading || !inputQuery.trim()) ? 0.6 : 1,
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
            >
              Send
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="22" y1="2" x2="11" y2="13"></line>
                <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
              </svg>
            </button>
          </form>
        </div>
      </main>
    </div>
  );
};

export default Chatbot;
