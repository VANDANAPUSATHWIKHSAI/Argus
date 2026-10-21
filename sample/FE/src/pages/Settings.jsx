import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import { updatePassword, requestPasswordResetOtp, verifyOtpAndResetPassword } from '../js/api';
import '../css/style.css';

const inputStyle = {
  width: '100%',
  padding: '12px 16px',
  border: '1px solid var(--border-strong)',
  borderRadius: 8,
  fontFamily: 'inherit',
  fontSize: 14,
  background: 'var(--bg-app)',
  color: 'var(--text-main)',
  outline: 'none',
  boxSizing: 'border-box',
  transition: 'border-color 0.2s',
};

const labelStyle = {
  display: 'block',
  fontSize: 13,
  fontWeight: 600,
  color: 'var(--text-muted)',
  marginBottom: 8,
};

const formGroup = { marginBottom: 20 };

const Settings = () => {
  const navigate = useNavigate();

  // Mode: 'change' (standard) or 'forgot' (OTP reset)
  const [activeTab, setActiveTab] = useState('change');

  // Change Password state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isUpdatingPassword, setIsUpdatingPassword] = useState(false);

  // Forgot Password / OTP state
  const [userIdInput, setUserIdInput] = useState(() => {
    try {
      const u = JSON.parse(localStorage.getItem('user'));
      return u?.id || u?.email || 'sathwik';
    } catch {
      return 'sathwik';
    }
  });
  const [otpCode, setOtpCode] = useState('');
  const [forgotNewPassword, setForgotNewPassword] = useState('');
  const [forgotConfirmPassword, setForgotConfirmPassword] = useState('');
  const [otpSent, setOtpSent] = useState(false);
  const [otpTargetInfo, setOtpTargetInfo] = useState('');
  const [isSendingOtp, setIsSendingOtp] = useState(false);
  const [isResettingWithOtp, setIsResettingWithOtp] = useState(false);

  // Status feedback
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  // Switch tabs cleanly
  const switchTab = (tab) => {
    setActiveTab(tab);
    setErrorMessage('');
    setSuccessMessage('');
  };

  // 1. Handle Standard Password Change
  const handlePasswordUpdate = async (e) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');
    
    if (!currentPassword || !newPassword || !confirmPassword) {
      setErrorMessage('All fields are required.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setErrorMessage('New password and confirm password do not match.');
      return;
    }
    if (newPassword.length < 6) {
      setErrorMessage('New password must be at least 6 characters.');
      return;
    }

    try {
      setIsUpdatingPassword(true);
      const result = await updatePassword(currentPassword, newPassword);
      setSuccessMessage(result.message || 'Password successfully updated!');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => setSuccessMessage(''), 5000);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to update password');
    } finally {
      setIsUpdatingPassword(false);
    }
  };

  // 2. Handle Forgot Password - Step 1: Send OTP
  const handleSendOtp = async (e) => {
    if (e) e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');

    if (!userIdInput.trim()) {
      setErrorMessage('Please enter your User ID or registered email.');
      return;
    }

    try {
      setIsSendingOtp(true);
      const res = await requestPasswordResetOtp(userIdInput.trim());
      setOtpSent(true);
      setOtpTargetInfo(res.message || 'OTP sent to registered email address.');
      setSuccessMessage(res.message || 'Verification code sent to registered security contact.');
    } catch (err) {
      setErrorMessage(err.message || 'Failed to send OTP. Please check your User ID.');
    } finally {
      setIsSendingOtp(false);
    }
  };

  // 3. Handle Forgot Password - Step 2: Verify OTP & Reset
  const handleVerifyOtpAndReset = async (e) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');

    if (!otpCode.trim()) {
      setErrorMessage('Please enter the 6-digit OTP code.');
      return;
    }
    if (!forgotNewPassword || !forgotConfirmPassword) {
      setErrorMessage('Please provide and confirm your new password.');
      return;
    }
    if (forgotNewPassword !== forgotConfirmPassword) {
      setErrorMessage('New password and confirm password do not match.');
      return;
    }
    if (forgotNewPassword.length < 6) {
      setErrorMessage('New password must be at least 6 characters.');
      return;
    }

    try {
      setIsResettingWithOtp(true);
      const res = await verifyOtpAndResetPassword(userIdInput.trim(), otpCode.trim(), forgotNewPassword);
      setSuccessMessage(res.message || 'Password successfully reset! You can now use your new password.');
      setOtpCode('');
      setForgotNewPassword('');
      setForgotConfirmPassword('');
      setOtpSent(false);

      // Return to standard view after brief delay
      setTimeout(() => {
        setActiveTab('change');
      }, 3500);
    } catch (err) {
      setErrorMessage(err.message || 'Invalid or expired OTP code.');
    } finally {
      setIsResettingWithOtp(false);
    }
  };

  return (
    <div id="app-shell">
      <Sidebar />
      <main className="main-content">
        <div style={{ padding: '32px 48px', maxWidth: 840, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 28 }}>
          
          {/* Page Title */}
          <div>
            <h2 style={{ fontFamily: "'Poppins', sans-serif", fontSize: 28, fontWeight: 800, color: 'var(--text-main)', marginBottom: 6 }}>
              Account Security & Settings
            </h2>
            <p style={{ fontSize: 14, color: 'var(--text-muted)' }}>
              Manage credentials, update access passwords, or recover accounts using multi-factor OTP verification.
            </p>
          </div>

          {/* Mode Selector Tabs */}
          <div style={{
            display: 'flex',
            gap: 8,
            backgroundColor: 'var(--bg-app)',
            border: '1px solid var(--border-subtle)',
            padding: 4,
            borderRadius: 12,
            width: 'fit-content'
          }}>
            <button
              type="button"
              onClick={() => switchTab('change')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '10px 20px',
                borderRadius: 8,
                border: 'none',
                fontSize: 13,
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                backgroundColor: activeTab === 'change' ? 'var(--bg-card)' : 'transparent',
                color: activeTab === 'change' ? 'var(--blue)' : 'var(--text-muted)',
                boxShadow: activeTab === 'change' ? 'var(--shadow-card)' : 'none'
              }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              Change Password
            </button>

            <button
              type="button"
              onClick={() => switchTab('forgot')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '10px 20px',
                borderRadius: 8,
                border: 'none',
                fontSize: 13,
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                backgroundColor: activeTab === 'forgot' ? 'var(--bg-card)' : 'transparent',
                color: activeTab === 'forgot' ? 'var(--blue)' : 'var(--text-muted)',
                boxShadow: activeTab === 'forgot' ? 'var(--shadow-card)' : 'none'
              }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 2l-2 2m-1-1l2 2M11 7a4 4 0 0 0-4 4 4 4 0 0 0 4 4 4 4 0 0 0 4-4 4 4 0 0 0-4-4zm0 6a2 2 0 1 1 0-4 2 2 0 0 1 0 4z"/><path d="M15 11l4.5 4.5M17 13.5l1.5 1.5M18.5 15l2 2"/></svg>
              Forgot Password / Reset with OTP
            </button>
          </div>

          {/* Feedback Messages */}
          {errorMessage && (
            <div style={{ background: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#f87171', padding: '14px 18px', borderRadius: 10, fontSize: 13, fontWeight: 500, display: 'flex', alignItems: 'center', gap: 10, animation: 'fadeIn 0.2s ease' }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
              <span>{errorMessage}</span>
            </div>
          )}

          {successMessage && (
            <div style={{ background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#34d399', padding: '14px 18px', borderRadius: 10, fontSize: 13, fontWeight: 500, display: 'flex', alignItems: 'center', gap: 10, animation: 'fadeIn 0.2s ease' }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M20 6L9 17l-5-5"/></svg>
              <span>{successMessage}</span>
            </div>
          )}

          {/* TAB 1: CHANGE PASSWORD */}
          {activeTab === 'change' && (
            <div style={{ background: 'var(--bg-card)', borderRadius: 16, border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)', padding: 36, transition: 'all 0.2s ease' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24, paddingBottom: 16, borderBottom: '1px solid var(--border-strong)' }}>
                <div style={{ width: 40, height: 40, borderRadius: 10, background: 'var(--blue-light)', color: 'var(--blue)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                </div>
                <div>
                  <h3 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-main)', margin: 0 }}>Change Existing Password</h3>
                  <p style={{ fontSize: 13, color: 'var(--text-muted)', margin: 0, marginTop: 2 }}>Update your current security key with your existing password verification.</p>
                </div>
              </div>

              <form onSubmit={handlePasswordUpdate}>
                <div style={formGroup}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <label style={{ ...labelStyle, marginBottom: 0 }}>Current Password</label>
                    <button
                      type="button"
                      onClick={() => switchTab('forgot')}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--blue)',
                        fontSize: 12,
                        fontWeight: 600,
                        cursor: 'pointer',
                        padding: 0
                      }}
                    >
                      Forgot your password?
                    </button>
                  </div>
                  <input
                    type="password"
                    style={inputStyle}
                    placeholder="Enter current password"
                    value={currentPassword}
                    onChange={e => setCurrentPassword(e.target.value)}
                  />
                </div>

                <div style={formGroup}>
                  <label style={labelStyle}>New Password</label>
                  <input
                    type="password"
                    style={inputStyle}
                    placeholder="Enter new password (min. 6 characters)"
                    value={newPassword}
                    onChange={e => setNewPassword(e.target.value)}
                  />
                </div>

                <div style={formGroup}>
                  <label style={labelStyle}>Confirm New Password</label>
                  <input
                    type="password"
                    style={inputStyle}
                    placeholder="Confirm new password"
                    value={confirmPassword}
                    onChange={e => setConfirmPassword(e.target.value)}
                  />
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-start', alignItems: 'center', marginTop: 28 }}>
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={isUpdatingPassword}
                    style={{
                      background: 'var(--blue)',
                      padding: '12px 28px',
                      fontWeight: 600,
                      fontSize: 14,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                      cursor: isUpdatingPassword ? 'not-allowed' : 'pointer',
                      opacity: isUpdatingPassword ? 0.7 : 1,
                    }}
                  >
                    {isUpdatingPassword ? 'Updating Password...' : 'Update Password'}
                  </button>
                </div>
              </form>
            </div>
          )}

          {/* TAB 2: FORGOT PASSWORD / OTP RESET */}
          {activeTab === 'forgot' && (
            <div style={{ background: 'var(--bg-card)', borderRadius: 16, border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)', padding: 36, transition: 'all 0.2s ease' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24, paddingBottom: 16, borderBottom: '1px solid var(--border-strong)' }}>
                <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(245, 158, 11, 0.12)', color: '#f59e0b', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                </div>
                <div>
                  <h3 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-main)', margin: 0 }}>Forgot Password Recovery</h3>
                  <p style={{ fontSize: 13, color: 'var(--text-muted)', margin: 0, marginTop: 2 }}>
                    {otpSent ? 'Step 2: Enter the 6-digit OTP code sent to your email and define your new password.' : 'Step 1: Request a one-time verification passcode (OTP) dispatched to your security contact.'}
                  </p>
                </div>
              </div>

              {!otpSent ? (
                /* Sub-step 1: Request OTP */
                <form onSubmit={handleSendOtp}>
                  <div style={formGroup}>
                    <label style={labelStyle}>User ID or Registered Email</label>
                    <input
                      type="text"
                      style={inputStyle}
                      placeholder="e.g. sathwik or sathwik@argus.ai"
                      value={userIdInput}
                      onChange={e => setUserIdInput(e.target.value)}
                    />
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>
                      We will dispatch a secure 6-digit cryptographic verification code to your verified email.
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginTop: 28 }}>
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={isSendingOtp}
                      style={{
                        background: '#2563eb',
                        padding: '12px 28px',
                        fontWeight: 600,
                        fontSize: 14,
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                        cursor: isSendingOtp ? 'not-allowed' : 'pointer',
                        opacity: isSendingOtp ? 0.7 : 1,
                      }}
                    >
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg>
                      {isSendingOtp ? 'Sending OTP Code...' : 'Send Security OTP Code'}
                    </button>

                    <button
                      type="button"
                      onClick={() => switchTab('change')}
                      style={{
                        background: 'transparent',
                        border: '1px solid var(--border-strong)',
                        color: 'var(--text-main)',
                        padding: '12px 20px',
                        borderRadius: 8,
                        fontSize: 13,
                        fontWeight: 600,
                        cursor: 'pointer'
                      }}
                    >
                      Cancel / Back
                    </button>
                  </div>
                </form>
              ) : (
                /* Sub-step 2: Verify OTP & Reset Password */
                <form onSubmit={handleVerifyOtpAndReset}>
                  <div style={{
                    backgroundColor: 'rgba(59, 130, 246, 0.08)',
                    border: '1px solid rgba(59, 130, 246, 0.25)',
                    padding: '12px 16px',
                    borderRadius: 8,
                    marginBottom: 20,
                    fontSize: 13,
                    color: '#38bdf8',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between'
                  }}>
                    <span>{otpTargetInfo || `OTP dispatched for user ${userIdInput}.`}</span>
                    <button
                      type="button"
                      onClick={() => setOtpSent(false)}
                      style={{ background: 'none', border: 'none', color: '#60a5fa', textDecoration: 'underline', fontSize: 12, cursor: 'pointer' }}
                    >
                      Change User ID
                    </button>
                  </div>

                  <div style={formGroup}>
                    <label style={labelStyle}>6-Digit OTP Code</label>
                    <input
                      type="text"
                      maxLength={6}
                      style={{ ...inputStyle, letterSpacing: '4px', fontSize: 18, fontWeight: 700, textAlign: 'center', maxWidth: 220 }}
                      placeholder="••••••"
                      value={otpCode}
                      onChange={e => setOtpCode(e.target.value.replace(/\D/g, ''))}
                    />
                  </div>

                  <div style={formGroup}>
                    <label style={labelStyle}>New Password</label>
                    <input
                      type="password"
                      style={inputStyle}
                      placeholder="Enter new password (min. 6 characters)"
                      value={forgotNewPassword}
                      onChange={e => setForgotNewPassword(e.target.value)}
                    />
                  </div>

                  <div style={formGroup}>
                    <label style={labelStyle}>Confirm New Password</label>
                    <input
                      type="password"
                      style={inputStyle}
                      placeholder="Confirm new password"
                      value={forgotConfirmPassword}
                      onChange={e => setForgotConfirmPassword(e.target.value)}
                    />
                  </div>

                  <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginTop: 28 }}>
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={isResettingWithOtp}
                      style={{
                        background: '#059669',
                        padding: '12px 28px',
                        fontWeight: 600,
                        fontSize: 14,
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                        cursor: isResettingWithOtp ? 'not-allowed' : 'pointer',
                        opacity: isResettingWithOtp ? 0.7 : 1,
                      }}
                    >
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="20 6 9 17 4 12"/></svg>
                      {isResettingWithOtp ? 'Verifying OTP...' : 'Verify OTP & Reset Password'}
                    </button>

                    <button
                      type="button"
                      onClick={handleSendOtp}
                      disabled={isSendingOtp}
                      style={{
                        background: 'transparent',
                        border: '1px solid var(--border-strong)',
                        color: 'var(--text-main)',
                        padding: '12px 20px',
                        borderRadius: 8,
                        fontSize: 13,
                        fontWeight: 600,
                        cursor: isSendingOtp ? 'not-allowed' : 'pointer',
                        opacity: isSendingOtp ? 0.6 : 1
                      }}
                    >
                      {isSendingOtp ? 'Resending...' : 'Resend OTP'}
                    </button>

                    <button
                      type="button"
                      onClick={() => switchTab('change')}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-muted)',
                        padding: '12px 14px',
                        fontSize: 13,
                        cursor: 'pointer'
                      }}
                    >
                      Back to Change Password
                    </button>
                  </div>
                </form>
              )}
            </div>
          )}

        </div>
      </main>

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(-4px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
};

export default Settings;