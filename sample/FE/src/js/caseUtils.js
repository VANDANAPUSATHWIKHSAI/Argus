/**
 * Case Utilities for ARGUS Forensic Platform
 * Standardizes case state inspection, report completion verification,
 * and closure gating.
 */

/**
 * Checks whether a case has had a forensic report generated, submitted, or certified.
 * Inspects case object properties and local storage flags.
 *
 * @param {Object|string} caseObjOrId - The case object or case ID string
 * @returns {boolean} True if a report has been generated or submitted for this case
 */
export function isCaseReportGenerated(caseObjOrId) {
  if (!caseObjOrId) return false;
  const caseId = typeof caseObjOrId === 'string' ? caseObjOrId : caseObjOrId.case_id;
  const caseObj = typeof caseObjOrId === 'object' ? caseObjOrId : null;

  if (caseObj) {
    if (
      Boolean(caseObj.has_report) ||
      Boolean(caseObj.submitted_to_senior) ||
      Boolean(caseObj.submitted_to_auditor) ||
      Boolean(caseObj.audit_certified) ||
      Boolean(caseObj.is_certified) ||
      caseObj.audit_status === 'certified' ||
      caseObj.audit_status === 'approved'
    ) {
      return true;
    }
  }

  if (typeof localStorage !== 'undefined' && caseId) {
    if (
      localStorage.getItem(`argus_case_${caseId}_report_completed`) ||
      localStorage.getItem(`argus_case_${caseId}_submitted_to_senior`) ||
      localStorage.getItem(`argus_case_${caseId}_submitted_to_auditor`) ||
      localStorage.getItem(`argus_audit_certified_${caseId}`)
    ) {
      return true;
    }
  }

  return false;
}

const AGENT_PIPELINE_KEYS = ['agent1', 'agent2', 'agent3', 'agent4', 'agent5a', 'agent5b', 'agent6', 'agent7'];
const FINISHED_AGENT_STATUSES = new Set([
  'COMPLETED',
  'SUCCESS',
  'NEEDS_REVIEW',
  'PARTIAL_SUCCESS',
  'COMPLETED_WITH_FINDINGS',
  'COMPLETED_WITH_NO_FINDINGS',
  'NO_CLAIMS',
]);
const FINISHED_AGENT7_STATUSES = new Set([
  'COMPLETED',
  'SUCCESS',
  'NEEDS_REVIEW',
  'NO_CLAIMS',
  'PARTIAL_SUCCESS',
]);

/**
 * Checks whether a single multi-agent pipeline stage has reached a finished terminal state
 * (including NEEDS_REVIEW and PARTIAL_SUCCESS alongside COMPLETED/SUCCESS).
 */
export function isAgentStageFinished(status) {
  return FINISHED_AGENT_STATUSES.has(String(status || '').trim().toUpperCase());
}

/**
 * Verifies whether all 8 reasoning agents completed and produced findings, claims, or synthesis.
 */
export function isAgentSwarmComplete(agentSummary, fallbackFindingsCount = 0) {
  if (!agentSummary) return false;
  const topStatus = String(agentSummary.status || '').trim().toUpperCase();
  if (['RUNNING', 'PROCESSING', 'FAILED', 'ERROR', 'STOPPED', 'CANCELLED'].includes(topStatus)) {
    return false;
  }
  const stageStatuses = agentSummary.stage_statuses || {};
  const allDone = AGENT_PIPELINE_KEYS.every((k) => isAgentStageFinished(stageStatuses[k]));
  const ag7 = String(stageStatuses.agent7 || '').trim().toUpperCase();
  const hasStageClaims = AGENT_PIPELINE_KEYS.some(
    (k) => Array.isArray(agentSummary[k]?.claims) && agentSummary[k].claims.length > 0
  );
  const hasVerification = Array.isArray(agentSummary.verification_results) && agentSummary.verification_results.length > 0;
  const hasSynthesis = Boolean(agentSummary.supervisor_synthesis && Object.keys(agentSummary.supervisor_synthesis).length > 0);
  const cleanNoFindingsRun =
    (agentSummary.evidence_count || 0) > 0 &&
    (ag7 === 'NO_CLAIMS' || String(stageStatuses.agent3 || '').trim().toUpperCase() === 'COMPLETED_WITH_NO_FINDINGS');
  const hasOutput =
    fallbackFindingsCount > 0 ||
    (agentSummary.findings_count || 0) > 0 ||
    (agentSummary.claims?.length || 0) > 0 ||
    hasStageClaims ||
    hasVerification ||
    hasSynthesis ||
    cleanNoFindingsRun;
  return Boolean(allDone && FINISHED_AGENT7_STATUSES.has(ag7) && hasOutput);
}

/**
 * Resolves authoritative investigation report submission and escalation status
 * by combining backend case state with browser localStorage records.
 */
export function getCaseSubmissionState(caseObjOrSummary, explicitCaseId = null) {
  const caseObj = (caseObjOrSummary && typeof caseObjOrSummary === 'object') ? caseObjOrSummary : null;
  const caseId = explicitCaseId || caseObj?.case_id || '';

  let localSenior = null;
  let localAuditor = null;
  let localCertified = null;
  if (typeof localStorage !== 'undefined' && caseId) {
    try {
      const sRaw = localStorage.getItem(`argus_case_${caseId}_submitted_to_senior`);
      if (sRaw) localSenior = JSON.parse(sRaw);
    } catch (_) {}
    try {
      const aRaw = localStorage.getItem(`argus_case_${caseId}_submitted_to_auditor`);
      if (aRaw) localAuditor = JSON.parse(aRaw);
    } catch (_) {}
    try {
      const cRaw = localStorage.getItem(`argus_audit_certified_${caseId}`);
      if (cRaw) localCertified = JSON.parse(cRaw);
    } catch (_) {}
  }

  const auditCertified = Boolean(
    localCertified ||
    caseObj?.audit_certified ||
    caseObj?.is_certified
  );

  const submittedToAuditor = Boolean(
    localAuditor?.submitted ||
    caseObj?.submitted_to_auditor ||
    auditCertified
  );

  const isClosed = caseObj?.status === 'closed' || caseObj?.status === 'completed' || caseObj?.status === 'archived';
  const backendReportDone = caseObj?.investigation_progress?.report === 'completed';

  const submittedToSenior = Boolean(
    localSenior?.submitted ||
    caseObj?.submitted_to_senior ||
    caseObj?.has_report ||
    backendReportDone ||
    submittedToAuditor ||
    (isClosed && Boolean(caseObj?.has_report))
  );

  const isReportReady = Boolean(submittedToSenior || submittedToAuditor);

  return {
    submittedToSenior,
    submittedToAuditor,
    auditCertified,
    isReportReady,
    seniorData: localSenior || caseObj?.submitted_to_senior_data || (submittedToSenior ? { submitted: true } : null),
    auditorData: localAuditor || caseObj?.submitted_to_auditor_data || (submittedToAuditor ? { submitted: true } : null),
  };
}

