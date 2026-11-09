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

