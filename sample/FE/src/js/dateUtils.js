/**
 * ARGUS Safe Date & Time Formatting Utilities
 * Handles raw ISO strings, SQL timestamp strings, Unix timestamps, and null/undefined values safely.
 */

export function safeFormatDate(rawDate, options = {}) {
  if (rawDate === null || rawDate === undefined || rawDate === '' || rawDate === '--') {
    return options.fallback || '-';
  }

  try {
    let str = String(rawDate).trim();

    // Fix SQL timestamp strings like "2026-10-10 19:18:25" -> "2026-10-10T19:18:25"
    if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}/.test(str)) {
      str = str.replace(/\s+/, 'T');
    }

    const d = new Date(str);
    if (typeof rawDate === 'string' && rawDate.includes('IST')) {
      return rawDate;
    }

    if (isNaN(d.getTime())) {
      return options.fallback || String(rawDate);
    }

    const locale = options.locale || 'en-IN';
    const tzOptions = { timeZone: 'Asia/Kolkata', ...options.opts };

    if (options.timeOnly) {
      return d.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit', second: '2-digit', ...tzOptions }) + ' IST';
    }

    if (options.dateOnly) {
      return d.toLocaleDateString(locale, { month: 'short', day: 'numeric', year: 'numeric', ...tzOptions });
    }

    return d.toLocaleString(locale, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      ...tzOptions
    }) + ' IST';
  } catch (e) {
    return options.fallback || '-';
  }
}

export function safeFormatTime(rawDate, fallback = '--:--') {
  return safeFormatDate(rawDate, { timeOnly: true, fallback });
}

export function safeFormatDateOnly(rawDate, fallback = '-') {
  return safeFormatDate(rawDate, { dateOnly: true, fallback });
}

export function safeFormatDateTime(rawDate, fallback = '-') {
  return safeFormatDate(rawDate, { fallback });
}

/**
 * Format an evidence ID to a clean, compact string starting with 'e-'.
 * Prioritizes short sequential format like 'e-01', 'e-02', etc.
 * 
 * @param {string|number} id - The raw evidence ID or identifier.
 * @param {number} [fallbackIndex] - 1-based sequential index (e.g., 1 -> "e-01").
 * @returns {string} Clean, formatted evidence ID like "e-01".
 */
export function formatEvidenceId(id, fallbackIndex = null) {
  if (fallbackIndex != null && Number.isInteger(Number(fallbackIndex)) && Number(fallbackIndex) > 0) {
    return `e-${String(fallbackIndex).padStart(2, '0')}`;
  }
  if (!id) return '-';
  const str = String(id).trim();

  // If already like "e-01", "e-1", "e-02", "EVID-001", "EV-1"
  const numMatch = str.match(/^(?:ev(?:id)?[-_]?|e[-_]?)0*(\d+)$/i);
  if (numMatch) {
    return `e-${numMatch[1].padStart(2, '0')}`;
  }

  // If pure numeric string or number
  if (/^\d+$/.test(str)) {
    return `e-${str.padStart(2, '0')}`;
  }

  // If already short e- prefixed hex/hash like "e-1f061460"
  if (/^e-[a-f0-9]{4,12}$/i.test(str)) {
    return str.toLowerCase();
  }

  // If starts with "e-"
  if (str.toLowerCase().startsWith('e-')) {
    const rest = str.slice(2).replace(/[^a-zA-Z0-9]/g, '');
    return `e-${rest.slice(0, 8).toLowerCase()}`;
  }

  // For general UUID or other raw IDs, clean and take first short segment
  const clean = str.replace(/^ev(?:id)?[-_]?/i, '').replace(/[^a-zA-Z0-9]/g, '');
  return `e-${clean.slice(0, 8).toLowerCase()}`;
}
