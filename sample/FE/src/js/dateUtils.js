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
    if (isNaN(d.getTime())) {
      return options.fallback || String(rawDate);
    }

    const locale = options.locale || 'en-US';

    if (options.timeOnly) {
      return d.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit', ...options.opts });
    }

    if (options.dateOnly) {
      return d.toLocaleDateString(locale, { month: 'short', day: 'numeric', year: 'numeric', ...options.opts });
    }

    return d.toLocaleString(locale, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      ...options.opts
    });
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
