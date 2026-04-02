/**
 * Defang utilities — safe display of IOC values in UI.
 * Never render a raw clickable URL or domain.
 */

/**
 * Defang an IOC value for safe display.
 * @param {string} value
 * @param {string} type - ioc type: ipv4, domain, url, sha256, sha1, md5
 * @returns {string}
 */
export function defang(value, type) {
  if (!value) return '';

  switch (type) {
    case 'ipv4':
      return value.replace(/\./g, '[.]');
    case 'domain':
      return value.replace(/\./g, '[.]');
    case 'url':
      // Replace protocol and dots in domain portion
      return value
        .replace(/^https?:\/\//i, (m) => m.replace('http', 'hxxp'))
        .replace(/\./g, '[.]');
    case 'sha256':
    case 'sha1':
    case 'md5':
      // Hashes are safe to display as-is
      return value;
    default:
      // Generic defang: replace dots and http
      return value
        .replace(/^https?:\/\//i, (m) => m.replace('http', 'hxxp'))
        .replace(/\./g, '[.]');
  }
}

/**
 * Truncate a long IOC value for display (e.g. long hashes).
 * @param {string} value
 * @param {number} maxLen
 * @returns {string}
 */
export function truncate(value, maxLen = 48) {
  if (!value || value.length <= maxLen) return value;
  return `${value.slice(0, maxLen / 2)}...${value.slice(-maxLen / 4)}`;
}

/**
 * Defang and truncate for compact display in tables.
 */
export function defangTruncate(value, type, maxLen = 48) {
  return truncate(defang(value, type), maxLen);
}
