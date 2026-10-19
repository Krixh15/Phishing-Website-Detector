/**
 * features.js
 * Browser-side implementation of the 10 URL feature extraction functions.
 * Must match ml/extract_features.py identically.
 */

(function (global) {
  'use strict';

  // Exact 10 feature names in fixed order
  const FEATURE_NAMES = [
    'url_length',
    'hostname_length',
    'dot_count',
    'hyphen_count',
    'subdomain_count',
    'has_ip',
    'has_https',
    'has_suspicious_keyword',
    'has_at_symbol',
    'digits_in_hostname'
  ];

  const SUSPICIOUS_KEYWORDS = [
    'login',
    'verify',
    'update',
    'secure',
    'account',
    'banking',
    'signin',
    'confirm',
    'password',
    'credential',
    'billing'
  ];

  const TWO_PART_TLDS = new Set([
    'co.uk', 'com.au', 'gov.in', 'ac.in', 'co.in', 'edu.in', 'org.uk', 'edu.au',
    'net.au', 'co.nz', 'com.br', 'co.za', 'com.sg', 'com.mx', 'gov.uk'
  ]);

  const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

  /**
   * Prepends http:// if scheme is missing so URL constructor parses host correctly.
   */
  function normalizeUrl(urlStr) {
    if (!urlStr || typeof urlStr !== 'string') return '';
    urlStr = urlStr.trim();
    if (!/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(urlStr)) {
      urlStr = 'http://' + urlStr;
    }
    return urlStr;
  }

  /**
   * Extracts lowercase hostname from URL string without port.
   */
  function getHostname(urlStr) {
    const normalized = normalizeUrl(urlStr);
    try {
      const parsed = new URL(normalized);
      return (parsed.hostname || '').toLowerCase();
    } catch (e) {
      // Fallback regex if URL constructor fails
      const match = normalized.match(/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\/([^/?#:]+)/);
      return match ? match[1].toLowerCase() : '';
    }
  }

  /**
   * Checks whether the hostname is an IPv4 address.
   */
  function isIpAddress(hostname) {
    if (!hostname) return 0;
    return IPV4_REGEX.test(hostname) ? 1 : 0;
  }

  /**
   * Counts subdomains in the hostname.
   */
  function countSubdomains(hostname) {
    if (!hostname || isIpAddress(hostname)) return 0;

    const parts = hostname.split('.').filter(Boolean);
    if (parts.length <= 2) return 0;

    const suffix = (parts[parts.length - 2] + '.' + parts[parts.length - 1]).toLowerCase();
    if (TWO_PART_TLDS.has(suffix) && parts.length >= 3) {
      return Math.max(0, parts.length - 3);
    }

    return Math.max(0, parts.length - 2);
  }

  /**
   * Counts character occurrences in a string.
   */
  function countOccurrences(str, char) {
    let count = 0;
    for (let i = 0; i < str.length; i++) {
      if (str[i] === char) count++;
    }
    return count;
  }

  /**
   * Counts numeric digits in a string.
   */
  function countDigits(str) {
    let count = 0;
    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      if (code >= 48 && code <= 57) count++;
    }
    return count;
  }

  /**
   * Extracts all 10 features as a dictionary.
   */
  function extractFeatures(urlStr) {
    if (!urlStr || typeof urlStr !== 'string') {
      const empty = {};
      FEATURE_NAMES.forEach(f => { empty[f] = 0; });
      return empty;
    }

    urlStr = urlStr.trim();
    const hostname = getHostname(urlStr);
    const urlLower = urlStr.toLowerCase();

    const urlLength = urlStr.length;
    const hostnameLength = hostname.length;
    const dotCount = countOccurrences(urlStr, '.');
    const hyphenCount = countOccurrences(urlStr, '-');
    const subdomainCount = countSubdomains(hostname);
    const hasIp = isIpAddress(hostname);
    const hasHttps = urlLower.startsWith('https://') ? 1 : 0;
    const hasSuspiciousKeyword = SUSPICIOUS_KEYWORDS.some(kw => urlLower.includes(kw)) ? 1 : 0;
    const hasAtSymbol = urlStr.includes('@') ? 1 : 0;
    const digitsInHostname = countDigits(hostname);

    return {
      url_length: urlLength,
      hostname_length: hostnameLength,
      dot_count: dotCount,
      hyphen_count: hyphenCount,
      subdomain_count: subdomainCount,
      has_ip: hasIp,
      has_https: hasHttps,
      has_suspicious_keyword: hasSuspiciousKeyword,
      has_at_symbol: hasAtSymbol,
      digits_in_hostname: digitsInHostname
    };
  }

  /**
   * Returns ordered feature array matching FEATURE_NAMES.
   */
  function extractFeaturesVector(urlStr) {
    const feat = extractFeatures(urlStr);
    return FEATURE_NAMES.map(name => feat[name]);
  }

  /**
   * Generates clear, human-readable explanations based on detected features.
   */
  function explainFeatures(urlStr, feat) {
    if (!feat) feat = extractFeatures(urlStr);
    const reasons = [];

    if (feat.has_ip === 1) {
      reasons.push('Uses a raw IP address instead of a standard domain name.');
    }
    if (feat.has_at_symbol === 1) {
      reasons.push('Contains an "@" symbol, which can mask the true destination domain.');
    }
    if (feat.subdomain_count >= 2) {
      reasons.push(`Contains multiple subdomains (${feat.subdomain_count}), commonly seen in brand impersonation.`);
    }
    if (feat.has_suspicious_keyword === 1) {
      reasons.push('Contains credential-harvesting keywords (e.g., login, verify, secure, account).');
    }
    if (feat.hyphen_count >= 3) {
      reasons.push(`Excessive hyphens (${feat.hyphen_count}) detected in the address.`);
    }
    if (feat.digits_in_hostname >= 4) {
      reasons.push(`High count of numbers in hostname (${feat.digits_in_hostname} digits).`);
    }
    if (feat.url_length > 75) {
      reasons.push(`Unusually long web address (${feat.url_length} characters).`);
    }
    if (feat.has_https === 0) {
      reasons.push('Connection is unencrypted (HTTP rather than HTTPS).');
    }

    if (reasons.length === 0) {
      reasons.push('Standard domain structure with no suspicious indicators detected.');
    }

    return reasons;
  }

  // Export for browser window and Node.js test environment
  const api = {
    FEATURE_NAMES,
    SUSPICIOUS_KEYWORDS,
    normalizeUrl,
    getHostname,
    isIpAddress,
    countSubdomains,
    extractFeatures,
    extractFeaturesVector,
    explainFeatures
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (typeof global !== 'undefined') {
    global.PhishingFeatures = api;
  }
})(typeof window !== 'undefined' ? window : globalThis);
