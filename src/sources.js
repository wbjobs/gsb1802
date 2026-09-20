// Origin / source analysis: first- vs third-party split, host categorization
// and directive breakdown across either normalized events or aggregates.

const CATEGORY_RULES = [
  ['analytics', /(google-analytics|googletagmanager|doubleclick|analytics|mixpanel|segment|plausible|matomo|hotjar|clarity)/i],
  ['cdn', /(cdn|jsdelivr|unpkg|cdnjs|cloudfront|akamaihd|fastly|netlify)/i],
  ['social', /(facebook|twitter|x\.com|linkedin|instagram|tiktok|youtube)/i],
  ['ads', /(adservice|adsystem|adnxs|ads|doubleclick)/i],
  ['fonts', /(fonts\.googleapis|fonts\.gstatic|typekit|fontawesome)/i],
];

export function isFirstParty(origin, pageOrigin) {
  if (!origin || origin === 'null') return false;
  if (!pageOrigin) return false;
  if (origin === pageOrigin) return true;
  try {
    const a = new URL(origin);
    const b = new URL(pageOrigin);
    return registrableDomain(a.hostname) === registrableDomain(b.hostname);
  } catch {
    return false;
  }
}

// Crude eTLD+1: good enough for grouping, not for cookie scoping.
export function registrableDomain(hostname) {
  const multiPartTlds = new Set(['co.uk', 'com.cn', 'co.jp', 'com.au', 'co.kr', 'com.br']);
  const parts = hostname.toLowerCase().split('.');
  if (parts.length <= 2) return hostname;
  const tail = parts.slice(-2).join('.');
  if (multiPartTlds.has(tail) && parts.length >= 3) return parts.slice(-3).join('.');
  return tail;
}

export function categorizeHost(host) {
  for (const [category, re] of CATEGORY_RULES) {
    if (re.test(host)) return category;
  }
  return 'other';
}

function bump(map, key, n = 1) {
  map.set(key, (map.get(key) || 0) + n);
}

function topEntries(map, limit = 20) {
  return [...map.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
    .slice(0, limit);
}

// Accepts normalized events (count each once) or aggregates weighted by .count.
export function analyzeOrigins(items, { pageOrigin, weighted = false } = {}) {
  const origins = new Map();
  const categories = new Map();
  const directives = new Map();
  const sourceFiles = new Map();
  let firstParty = 0;
  let thirdParty = 0;
  let inline = 0;
  let total = 0;

  for (const item of items) {
    const weight = weighted ? item.count : 1;
    total += weight;
    bump(directives, item.effectiveDirective || 'unknown', weight);
    const src = item.sourceFile || '(inline / blocked)';
    bump(sourceFiles, src, weight);

    const origin = item.blockedOrigin;
    if (!origin || origin === 'null' || item.blockedKind === 'inline' || item.blockedKind === 'eval') {
      inline += weight;
      continue;
    }
    bump(origins, origin, weight);
    let host;
    try {
      host = new URL(origin).host;
    } catch {
      host = origin;
    }
    bump(categories, categorizeHost(host), weight);
    if (isFirstParty(origin, pageOrigin || item.pageOrigin)) firstParty += weight;
    else thirdParty += weight;
  }

  return {
    total,
    firstParty,
    thirdParty,
    inline,
    topOrigins: topEntries(origins),
    categories: topEntries(categories),
    directives: topEntries(directives),
    topSourceFiles: topEntries(sourceFiles, 10),
  };
}
