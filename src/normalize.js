// Pure normalization layer: turns a SecurityPolicyViolationEvent (or a plain
// object with the same camelCase fields) into a compact, serializable record.
// No DOM access here so the module is unit-testable in Node.

const INLINE_PATTERNS = [
  /^data:/i,
  /^blob:/i,
  /^javascript:/i,
];

export const RESOURCE_TYPES = {
  script: ['script-src', 'script-src-elem', 'script-src-attr'],
  style: ['style-src', 'style-src-elem', 'style-src-attr'],
  image: ['img-src'],
  font: ['font-src'],
  xhr: ['connect-src'],
  websocket: ['connect-src'],
  frame: ['frame-src', 'child-src'],
  worker: ['worker-src', 'child-src'],
  media: ['media-src'],
  object: ['object-src'],
  manifest: ['manifest-src'],
};

export function isInlineSource(uri, effectiveDirective) {
  if (!uri) return true;
  if (uri === 'inline' || uri === 'eval' || uri === 'self' || uri === 'data') return true;
  if (INLINE_PATTERNS.some((re) => re.test(uri))) return true;
  if (effectiveDirective && !/\/|:/.test(uri)) return true;
  return false;
}

export function resourceTypeFor(effectiveDirective) {
  for (const [type, directives] of Object.entries(RESOURCE_TYPES)) {
    if (directives.includes(effectiveDirective)) return type;
  }
  if (effectiveDirective === 'default-src') return 'other';
  if (effectiveDirective === 'base-uri') return 'base';
  if (effectiveDirective === 'form-action') return 'form';
  if (effectiveDirective === 'frame-ancestors') return 'frame-ancestor';
  if (effectiveDirective === 'report-uri' || effectiveDirective === 'report-to') return 'report';
  return 'other';
}

export function tryParseUrl(uri, base) {
  if (!uri) return null;
  try {
    return new URL(uri, base || undefined);
  } catch {
    return null;
  }
}

export function classifyBlocked(uri, effectiveDirective, baseUri) {
  if (uri == null || uri === '') {
    return { kind: 'inline', origin: null, url: null };
  }
  if (uri === 'eval') return { kind: 'eval', origin: null, url: null };
  if (/^data:/i.test(uri)) return { kind: 'data-uri', origin: 'null', url: uri };
  if (/^blob:/i.test(uri)) {
    const inner = tryParseUrl(uri.replace(/^blob:/i, ''), baseUri);
    return { kind: 'blob-uri', origin: inner ? inner.origin : null, url: uri };
  }
  if (/^javascript:/i.test(uri)) return { kind: 'inline', origin: null, url: uri };
  const parsed = tryParseUrl(uri, baseUri || undefined);
  if (parsed) return { kind: 'url', origin: parsed.origin, url: parsed.href };
  // Relative / bare token that URL cannot resolve without a base.
  if (isInlineSource(uri, effectiveDirective)) {
    return { kind: 'inline', origin: null, url: uri };
  }
  return { kind: 'other', origin: null, url: uri };
}

function dispositionOf(value) {
  if (value === 'report') return 'report';
  return 'enforce';
}

function readFields(e) {
  // Browser events expose camelCase; defensive fallbacks cover older engines.
  return {
    documentUri: e.documentURI ?? e.documentUri ?? '',
    referrer: e.referrer ?? '',
    blockedUri: e.blockedURI ?? e.blockedUri ?? '',
    violatedDirective: e.violatedDirective ?? e.violated-directive ?? '',
    effectiveDirective:
      e.effectiveDirective ??
      e['effective-directive'] ??
      e.violatedDirective ??
      '',
    originalPolicy: e.originalPolicy ?? '',
    sourceFile: e.sourceFile ?? '',
    sample: e.sample ?? '',
    disposition: e.disposition ?? 'enforce',
    statusCode: Number(e.statusCode ?? 0),
    lineNumber: Number(e.lineNumber ?? 0),
    columnNumber: Number(e.columnNumber ?? 0),
  };
}

export function normalizeEvent(eventLike, context = {}) {
  const f = readFields(eventLike);
  const docUrl = tryParseUrl(f.documentUri, context.documentBase);
  const pageOrigin = docUrl ? docUrl.origin : context.pageOrigin || null;
  const blocked = classifyBlocked(f.blockedUri, f.effectiveDirective, f.documentUri || context.documentBase);
  const resourceType = resourceTypeFor(f.effectiveDirective);
  const sourceFileUrl = f.sourceFile ? tryParseUrl(f.sourceFile, f.documentUri || context.documentBase) : null;

  return {
    id: context.id || null,
    ts: context.ts || Date.now(),
    pageOrigin,
    documentUri: f.documentUri,
    referrer: f.referrer,
    blockedUri: f.blockedUri,
    blockedKind: blocked.kind,
    blockedOrigin: blocked.origin,
    effectiveDirective: f.effectiveDirective,
    violatedDirective: f.violatedDirective,
    resourceType,
    originalPolicy: f.originalPolicy,
    sourceFile: f.sourceFile,
    sourceOrigin: sourceFileUrl ? sourceFileUrl.origin : pageOrigin,
    lineNumber: f.lineNumber,
    columnNumber: f.columnNumber,
    sample: f.sample,
    disposition: dispositionOf(f.disposition),
    statusCode: f.statusCode,
  };
}
