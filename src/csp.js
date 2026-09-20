export const NONE = '(none)';

const DIRECTIVE_NAMES = new Set([
  'base-uri',
  'block-all-mixed-content',
  'child-src',
  'connect-src',
  'default-src',
  'font-src',
  'eval-script',
  'frame-ancestors',
  'frame-src',
  'img-src',
  'manifest-src',
  'media-src',
  'navigate-to',
  'object-src',
  'plugin-types',
  'prefetch-src',
  'report-uri',
  'require-trusted-types-for',
  'sandbox',
  'script-src',
  'script-src-attr',
  'script-src-elem',
  'style-src',
  'style-src-attr',
  'style-src-elem',
  'upgrade-insecure-requests',
  'worker-src'
]);

const DIRECTIVE_ALIASES = new Map([
  ['base', 'base-uri'],
  ['connect', 'connect-src'],
  ['font', 'font-src'],
  ['frame', 'frame-src'],
  ['img', 'img-src'],
  ['manifest', 'manifest-src'],
  ['media', 'media-src'],
  ['object', 'object-src'],
  ['script', 'script-src'],
  ['style', 'style-src'],
  ['worker', 'worker-src']
]);

const FETCH_DIRECTIVES = new Set([
  'child-src',
  'connect-src',
  'font-src',
  'frame-src',
  'img-src',
  'manifest-src',
  'media-src',
  'object-src',
  'script-src',
  'script-src-elem',
  'style-src',
  'style-src-elem',
  'worker-src'
]);

const DIRECTIVE_LABELS = {
  'base-uri': 'base 标签地址',
  'child-src': 'Worker 与嵌入框架',
  'connect-src': '网络请求',
  'font-src': '字体',
  'frame-ancestors': '页面被嵌入来源',
  'frame-src': 'iframe',
  'img-src': '图片',
  'manifest-src': 'PWA Manifest',
  'media-src': '音视频',
  'object-src': '插件对象',
  'script-src': '脚本',
  'script-src-attr': '内联事件处理器',
  'script-src-elem': 'script 元素',
  'style-src': '样式',
  'style-src-attr': '内联 style 属性',
  'style-src-elem': 'style/link 样式元素',
  'worker-src': 'Worker'
};

export function text(value) {
  if (value === null || value === undefined) {
    return '';
  }
  return String(value);
}

export function safeText(value, limit = 300) {
  const normalized = text(value).replace(/\s+/g, ' ').trim();
  return normalized.length > limit ? `${normalized.slice(0, limit)}…` : normalized;
}

export function normalizeDirective(value) {
  const raw = text(value).trim().toLowerCase();
  if (!raw) {
    return '';
  }
  if (DIRECTIVE_NAMES.has(raw)) {
    return raw;
  }
  const [name] = raw.split(/\s+/, 1);
  if (DIRECTIVE_NAMES.has(name)) {
    return name;
  }
  return DIRECTIVE_ALIASES.get(name) || name;
}

export function isInlineBlockedDirective(directive) {
  return directive === 'script-src'
    || directive === 'script-src-attr'
    || directive === 'script-src-elem'
    || directive === 'style-src'
    || directive === 'style-src-attr'
    || directive === 'style-src-elem';
}

export function isScriptDirective(directive) {
  return directive === 'script-src'
    || directive === 'script-src-attr'
    || directive === 'script-src-elem'
    || directive === 'eval-script'
    || directive === 'require-trusted-types-for';
}

export function isStyleDirective(directive) {
  return directive === 'style-src'
    || directive === 'style-src-attr'
    || directive === 'style-src-elem';
}

export function isInlineSource(source) {
  const value = text(source);
  return value === '' || value === NONE || value.startsWith('inline');
}

export function isEvalSource(source, directive) {
  const value = text(source);
  if (value === 'eval' || value === 'wasm-unsafe-eval') {
    return true;
  }
  return directive === 'eval-script' || value.startsWith('eval');
}

export function isFetchDirective(directive) {
  return FETCH_DIRECTIVES.has(directive) || directive.endsWith('-src');
}

export function originOf(value) {
  const raw = text(value);
  if (!raw || raw === NONE) {
    return NONE;
  }
  try {
    return new URL(raw, selfLocationHref()).origin;
  } catch {
    return raw.split('/').slice(0, 3).join('/') || NONE;
  }
}

function selfLocationHref() {
  if (typeof globalThis.location !== 'undefined' && globalThis.location?.href) {
    return globalThis.location.href;
  }
  return 'http://localhost/';
}

export function pathOf(value) {
  const raw = text(value);
  if (!raw || raw === NONE) {
    return NONE;
  }
  try {
    const url = new URL(raw, selfLocationHref());
    return url.pathname === '/' ? '/' : url.pathname.replace(/\/+$/, '');
  } catch {
    return raw;
  }
}

export function classifySource({ directive, blockedURI, sourceFile, lineNumber, columnNumber, sample }) {
  const normalizedDirective = normalizeDirective(directive);
  const blocked = text(blockedURI);
  const file = text(sourceFile);
  const line = Number(lineNumber) || 0;
  const column = Number(columnNumber) || 0;
  const codeSample = safeText(sample, 120);

  if (isInlineSource(blocked)) {
    if (isScriptDirective(normalizedDirective) || /\bon(?:click|load|error|submit|change|input)\s*=/i.test(codeSample)) {
      return {
        kind: normalizedDirective === 'script-src-attr' || /\bon[a-z]+\s*=/i.test(codeSample) ? 'inline-handler' : 'inline-script',
        origin: originOf(file),
        file: file || NONE,
        path: file ? pathOf(file) : NONE,
        line,
        column,
        sample: codeSample
      };
    }
    if (isStyleDirective(normalizedDirective)) {
      return {
        kind: normalizedDirective === 'style-src-attr' ? 'inline-style-attribute' : 'inline-style',
        origin: originOf(file),
        file: file || NONE,
        path: file ? pathOf(file) : NONE,
        line,
        column,
        sample: codeSample
      };
    }
  }

  if (isEvalSource(blocked, normalizedDirective) || /^\s*(?:eval\s*\(|new\s+Function\b|setTimeout\s*\(\s*["'`])/.test(codeSample)) {
    return {
      kind: 'eval',
      origin: originOf(file),
      file: file || NONE,
      path: file ? pathOf(file) : NONE,
      line,
      column,
      sample: codeSample
    };
  }

  if (blocked.startsWith('data:')) {
    return {
      kind: 'data-url',
      origin: 'data:',
      file: blocked.slice(0, 80),
      path: 'data:',
      line: 0,
      column: 0,
      sample: codeSample
    };
  }

  if (isFetchDirective(normalizedDirective) && blocked) {
    return {
      kind: 'external-resource',
      origin: originOf(blocked),
      file: blocked,
      path: pathOf(blocked),
      line: 0,
      column: 0,
      sample: codeSample
    };
  }

  return {
    kind: normalizedDirective || 'other',
    origin: originOf(file || blocked),
    file: file || blocked || NONE,
    path: file ? pathOf(file) : NONE,
    line,
    column,
    sample: codeSample
  };
}

export function violationFingerprint(input) {
  const source = classifySource(input);
  return [
    normalizeDirective(input.directive),
    source.kind,
    normalizeBlocked(input.blockedURI, source.kind),
    normalizeFile(input.sourceFile, source.kind),
    source.kind === 'external-resource' ? 0 : source.line,
    normalizeExpression(text(input.sample), source.kind)
  ].join('|');
}

function normalizeBlocked(value, kind) {
  if (kind === 'external-resource') {
    const origin = originOf(value);
    return `${origin}${pathOf(value)}`;
  }
  return kind;
}

function normalizeFile(value, kind) {
  if (kind === 'external-resource' || kind === 'data-url') {
    return '';
  }
  const file = text(value);
  return file ? `${originOf(file)}${pathOf(file)}` : NONE;
}

function normalizeExpression(value, kind) {
  if (kind === 'inline-handler') {
    const match = value.match(/\bon([a-z]+)\s*=/i);
    return match ? `on${match[1].toLowerCase()}` : 'inline-handler';
  }
  if (kind === 'inline-script') {
    return stableHash(value.replace(/\s+/g, ' ').trim().slice(0, 500));
  }
  if (kind === 'eval') {
    const compact = value.replace(/\s+/g, ' ').trim();
    if (/^eval\b/.test(compact)) {
      return 'eval';
    }
    if (/^new\s+Function\b/.test(compact)) {
      return 'function-constructor';
    }
    return stableHash(compact.slice(0, 500));
  }
  return '';
}

export function stableHash(value) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(36).padStart(7, '0');
}

export function directiveLabel(directive) {
  return DIRECTIVE_LABELS[normalizeDirective(directive)] || directive;
}

export function currentScriptNonce() {
  return text(document.currentScript?.nonce || '');
}

export async function generateNonce() {
  if (typeof globalThis.crypto?.getRandomValues === 'function') {
    const bytes = new Uint8Array(16);
    globalThis.crypto.getRandomValues(bytes);
    const binary = String.fromCharCode(...bytes);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  return `${Date.now().toString(36)}-${stableHash(Math.random().toString()).padStart(7, '0')}`;
}

export function serializeViolation(event, extra = {}) {
  const fields = [
    'blockedURI',
    'columnNumber',
    'disposition',
    'documentURI',
    'effectiveDirective',
    'lineNumber',
    'originalPolicy',
    'referrer',
    'sample',
    'sourceFile',
    'statusCode',
    'violatedDirective'
  ];
  const result = {};
  for (const field of fields) {
    result[field] = event?.[field] ?? '';
  }
  return {
    ...result,
    isTrusted: Boolean(event?.isTrusted),
    ...extra
  };
}
