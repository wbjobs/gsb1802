// Turns an aggregate into an actionable fix: severity, explanation, a policy
// snippet and copy-pasteable before/after code. Pure and deterministic.

const DIRECTIVE_LABEL = {
  'script-src': 'scripts',
  'script-src-elem': 'script elements',
  'script-src-attr': 'inline event handlers',
  'style-src': 'styles',
  'style-src-elem': 'style elements',
  'style-src-attr': 'inline style attributes',
  'img-src': 'images',
  'font-src': 'fonts',
  'connect-src': 'XHR/fetch/WebSocket connections',
  'frame-src': 'frames',
  'child-src': 'workers/frames',
  'worker-src': 'workers',
  'media-src': 'media',
  'object-src': 'plugins/objects',
  'manifest-src': 'manifests',
  'default-src': 'resources (default-src fallback)',
  'base-uri': '<base> URLs',
  'form-action': 'form submissions',
  'frame-ancestors': 'embedding pages',
};

// Directives where 'unsafe-inline' / 'unsafe-eval' are even meaningful.
function directiveLabel(d) {
  return DIRECTIVE_LABEL[d] || d || 'resources';
}

function hostFromOrigin(agg) {
  try {
    return new URL(agg.blockedOrigin || agg.blockedUri).host;
  } catch {
    return agg.blockedOrigin || agg.blockedUri;
  }
}

export function suggest(agg) {
  const d = agg.effectiveDirective || 'default-src';
  const label = directiveLabel(d);

  if (agg.blockedKind === 'inline' && d.startsWith('script')) {
    const handler = /attr$/.test(d) ? 'an inline event handler (e.g. onclick="...")' : 'an inline <script> block';
    return {
      id: 'inline-script-nonce',
      severity: 'high',
      title: 'Allow inline scripts with a per-response nonce',
      description:
        `CSP blocked ${handler}. A random per-response nonce keeps inline ` +
        'bootstrapping code working while still blocking injected scripts ' +
        '(attacker cannot guess the nonce). Prefer nonce over hashes for ' +
        'frequently changing code; move code to an external file when possible.',
      policySnippet: `${d} 'self' 'nonce-CHANGE_ME_BASE64'`,
      before: '<script>startApp();</script>\n<button onclick="doStuff()">x</button>',
      after:
        '<script nonce="CHANGE_ME_BASE64">startApp();</script>\n' +
        '<button id="btn">x</button>\n' +
        '<script nonce="CHANGE_ME_BASE64">\n' +
        '  document.getElementById("btn").addEventListener("click", doStuff);\n' +
        '</script>',
      steps: [
        'Generate a fresh cryptographically random base64 nonce on every HTTP response.',
        "Put 'nonce-<value>' into " + d + " (or script-src) of the CSP header.",
        'Add the matching nonce="..." attribute to every trusted inline <script>.',
        'Rewrite inline event handlers (onclick="...") as addEventListener in a nonced script.',
        'Never use the same nonce across responses and never expose it to untrusted template data.',
      ],
      refs: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#using_nonces'],
    };
  }

  if (agg.blockedKind === 'eval' && d.startsWith('script')) {
    return {
      id: 'unsafe-eval',
      severity: 'high',
      title: 'Eliminate eval-like code, or scope a temporary unsafe-eval',
      description:
        'CSP blocked eval() / new Function() / setTimeout(string). Remove the ' +
        'dynamic evaluation if you can; libraries often support a CSP-safe build.',
      policySnippet: `${d} 'self' 'unsafe-eval'`,
      before: "const fn = new Function('a', 'return a + 1');\nsetTimeout('refresh()', 100);",
      after:
        'const fn = (a) => a + 1;\nsetTimeout(refresh, 100);',
      steps: [
        'Search the bundle for eval(, new Function(, setTimeout(" and setAttribute("on...").',
        "Upgrade templating libraries to precompiled modes that don't need new Function().",
        "Only if unavoidable, add 'unsafe-eval' temporarily and track removal; it re-enables most XSS impact.",
      ],
      refs: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe_eval_expressions'],
    };
  }

  if (agg.blockedKind === 'inline' && d.startsWith('style')) {
    return {
      id: 'inline-style-nonce',
      severity: 'medium',
      title: 'Allow trusted inline styles with nonce or hash',
      description:
        'CSP blocked inline CSS (a <style> block or style="" attribute). ' +
        'Nonce the trusted <style> blocks; for style attributes injected by a ' +
        'component library, evaluate the narrower impact before allowing unsafe-inline.',
      policySnippet: `${d} 'self' 'nonce-CHANGE_ME_BASE64'`,
      before: '<style>.x{color:red}</style>\n<div style="color:red"></div>',
      after:
        '<style nonce="CHANGE_ME_BASE64">.x{color:red}</style>\n' +
        '<div class="x"></div>',
      steps: [
        "Add 'nonce-<value>' to style-src and nonce attributes on trusted <style> tags.",
        'Move style="" attributes into classes where practical.',
      ],
      refs: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/style-src'],
    };
  }

  if (agg.blockedKind === 'url') {
    const host = hostFromOrigin(agg);
    return {
      id: 'allow-origin',
      severity: 'medium',
      title: `Allow the third-party origin ${host}`,
      description:
        `${label} were blocked while loading from ${host}. If this origin is ` +
        'expected, allowlist exactly that host (no wildcard where a host suffices).',
      policySnippet: `${d} 'self' https://${host}`,
      before: `Content-Security-Policy: ${d} 'self'`,
      after: `Content-Security-Policy: ${d} 'self' https://${host}`,
      steps: [
        `Confirm ${host} is a trusted provider for ${label} and review what data it receives.`,
        `Add https://${host} to ${d}; pin https:// and avoid wildcard subdomains unless required.`,
        'Ship the change first with Content-Security-Policy-Report-Only to watch for missed hosts.',
      ],
      refs: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP#using_content_security_policy'],
    };
  }

  if (agg.blockedKind === 'data-uri') {
    return {
      id: 'data-uri',
      severity: 'medium',
      title: 'Replace data: URIs or explicitly allow them',
      description:
        `CSP blocked a data: URL used for ${label}. Serve the asset over the ` +
        "same origin instead; only add data: to the directive if you control the contents.",
      policySnippet: `${d} 'self' data:`,
      before: '<img src="data:image/png;base64,...">',
      after: '<img src="/assets/sprite.png">',
      steps: [
        'Find the emitting code (often a bundler inline-image threshold) and raise the limit or host the file.',
        "If required, append data: to ${d} — note it broadens the attack surface for scripts/objects.",
      ],
      refs: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy'],
    };
  }

  if (agg.blockedKind === 'blob-uri') {
    return {
      id: 'blob-uri',
      severity: 'medium',
      title: 'Allow blob: resources or remove their usage',
      description: `CSP blocked a blob: URL used for ${label}.`,
      policySnippet: `${d} 'self' blob:`,
      before: 'const u = URL.createObjectURL(blob); el.src = u;',
      after: "// Serve the resource from a same-origin endpoint, or:\n" + `Content-Security-Policy: ${d} 'self' blob:`,
      steps: [
        'Verify the blob is created from same-origin/trusted data.',
        `Add blob: to ${d} if the pattern is intentional and safe.`,
      ],
      refs: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy'],
    };
  }

  return {
    id: 'generic-directive',
    severity: 'low',
    title: `Review the ${d} directive`,
    description: `CSP blocked ${label}. Inspect the blocked URI and source locations below and adjust ${d} to match intended behavior.`,
    policySnippet: `${d} 'self'`,
    before: '',
    after: '',
    steps: [
      'Open a representative location to see what the page tried to load.',
      `Tighten or extend ${d}, then validate via Report-Only before enforcing.`,
    ],
    refs: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy'],
  };
}

export function annotateAggregates(aggs) {
  return aggs.map((agg) => ({ ...agg, remediation: suggest(agg) }));
}
