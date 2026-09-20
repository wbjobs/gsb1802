(() => {
  const queue = [];

  window.__CSP_QUEUE__ = queue;
  window.__CSP_NONCE__ = document.currentScript?.nonce || '';

  document.addEventListener('securitypolicyviolation', (event) => {
    try {
      Object.defineProperty(event, '__cspSeen', { value: true, configurable: true });
    } catch {
      event.__cspSeen = true;
    }
    queue.push({
      occurredAt: Date.now(),
      blockedURI: event.blockedURI || '',
      columnNumber: event.columnNumber || 0,
      disposition: event.disposition || '',
      documentURI: event.documentURI || '',
      effectiveDirective: event.effectiveDirective || '',
      lineNumber: event.lineNumber || 0,
      originalPolicy: event.originalPolicy || '',
      referrer: event.referrer || '',
      sample: event.sample || '',
      sourceFile: event.sourceFile || '',
      statusCode: event.statusCode || 0,
      violatedDirective: event.violatedDirective || '',
      isTrusted: event.isTrusted !== false
    });
  }, true);
})();
