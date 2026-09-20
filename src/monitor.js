import { currentScriptNonce, serializeViolation } from './csp.js';

const MAX_BATCH_SIZE = 100;
const MAX_QUEUE_SIZE = 2000;
const FLUSH_DELAY_MS = 500;

export function createCspMonitor({ workerUrl = './src/csp-worker.js', nonce = '' } = {}) {
  const queue = [];
  const listeners = new Set();
  const worker = new Worker(workerUrl, { type: 'module' });
  let flushTimer = 0;
  let flushing = false;
  let dropped = 0;
  let lastBatchDuration = 0;

  worker.postMessage({ type: 'INIT', nonce: nonce || currentScriptNonce() });
  worker.onmessage = (message) => {
    for (const listener of listeners) {
      listener(message.data);
    }
  };

  function enqueue(event, overrides = {}) {
    if (queue.length >= MAX_QUEUE_SIZE) {
      dropped += 1;
      worker.postMessage({ type: 'MARK_DROPPED', count: 1 });
      return;
    }
    queue.push({
      ...serializeViolation(event, overrides),
      occurredAt: overrides.occurredAt || Date.now(),
      pageUrl: overrides.pageUrl || globalThis.location?.href || '',
      userAgent: overrides.userAgent || globalThis.navigator?.userAgent || ''
    });
    scheduleFlush();
  }

  function scheduleFlush() {
    if (flushing || flushTimer) {
      return;
    }
    if (queue.length >= MAX_BATCH_SIZE) {
      void flush();
      return;
    }
    flushTimer = setTimeout(() => {
      flushTimer = 0;
      void flush();
    }, FLUSH_DELAY_MS);
  }

  async function flush() {
    if (flushing || !queue.length) {
      return;
    }
    flushing = true;
    const events = queue.splice(0, MAX_BATCH_SIZE);
    const loadTest = events.length > 1 && events.every((event) => event.loadTest);
    const started = performance.now();
    worker.postMessage({ type: 'REPORT_BATCH', events, loadTest });
    lastBatchDuration = performance.now() - started;
    flushing = false;
    if (queue.length) {
      scheduleFlush();
    }
  }

  function subscribe(listener) {
    listeners.add(listener);
    return () => listeners.delete(listener);
  }

  function drainEarlyQueue(earlyQueue) {
    if (!Array.isArray(earlyQueue)) {
      return 0;
    }
    for (const event of earlyQueue.splice(0)) {
      enqueue(event, { loadTest: Boolean(event.loadTest) });
    }
    return earlyQueue.length;
  }

  function send(message) {
    worker.postMessage(message);
  }

  function metrics() {
    return {
      queued: queue.length,
      dropped,
      lastBatchDuration,
      maxBatchSize: MAX_BATCH_SIZE,
      maxQueueSize: MAX_QUEUE_SIZE
    };
  }

  return {
    worker,
    enqueue,
    flush,
    subscribe,
    drainEarlyQueue,
    send,
    metrics
  };
}

export function bindDocumentListener(monitor, { passive = true } = {}) {
  const handler = (event) => {
    if (event.__cspSeen) {
      return;
    }
    monitor.enqueue(event);
  };
  document.addEventListener('securitypolicyviolation', handler, { capture: true, passive });
  return () => document.removeEventListener('securitypolicyviolation', handler, { capture: true });
}

export function simulateViolation(overrides = {}) {
  const event = new SecurityPolicyViolationEvent('securitypolicyviolation', {
    bubbles: true,
    cancelable: false,
    composed: true,
    blockedURI: overrides.blockedURI ?? '',
    columnNumber: overrides.columnNumber ?? 1,
    disposition: overrides.disposition ?? 'enforce',
    documentURI: globalThis.location.href,
    effectiveDirective: overrides.effectiveDirective ?? overrides.violatedDirective ?? 'script-src',
    lineNumber: overrides.lineNumber ?? 1,
    originalPolicy: overrides.originalPolicy ?? "script-src 'self'",
    referrer: '',
    sample: overrides.sample ?? "console.log('synthetic')",
    sourceFile: overrides.sourceFile ?? globalThis.location.href,
    statusCode: 200,
    violatedDirective: overrides.violatedDirective ?? 'script-src'
  });
  document.dispatchEvent(event);
  return event;
}

export function generateLoad(monitor, { count = 1000 } = {}) {
  const started = performance.now();
  const variants = [
    {
      violatedDirective: 'script-src',
      sample: "console.log('load-inline-a')",
      lineNumber: 11
    },
    {
      violatedDirective: 'script-src-attr',
      sample: 'onclick="return false"',
      lineNumber: 22
    },
    {
      violatedDirective: 'img-src',
      blockedURI: 'https://images.example.com/load.png',
      sample: ''
    }
  ];

  return new Promise((resolve) => {
    let remaining = count;
    const chunkSize = 100;
    function chunk() {
      const size = Math.min(chunkSize, remaining);
      for (let index = 0; index < size; index += 1) {
        const variant = variants[(count - remaining + index) % variants.length];
        monitor.enqueue({
          blockedURI: variant.blockedURI || '',
          columnNumber: 1,
          disposition: 'enforce',
          documentURI: globalThis.location.href,
          effectiveDirective: variant.violatedDirective,
          lineNumber: variant.lineNumber,
          originalPolicy: "default-src 'self'",
          referrer: '',
          sample: variant.sample,
          sourceFile: globalThis.location.href,
          statusCode: 200,
          violatedDirective: variant.violatedDirective,
          isTrusted: false
        }, { loadTest: true, occurredAt: Date.now() });
      }
      remaining -= size;
      if (remaining > 0) {
        requestAnimationFrame(chunk);
      } else {
        resolve({
          count,
          dispatchMs: performance.now() - started
        });
      }
    }
    chunk();
  });
}
