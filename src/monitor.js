// Main-thread entry point. Captures SecurityPolicyViolationEvents, normalizes
// them and hands plain objects to the worker in timed micro-batches.

import { normalizeEvent } from './normalize.js';

const DEFAULT_OPTIONS = {
  workerUrl: new URL('./worker.js', import.meta.url).href,
  batchMs: 1000,
  maxBatch: 100,
  autoStart: true,
};

export class CspMonitor {
  constructor(options = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.worker = null;
    this.buffer = [];
    this.flushTimer = 0;
    this.pending = new Map();
    this.seq = 0;
    this.started = false;
    this.listeners = new Set();
    if (this.options.autoStart) this.start();
  }

  start() {
    if (this.started) return;
    this.started = true;
    this.worker = new Worker(this.options.workerUrl, { type: 'module' });
    this.worker.onmessage = (e) => this._onWorkerMessage(e.data);
    this.worker.onerror = (e) => this._emit('workererror', { message: e.message });

    this._call('init', { pageOrigin: location.origin }).catch((err) => {
      this._emit('error', new Error(`worker init failed: ${err.message}`));
    });

    // Capture phase catches events even if page code stops propagation.
    this._handler = (event) => this.capture(event);
    document.addEventListener('securitypolicyviolation', this._handler, true);
    // The boot.js listener now forwards to us; remove it so later events are
    // delivered exactly once.
    if (window.__cspBootListener) {
      document.removeEventListener('securitypolicyviolation', window.__cspBootListener, true);
    }
    window.__cspMonitorCapture = (event) => this.capture(event);

    const early = window.__cspEarlyEvents || [];
    window.__cspEarlyEvents = [];
    early.forEach((event) => this.capture(event));

    // Best-effort flush before the page is suspended/destroyed.
    this._flushOnHide = () => {
      if (document.visibilityState === 'hidden') this.flush();
    };
    document.addEventListener('visibilitychange', this._flushOnHide, true);
    window.addEventListener('pagehide', this.flush.bind(this), true);
  }

  capture(eventLike) {
    if (!eventLike) return;
    const normalized = normalizeEvent(eventLike, {
      ts: Date.now(),
      pageOrigin: location.origin,
      documentBase: document.baseURI,
    });
    this.buffer.push(normalized);
    this._emit('event', normalized);
    if (this.buffer.length >= this.options.maxBatch) {
      this.flush();
    } else if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => this.flush(), this.options.batchMs);
    }
  }

  flush() {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = 0;
    }
    if (!this.buffer.length) return Promise.resolve();
    const events = this.buffer;
    this.buffer = [];
    return this._call('ingest', { events })
      .then((res) => {
      this._emit('ingested', res);
      this._scheduleDashboardSoon();
      })
      .catch((err) => {
        // Put events back so a transient worker failure doesn't lose data.
        this.buffer = events.concat(this.buffer);
        this._emit('error', err);
      });
  }

  _dashboardScheduled = false;
  _scheduleDashboardSoon() {
    if (this._dashboardScheduled) return;
    this._dashboardScheduled = true;
    setTimeout(() => {
      this._dashboardScheduled = false;
      this._emit('dirty');
    }, 250);
  }

  getDashboard(options) {
    return this._call('dashboard', { options: { includeEvents: true, eventLimit: 500, ...options } });
  }

  exportReport(format = 'json') {
    return this._call('export', { format });
  }

  clear() {
    this.buffer = [];
    return this._call('clear', {});
  }

  on(type, fn) {
    const entry = { type, fn };
    this.listeners.add(entry);
    return () => this.listeners.delete(entry);
  }

  _emit(type, payload) {
    for (const l of [...this.listeners]) if (l.type === type) l.fn(payload);
  }

  _call(type, payload = {}) {
    const id = ++this.seq;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, type, ...payload });
    });
  }

  _onWorkerMessage(msg) {
    const pending = this.pending.get(msg.id);
    if (!pending) return;
    this.pending.delete(msg.id);
    if (msg.ok) pending.resolve(msg.payload);
    else pending.reject(new Error(msg.payload && msg.payload.message));
  }
}

export function createMonitor(options) {
  return new CspMonitor(options);
}
