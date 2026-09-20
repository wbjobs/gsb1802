// Module worker: receives normalized violations from the main thread and runs
// all IndexedDB and report-building work off the UI thread.

import { CspController } from './controller.js';

const controller = new CspController(self.indexedDB);

// Serialize messages: overlapping readwrite IndexedDB transactions would risk
// abort errors under a burst of violations.
let chain = Promise.resolve();

function reply(id, ok, payload) {
  self.postMessage({ id, ok, payload: ok ? payload : { message: String(payload && payload.message || payload) } });
}

function enqueue(message, task) {
  chain = chain.then(async () => {
    try {
      const payload = await task();
      reply(message.id, true, payload);
    } catch (err) {
      reply(message.id, false, err);
    }
  });
}

self.onmessage = (e) => {
  const msg = e.data || {};
  switch (msg.type) {
    case 'init':
      enqueue(msg, async () => {
        await controller.init(msg.pageOrigin);
        return { ready: true };
      });
      break;
    case 'ingest':
      enqueue(msg, () => controller.ingest(msg.events || []));
      break;
    case 'dashboard':
      enqueue(msg, () => controller.dashboard(msg.options || {}));
      break;
    case 'export':
      enqueue(msg, async () => {
        const report = await controller.exportReport(msg.format);
        // Transfer the string back; UI turns it into a Blob download.
        return { format: msg.format, mime: report.mime, ext: report.ext, content: report.content };
      });
      break;
    case 'clear':
      enqueue(msg, async () => {
        await controller.clear();
        return { cleared: true };
      });
      break;
    default:
      reply(msg.id, false, new Error(`unknown message type: ${msg.type}`));
  }
};
