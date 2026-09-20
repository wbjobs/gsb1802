// Exercise the real src/worker.js message protocol inside Node with a mocked
// Worker global scope (self.postMessage + a fake IndexedDB).
import test from 'node:test';
import assert from 'node:assert/strict';
import { FakeIDBFactory, makeEvent } from './fake-idb.js';
import { normalizeEvent } from '../src/normalize.js';

async function bootWorker() {
  const replies = [];
  const scope = {
    indexedDB: new FakeIDBFactory(),
    postMessage: (msg) => replies.push(msg),
  };
  globalThis.self = scope;
  await import('../src/worker.js');
  return {
    scope,
    replies,
    send(message) {
      replies.length = 0;
      scope.onmessage({ data: message });
    },
    flush: () => new Promise((r) => setTimeout(r, 5)),
  };
}

test('worker init → ingest → dashboard → export → unknown message → clear', async () => {
  const w = await bootWorker();

  w.send({ id: 1, type: 'init', pageOrigin: 'https://app.example.com' });
  await w.flush();
  assert.equal(w.replies[0].ok, true);

  const events = [
    normalizeEvent(makeEvent({ blockedURI: '', effectiveDirective: 'script-src' }), { ts: 10 }),
    normalizeEvent(makeEvent({ blockedURI: '', effectiveDirective: 'script-src' }), { ts: 20 }),
    normalizeEvent(
      makeEvent({ blockedURI: 'https://www.google-analytics.com/a.js', effectiveDirective: 'script-src' }),
      { ts: 30 }
    ),
  ];
  w.send({ id: 2, type: 'ingest', events });
  await w.flush();
  assert.equal(w.replies[0].ok, true);
  assert.equal(w.replies[0].payload.ingested, 3);

  w.send({ id: 3, type: 'dashboard', options: { includeEvents: true, bucketMs: 60000 } });
  await w.flush();
  const dash = w.replies[0].payload;
  assert.equal(dash.summary.totalEvents, 3);
  assert.equal(dash.summary.totalIssues, 2);
  const inline = dash.aggregates.find((a) => a.blockedKind === 'inline');
  assert.equal(inline.count, 2);
  assert.equal(inline.remediation.id, 'inline-script-nonce');
  assert.equal(dash.events.length, 3);

  w.send({ id: 4, type: 'export', format: 'json' });
  await w.flush();
  const report = w.replies[0].payload;
  assert.equal(report.mime, 'application/json');
  const parsed = JSON.parse(report.content);
  assert.equal(parsed.summary.totalEvents, 3);

  w.send({ id: 5, type: 'bogus' });
  await w.flush();
  assert.equal(w.replies[0].ok, false);
  assert.match(w.replies[0].payload.message, /unknown message type/);

  w.send({ id: 6, type: 'clear' });
  await w.flush();
  assert.equal(w.replies[0].ok, true);
});
