import test from 'node:test';
import assert from 'node:assert/strict';
import { CspController } from '../src/controller.js';
import { normalizeEvent } from '../src/normalize.js';
import { FakeIDBFactory, makeEvent } from './fake-idb.js';
import { MAX_RAW_EVENTS } from '../src/store.js';

const PAGE = 'https://app.example.com/';

function ev(over = {}) {
  return normalizeEvent(makeEvent(over), { ts: over.ts });
}

function mixedBatch(n, startTs = 1) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const pick = i % 4;
    if (pick === 0) {
      out.push(ev({ blockedURI: '', effectiveDirective: 'script-src', lineNumber: 10 + (i % 3), ts: startTs + i }));
    } else if (pick === 1) {
      out.push(ev({ blockedURI: 'eval', effectiveDirective: 'script-src', ts: startTs + i }));
    } else if (pick === 2) {
      out.push(
        ev({ blockedURI: 'https://www.google-analytics.com/a.js', effectiveDirective: 'script-src', ts: startTs + i })
      );
    } else {
      out.push(ev({ blockedURI: `https://cdn-${i % 5}.example-csp-test.test/x.js`, effectiveDirective: 'script-src', ts: startTs + i }));
    }
  }
  return out;
}

test('ingest batches aggregate accurately and survive a worker restart', async () => {
  const idb = new FakeIDBFactory();
  const c1 = new CspController(idb);
  await c1.init(PAGE);
  await c1.ingest(mixedBatch(100, 1));
  await c1.ingest(mixedBatch(50, 200));

  const dash = await c1.dashboard({ includeEvents: true, bucketMs: 1000 });
  assert.equal(dash.summary.totalEvents, 150);
  // 1 inline + 1 eval + 1 GA + 5 rotating cdn hosts = 8 unique issues.
  assert.equal(dash.summary.totalIssues, 8);
  const inline = dash.aggregates.find((a) => a.blockedKind === 'inline');
  assert.equal(inline.count, 38); // 25 in the first batch + 13 in the second
  assert.equal(inline.remediation.id, 'inline-script-nonce');
  assert.equal(dash.originAnalysis.inline, 76); // inline (38) + eval (38)
  assert.equal(dash.events.length, 150);
  assert.ok(dash.trend.length >= 1);

  // New controller (simulates worker/page reload): aggregates load from IDB.
  const c2 = new CspController(idb);
  await c2.init(PAGE);
  const dash2 = await c2.dashboard();
  assert.equal(dash2.summary.totalEvents, 150);
  assert.equal(dash2.summary.totalIssues, 8);

  // Incremental ingest after restart stays exact.
  await c2.ingest(mixedBatch(4, 1000));
  const dash3 = await c2.dashboard();
  assert.equal(dash3.summary.totalEvents, 154);
});

test('raw events are trimmed to MAX_RAW_EVENTS while aggregates keep total', async () => {
  const idb = new FakeIDBFactory();
  const c = new CspController(idb);
  await c.init(PAGE);
  await c.ingest(mixedBatch(MAX_RAW_EVENTS + 250, 1));
  const all = await c.store.getAllEvents();
  assert.equal(all.length, MAX_RAW_EVENTS);
  const total = c.getAggregates().reduce((n, a) => n + a.count, 0);
  assert.equal(total, MAX_RAW_EVENTS + 250);
});

test('clear wipes both raw events and aggregates', async () => {
  const idb = new FakeIDBFactory();
  const c = new CspController(idb);
  await c.init(PAGE);
  await c.ingest(mixedBatch(10, 1));
  await c.clear();
  const dash = await c.dashboard({ includeEvents: true });
  assert.equal(dash.summary.totalEvents, 0);
  assert.equal(dash.events.length, 0);
});

test('reports export through the full controller pipeline', async () => {
  const idb = new FakeIDBFactory();
  const c = new CspController(idb);
  await c.init(PAGE);
  await c.ingest(mixedBatch(20, 1));
  const json = await c.exportReport('json');
  const parsed = JSON.parse(json.content);
  assert.ok(parsed.issues.length >= 2);
  assert.equal(parsed.events.length, 20);
  const csv = await c.exportReport('csv');
  assert.match(csv.content, /Allow inline scripts with a per-response nonce/);
  const html = await c.exportReport('html');
  assert.match(html.content, /CSP Violation Report/);
});

test('rebuild reconstructs identical aggregates from raw events', async () => {
  const idb = new FakeIDBFactory();
  const c = new CspController(idb);
  await c.init(PAGE);
  await c.ingest(mixedBatch(137, 1));
  const before = c.getAggregates().map((a) => [a.key, a.count]).sort();
  await c.rebuild();
  const after = c.getAggregates().map((a) => [a.key, a.count]).sort();
  assert.deepEqual(after, before);
});

test('performance: 2000 violations ingest well under budget', async () => {
  const idb = new FakeIDBFactory();
  const c = new CspController(idb);
  await c.init(PAGE);
  const batch = mixedBatch(2000, 1);
  const started = Date.now();
  await c.ingest(batch);
  const elapsed = Date.now() - started;
  assert.equal(c.summary().totalEvents, 2000);
  // Fake IDB is slower-per-op than native IndexedDB; 3s is a generous bound.
  assert.ok(elapsed < 3000, `ingest took ${elapsed}ms`);

  const qStarted = Date.now();
  const dash = await c.dashboard({ includeEvents: true, eventLimit: 100, bucketMs: 60000 });
  const qElapsed = Date.now() - qStarted;
  assert.equal(dash.events.length, 100);
  assert.ok(qElapsed < 1000, `dashboard query took ${qElapsed}ms`);
});
