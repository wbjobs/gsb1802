import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeEvent } from '../src/normalize.js';
import { aggregateEvents, groupKey, timeline, sortAggregates } from '../src/aggregate.js';
import { makeEvent } from './fake-idb.js';

function inlineScript(over = {}) {
  return normalizeEvent(
    makeEvent({
      blockedURI: '',
      effectiveDirective: 'script-src',
      sourceFile: over.sourceFile || '',
      lineNumber: over.lineNumber || 0,
      sample: over.sample || '',
      ...over,
    }),
    { ts: over.ts }
  );
}

test('repeated inline violations collapse into one exact-count aggregate', () => {
  const events = [
    inlineScript({ lineNumber: 10, sample: 'a()', ts: 1000 }),
    inlineScript({ lineNumber: 10, sample: 'a()', ts: 2000 }),
    inlineScript({ lineNumber: 55, sample: 'b()', ts: 3000 }),
  ];
  const aggs = aggregateEvents(events);
  assert.equal(aggs.length, 1);
  assert.equal(aggs[0].count, 3);
  assert.equal(aggs[0].firstSeen, 1000);
  assert.equal(aggs[0].lastSeen, 3000);
  // Two distinct locations inside the single issue.
  assert.equal(Object.keys(aggs[0].locations).length, 2);
  assert.deepEqual([...aggs[0].samples].sort(), ['a()', 'b()']);
});

test('distinct directives / hosts never merge', () => {
  const events = [
    inlineScript({ effectiveDirective: 'script-src' }),
    inlineScript({
      effectiveDirective: 'script-src',
      blockedURI: 'https://cdn.a.test/x.js',
      sourceFile: 'https://cdn.a.test/x.js',
    }),
    inlineScript({
      effectiveDirective: 'script-src',
      blockedURI: 'https://cdn.b.test/x.js',
      sourceFile: 'https://cdn.b.test/x.js',
    }),
    inlineScript({ effectiveDirective: 'style-src' }),
    inlineScript({ effectiveDirective: 'script-src', blockedURI: 'eval' }),
  ];
  const aggs = aggregateEvents(events);
  assert.equal(aggs.length, 5);
});

test('different pages with same inline problem stay separate', () => {
  const a = inlineScript({ documentURI: 'https://a.test/' });
  const b = inlineScript({ documentURI: 'https://b.test/' });
  assert.notEqual(groupKey(a), groupKey(b));
});

test('sortAggregates orders by frequency then recency', () => {
  const events = [
    inlineScript({ ts: 1 }),
    inlineScript({ blockedURI: 'eval', ts: 2 }),
    inlineScript({ blockedURI: 'eval', ts: 3 }),
  ];
  const sorted = sortAggregates(aggregateEvents(events));
  assert.equal(sorted[0].count, 2);
});

test('timeline buckets events per minute and fills gaps', () => {
  const events = [
    inlineScript({ ts: 60_000 }),
    inlineScript({ ts: 61_000 }),
    inlineScript({ ts: 120_000 }),
  ];
  const buckets = timeline(events, 60_000, 120_000);
  assert.deepEqual(buckets, [
    { t: 60000, count: 2 },
    { t: 120000, count: 1 },
  ]);
});
