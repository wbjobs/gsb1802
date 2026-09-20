import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeEvent } from '../src/normalize.js';
import { analyzeOrigins, isFirstParty, registrableDomain, categorizeHost } from '../src/sources.js';
import { aggregateEvents } from '../src/aggregate.js';
import { makeEvent } from './fake-idb.js';

test('registrable domain handles co.uk style suffixes', () => {
  assert.equal(registrableDomain('sub.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('a.b.example.com'), 'example.com');
});

test('first/third party split uses eTLD+1', () => {
  assert.ok(isFirstParty('https://cdn.example.com', 'https://www.example.com'));
  assert.ok(!isFirstParty('https://cdn.other.com', 'https://www.example.com'));
  assert.ok(!isFirstParty('null', 'https://www.example.com'));
});

test('categorizeHost identifies common provider classes', () => {
  assert.equal(categorizeHost('www.google-analytics.com'), 'analytics');
  assert.equal(categorizeHost('cdn.jsdelivr.net'), 'cdn');
  assert.equal(categorizeHost('random-host.example'), 'other');
});

test('analyzeOrigins counts first/third party, inline, directives', () => {
  const events = [
    normalizeEvent(makeEvent({ blockedURI: '', effectiveDirective: 'script-src' })),
    normalizeEvent(makeEvent({ blockedURI: '', effectiveDirective: 'script-src' })),
    normalizeEvent(
      makeEvent({ blockedURI: 'https://www.google-analytics.com/analytics.js', effectiveDirective: 'script-src' })
    ),
    normalizeEvent(
      makeEvent({ blockedURI: 'https://images.example.com/p.png', effectiveDirective: 'img-src' })
    ),
  ];
  const report = analyzeOrigins(events, { pageOrigin: 'https://app.example.com' });
  assert.equal(report.total, 4);
  assert.equal(report.inline, 2);
  assert.equal(report.thirdParty, 1);
  assert.equal(report.firstParty, 1);
  assert.deepEqual(report.topOrigins.map((o) => o.name).sort(), [
    'https://images.example.com',
    'https://www.google-analytics.com',
  ]);
  assert.ok(report.categories.some((c) => c.name === 'analytics' && c.count === 1));
  const directiveNames = report.directives.map((d) => d.name);
  assert.deepEqual(directiveNames.sort(), ['img-src', 'script-src']);
});

test('weighted analysis of aggregates matches raw event totals', () => {
  const events = [];
  for (let i = 0; i < 5; i++) {
    events.push(normalizeEvent(makeEvent({ blockedURI: '', effectiveDirective: 'script-src' })));
  }
  events.push(
    normalizeEvent(
      makeEvent({ blockedURI: 'https://tracker.example-csp-test.test/x', effectiveDirective: 'connect-src' })
    )
  );
  const aggs = aggregateEvents(events);
  const report = analyzeOrigins(aggs, { pageOrigin: 'https://app.example.com', weighted: true });
  assert.equal(report.total, 6);
  assert.equal(report.inline, 5);
  assert.equal(report.thirdParty, 1);
});
