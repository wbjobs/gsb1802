import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeEvent } from '../src/normalize.js';
import { aggregateEvents } from '../src/aggregate.js';
import { suggest } from '../src/remediation.js';
import { makeEvent } from './fake-idb.js';

test('inline script violation suggests a nonce-based fix', () => {
  const [agg] = aggregateEvents([
    normalizeEvent(makeEvent({ blockedURI: '', effectiveDirective: 'script-src' })),
  ]);
  const fix = suggest(agg);
  assert.equal(fix.id, 'inline-script-nonce');
  assert.equal(fix.severity, 'high');
  assert.match(fix.policySnippet, /nonce-/);
  assert.match(fix.after, /nonce="CHANGE_ME_BASE64"/);
  assert.ok(fix.steps.length >= 3);
});

test('inline event handler variant advises addEventListener rewrite', () => {
  const [agg] = aggregateEvents([
    normalizeEvent(makeEvent({ blockedURI: '', effectiveDirective: 'script-src-attr' })),
  ]);
  const fix = suggest(agg);
  assert.match(fix.description, /event handler/);
  assert.match(fix.after, /addEventListener/);
});

test('eval suggests removing dynamic evaluation', () => {
  const [agg] = aggregateEvents([
    normalizeEvent(makeEvent({ blockedURI: 'eval', effectiveDirective: 'script-src' })),
  ]);
  const fix = suggest(agg);
  assert.equal(fix.id, 'unsafe-eval');
  assert.match(fix.policySnippet, /unsafe-eval/);
  assert.match(fix.after, /setTimeout\(refresh/);
});

test('blocked third-party host gets an origin-scoped policy snippet', () => {
  const [agg] = aggregateEvents([
    normalizeEvent(
      makeEvent({ blockedURI: 'https://cdn.example-csp-test.test/a.js', effectiveDirective: 'script-src' })
    ),
  ]);
  const fix = suggest(agg);
  assert.equal(fix.id, 'allow-origin');
  assert.match(fix.policySnippet, /script-src 'self' https:\/\/cdn\.example-csp-test\.test/);
});

test('blocked image and inline style each get specific guidance', () => {
  const [imgAgg] = aggregateEvents([
    normalizeEvent(
      makeEvent({ blockedURI: 'https://img.example-csp-test.test/x.png', effectiveDirective: 'img-src' })
    ),
  ]);
  assert.equal(suggest(imgAgg).id, 'allow-origin');

  const [styleAgg] = aggregateEvents([
    normalizeEvent(makeEvent({ blockedURI: '', effectiveDirective: 'style-src-elem' })),
  ]);
  const styleFix = suggest(styleAgg);
  assert.equal(styleFix.id, 'inline-style-nonce');
  assert.match(styleFix.policySnippet, /style-src-elem/);
});
