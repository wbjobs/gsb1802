import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeEvent, classifyBlocked, resourceTypeFor, isInlineSource } from '../src/normalize.js';
import { makeEvent } from './fake-idb.js';

test('inline script violation is classified as inline/script-src', () => {
  const ev = normalizeEvent(
    makeEvent({
      blockedURI: '',
      effectiveDirective: 'script-src',
      violatedDirective: "script-src 'self'",
      sourceFile: '',
      sample: "console.log('x')",
      lineNumber: 42,
    })
  );
  assert.equal(ev.blockedKind, 'inline');
  assert.equal(ev.resourceType, 'script');
  assert.equal(ev.effectiveDirective, 'script-src');
  assert.equal(ev.pageOrigin, 'https://app.example.com');
});

test('eval blockedURI is classified as eval', () => {
  const c = classifyBlocked('eval', 'script-src', 'https://a.test/');
  assert.equal(c.kind, 'eval');
});

test('third-party URL keeps exact origin', () => {
  const ev = normalizeEvent(
    makeEvent({
      blockedURI: 'https://cdn.example.org/lib/x.js',
      effectiveDirective: 'script-src-elem',
    })
  );
  assert.equal(ev.blockedKind, 'url');
  assert.equal(ev.blockedOrigin, 'https://cdn.example.org');
  assert.equal(ev.resourceType, 'script');
});

test('data: URI is grouped as data-uri', () => {
  const ev = normalizeEvent(
    makeEvent({ blockedURI: 'data:text/javascript;base64,YWJj', effectiveDirective: 'script-src' })
  );
  assert.equal(ev.blockedKind, 'data-uri');
});

test('directive to resource type mapping', () => {
  assert.equal(resourceTypeFor('img-src'), 'image');
  assert.equal(resourceTypeFor('connect-src'), 'xhr');
  assert.equal(resourceTypeFor('font-src'), 'font');
  assert.equal(resourceTypeFor('frame-ancestors'), 'frame-ancestor');
});

test('isInlineSource recognizes tokens and schemes', () => {
  assert.ok(isInlineSource('', 'script-src'));
  assert.ok(isInlineSource('inline', 'script-src'));
  assert.ok(isInlineSource('javascript:void(0)', 'script-src'));
  assert.ok(!isInlineSource('https://a.test/x.js', 'script-src'));
});

test('report-only disposition is preserved', () => {
  const ev = normalizeEvent(makeEvent({ disposition: 'report', effectiveDirective: 'img-src' }));
  assert.equal(ev.disposition, 'report');
});
