import test from 'node:test';
import assert from 'node:assert/strict';
import { aggregate, createRecord, filterGroups, reportToCsv, toReport } from '../src/aggregation.js';
import { buildExport } from '../src/export-report.js';
import { buildRecommendation } from '../src/recommendations.js';
import { normalizeDirective, violationFingerprint } from '../src/csp.js';

function inlineEvent(overrides = {}) {
  return {
    blockedURI: '',
    columnNumber: 17,
    disposition: 'enforce',
    documentURI: 'http://localhost:4173/',
    effectiveDirective: 'script-src',
    lineNumber: 42,
    originalPolicy: "script-src 'self'",
    referrer: '',
    sample: "console.log('inline')",
    sourceFile: 'http://localhost:4173/index.html',
    statusCode: 200,
    violatedDirective: 'script-src',
    isTrusted: true,
    ...overrides
  };
}

test('captures inline script violation and recommends nonce', () => {
  const record = createRecord(inlineEvent(), { nonce: 'abc' });
  const recommendation = buildRecommendation(record, 'request-nonce');

  assert.equal(record.source.kind, 'inline-script');
  assert.equal(record.source.origin, 'http://localhost:4173');
  assert.equal(record.source.line, 42);
  assert.equal(recommendation.priority, 'critical');
  assert.match(recommendation.title, /nonce/);
  assert.ok(recommendation.actions.some((action) => action.includes('随机')));
  assert.ok(recommendation.snippets[0].code.includes("'nonce-request-nonce'"));
  assert.ok(recommendation.snippets[0].code.includes('strict-dynamic'));
  assert.ok(recommendation.snippets[1].code.includes('nonce="request-nonce"'));
});

test('inline event handler recommends addEventListener instead of nonce', () => {
  const record = createRecord(inlineEvent({
    blockedURI: 'inline',
    effectiveDirective: 'script-src-attr',
    violatedDirective: 'script-src-attr',
    lineNumber: 8,
    sample: 'onclick="handleClick()"'
  }));
  const recommendation = buildRecommendation(record);

  assert.equal(record.source.kind, 'inline-handler');
  assert.match(recommendation.title, /addEventListener/);
  assert.ok(recommendation.snippets.some((snippet) => snippet.code.includes('addEventListener')));
  assert.ok(!recommendation.snippets[0].code.includes("'nonce-SERVER_GENERATED_NONCE'"));
});

test('aggregates repeated inline scripts accurately', () => {
  const first = createRecord(inlineEvent());
  const second = createRecord(inlineEvent({ columnNumber: 99 }));
  const otherLine = createRecord(inlineEvent({ lineNumber: 88 }));
  const groups = aggregate([first, second, otherLine], 'nonce');

  assert.equal(groups.length, 2);
  assert.equal(groups[0].count, 2);
  assert.equal(groups[0].countTrusted, 2);
  assert.equal(groups[1].count, 1);
});

test('separates same directive by external origin and path', () => {
  const first = createRecord(inlineEvent({
    blockedURI: 'https://cdn.example.com/a.js',
    effectiveDirective: 'script-src-elem',
    violatedDirective: 'script-src-elem',
    sample: '',
    sourceFile: '',
    lineNumber: 0
  }));
  const second = createRecord(inlineEvent({
    blockedURI: 'https://cdn.example.com/b.js',
    effectiveDirective: 'script-src-elem',
    violatedDirective: 'script-src-elem',
    sample: '',
    sourceFile: '',
    lineNumber: 0
  }));
  const third = createRecord(inlineEvent({
    blockedURI: 'https://images.example.com/a.png',
    effectiveDirective: 'img-src',
    violatedDirective: 'img-src',
    sample: '',
    sourceFile: '',
    lineNumber: 0
  }));

  assert.equal(violationFingerprint(first) === violationFingerprint(second), false);
  const groups = aggregate([first, second, third]);
  assert.equal(groups.length, 3);
  assert.equal(groups[2].origins['https://images.example.com'], 1);
});

test('external resource recommendation uses minimal origin', () => {
  const record = createRecord(inlineEvent({
    blockedURI: 'https://cdn.example.com/vendor/app.js',
    effectiveDirective: 'script-src-elem',
    violatedDirective: 'script-src-elem',
    sourceFile: '',
    sample: '',
    lineNumber: 0
  }));
  const recommendation = buildRecommendation(record);

  assert.equal(record.source.kind, 'external-resource');
  assert.match(recommendation.title, /script 元素/);
  assert.ok(recommendation.snippets[0].code.includes("script-src-elem 'self' https://cdn.example.com"));
  assert.ok(recommendation.actions.some((action) => action.includes('SRI')));
});

test('filters groups by directive, source, origin, and query', () => {
  const groups = aggregate([
    createRecord(inlineEvent()),
    createRecord(inlineEvent({
      blockedURI: 'https://cdn.example.com/app.js',
      effectiveDirective: 'script-src-elem',
      violatedDirective: 'script-src-elem',
      sourceFile: '',
      sample: '',
      lineNumber: 0
    }))
  ]);

  assert.equal(filterGroups(groups, { directive: 'script-src' }).length, 1);
  assert.equal(filterGroups(groups, { sourceKind: 'external-resource' }).length, 1);
  assert.equal(filterGroups(groups, { origin: 'https://cdn.example.com' }).length, 1);
  assert.equal(filterGroups(groups, { query: 'nonce' }).length, 1);
  assert.equal(filterGroups(groups, { query: 'missing' }).length, 0);
});

test('exports JSON and CSV reports', () => {
  const records = [createRecord(inlineEvent()), createRecord(inlineEvent())];
  const groups = aggregate(records);
  const json = buildExport(groups, records, { format: 'json', includeRaw: true });
  const csv = buildExport(groups, [], { format: 'csv' });
  const report = JSON.parse(json.content);

  assert.equal(json.mimeType, 'application/json;charset=utf-8');
  assert.equal(report.summary.total, 2);
  assert.equal(report.summary.groups, 1);
  assert.equal(report.rawEvents.length, 2);
  assert.match(csv.content, /内联脚本/);
  assert.match(csv.content, /nonce-request-nonce|SERVER_GENERATED_NONCE/);
  assert.equal(typeof reportToCsv(groups), 'string');
});

test('normalizes aliases and report schema stays stable', () => {
  assert.equal(normalizeDirective('img-src https:'), 'img-src');
  const report = toReport(aggregate([createRecord(inlineEvent())]));
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.reportKind, 'csp-violations');
  assert.ok(report.groups[0].recommendation.actions.length >= 2);
  assert.ok(report.groups[0].fingerprint);
});

test('aggregates 10,000 events into bounded groups', () => {
  const records = [];
  for (let index = 0; index < 10000; index += 1) {
    const variant = index % 5;
    records.push(createRecord(inlineEvent({
      lineNumber: 100 + variant,
      sample: variant === 0 ? "console.log('hot-path')" : `console.log('variant-${variant}')`
    })));
  }

  const groups = aggregate(records);
  const report = toReport(groups);

  assert.equal(report.summary.total, 10000);
  assert.equal(groups.length, 5);
  assert.equal(groups.reduce((sum, group) => sum + group.count, 0), 10000);
});
