import test from 'node:test';
import assert from 'node:assert/strict';
import { buildReport, buildCsv, buildHtmlReport, buildJson } from '../src/export.js';

const dashboard = {
  summary: { totalEvents: 2, totalIssues: 1, pageOrigin: 'https://app.example.com', disposition: [], lastSeen: 1 },
  originAnalysis: {
    total: 2,
    firstParty: 0,
    thirdParty: 2,
    inline: 0,
    topOrigins: [{ name: 'https://evil.test', count: 2 }],
    categories: [{ name: 'other', count: 2 }],
    directives: [{ name: 'script-src', count: 2 }],
    topSourceFiles: [],
  },
  aggregates: [
    {
      key: 'url:script-src:https://evil.test',
      count: 2,
      firstSeen: 1,
      lastSeen: 2,
      effectiveDirective: 'script-src',
      blockedKind: 'url',
      blockedOrigin: 'https://evil.test',
      blockedUri: 'https://evil.test/x.js',
      resourceType: 'script',
      locations: {
        fp1: { count: 2, sourceFile: 'https://evil.test/x.js', line: 1, col: 2, sample: '<script src=evil>' },
      },
      remediation: {
        id: 'allow-origin',
        severity: 'medium',
        title: 'Allow the third-party origin evil.test',
        description: 'desc',
        policySnippet: "script-src 'self' https://evil.test",
        before: 'b',
        after: 'a',
        steps: ['s1', 's2'],
      },
    },
  ],
  events: [
    {
      ts: 2,
      disposition: 'enforce',
      effectiveDirective: 'script-src',
      resourceType: 'script',
      blockedKind: 'url',
      blockedUri: 'https://evil.test/x.js',
      blockedOrigin: 'https://evil.test',
      sourceFile: 'https://evil.test/x.js',
      lineNumber: 1,
      columnNumber: 2,
      sample: 'x",y',
      pageOrigin: 'https://app.example.com',
      documentUri: 'https://app.example.com/',
    },
  ],
};

test('JSON export parses and contains summary, issues and events', () => {
  const json = JSON.parse(buildJson(dashboard));
  assert.equal(json.summary.totalEvents, 2);
  assert.equal(json.issues.length, 1);
  assert.equal(json.events.length, 1);
  assert.equal(json.issues[0].remediation.policySnippet, "script-src 'self' https://evil.test");
});

test('CSV export escapes quotes and includes both sections', () => {
  const csv = buildCsv(dashboard.aggregates, dashboard.events);
  assert.match(csv, /# Aggregated issues/);
  assert.match(csv, /# Raw events \(1\)/);
  assert.match(csv, /"x"",y"/);
  assert.match(csv, /script-src 'self' https:\/\/evil\.test/);
});

test('HTML report is standalone and escapes injected content', () => {
  const html = buildHtmlReport(dashboard);
  assert.match(html, /<!doctype html>/);
  assert.match(html, /Allow the third-party origin evil\.test/);
  const dangerous = {
    ...dashboard,
    aggregates: [
      {
        ...dashboard.aggregates[0],
        blockedOrigin: 'https://evil.test"><script>alert(1)</script>',
      },
    ],
  };
  const out = buildHtmlReport(dangerous);
  assert.ok(!out.includes('<script>alert(1)</script>'));
});

test('buildReport dispatches formats and rejects unknown ones', () => {
  assert.equal(buildReport(dashboard, 'json').mime, 'application/json');
  assert.equal(buildReport(dashboard, 'csv').ext, 'csv');
  assert.equal(buildReport(dashboard, 'html').mime, 'text/html');
  assert.throws(() => buildReport(dashboard, 'pdf'), /unknown export format/);
});
