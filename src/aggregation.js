import {
  classifySource,
  normalizeDirective,
  originOf,
  safeText,
  text,
  violationFingerprint
} from './csp.js';
import { buildRecommendation } from './recommendations.js';

const PRIORITY_WEIGHT = {
  critical: 3,
  high: 2,
  medium: 1,
  low: 0
};

export function createRecord(event, overrides = {}) {
  const raw = event || {};
  const timestamp = toTimestamp(overrides.occurredAt || Date.now());
  const directive = normalizeDirective(raw.violatedDirective || raw.effectiveDirective || overrides.directive);
  const source = classifySource({
    directive,
    blockedURI: raw.blockedURI,
    sourceFile: raw.sourceFile,
    lineNumber: raw.lineNumber,
    columnNumber: raw.columnNumber,
    sample: raw.sample
  });

  return {
    id: overrides.id || cryptoRandomId(),
    fingerprint: violationFingerprint({
      directive,
      blockedURI: raw.blockedURI,
      sourceFile: raw.sourceFile,
      lineNumber: raw.lineNumber,
      columnNumber: raw.columnNumber,
      sample: raw.sample
    }),
    occurredAt: timestamp,
    receivedAt: timestamp,
    disposition: normalizeDisposition(raw.disposition),
    directive,
    blockedURI: text(raw.blockedURI || ''),
    documentURI: text(raw.documentURI || ''),
    sourceFile: text(raw.sourceFile || ''),
    lineNumber: Number(raw.lineNumber) || 0,
    columnNumber: Number(raw.columnNumber) || 0,
    sample: safeText(raw.sample, 500),
    originalPolicy: text(raw.originalPolicy || ''),
    referrer: text(raw.referrer || ''),
    statusCode: Number(raw.statusCode) || 0,
    isTrusted: raw.isTrusted !== false,
    loadTest: Boolean(overrides.loadTest),
    userAgent: text(overrides.userAgent || raw.userAgent || navigatorAgent()),
    pageUrl: text(overrides.pageUrl || raw.documentURI || documentHref()),
    source
  };
}

export function createGroup(record, nonce) {
  const recommendation = buildRecommendation(record, nonce);
  return {
    fingerprint: record.fingerprint,
    firstSeen: record.occurredAt,
    lastSeen: record.occurredAt,
    count: 1,
    countTrusted: record.isTrusted ? 1 : 0,
    countLoadTest: record.loadTest ? 1 : 0,
    directive: record.directive,
    disposition: record.disposition,
    blockedURI: record.blockedURI,
    sourceKind: record.source.kind,
    origins: incrementMap({}, record.source.origin),
    pages: incrementMap({}, record.pageUrl || record.documentURI),
    sourceFiles: incrementMap({}, record.source.file),
    samples: uniqueLimited([record.sample].filter(Boolean), 5),
    lines: uniqueLimited([record.lineNumber].filter(Boolean), 10),
    latestRecord: record,
    recommendation
  };
}

export function addRecordToGroup(group, record, nonce) {
  group.firstSeen = Math.min(group.firstSeen, record.occurredAt);
  group.lastSeen = Math.max(group.lastSeen, record.occurredAt);
  group.count += 1;
  group.countTrusted += record.isTrusted ? 1 : 0;
  group.countLoadTest += record.loadTest ? 1 : 0;
  group.disposition = chooseDisposition(group.disposition, record.disposition);
  incrementMap(group.origins, record.source.origin);
  incrementMap(group.pages, record.pageUrl || record.documentURI);
  incrementMap(group.sourceFiles, record.source.file);
  addUnique(group.samples, record.sample, 5);
  addUnique(group.lines, record.lineNumber, 10);
  group.latestRecord = record.occurredAt >= group.latestRecord.occurredAt ? record : group.latestRecord;
  if (!group.recommendation) {
    group.recommendation = buildRecommendation(record, nonce);
  }
  return group;
}

export function aggregate(records, nonce = '') {
  const groups = new Map();
  for (const record of records) {
    if (!groups.has(record.fingerprint)) {
      groups.set(record.fingerprint, createGroup(record, nonce));
    } else {
      addRecordToGroup(groups.get(record.fingerprint), record, nonce);
    }
  }
  return sortGroups([...groups.values()]);
}

export function mergeGroup(existing, incoming) {
  existing.firstSeen = Math.min(existing.firstSeen, incoming.firstSeen);
  existing.lastSeen = Math.max(existing.lastSeen, incoming.lastSeen);
  existing.count += incoming.count;
  existing.countTrusted += incoming.countTrusted;
  existing.countLoadTest += incoming.countLoadTest;
  existing.disposition = chooseDisposition(existing.disposition, incoming.disposition);
  mergeCountMap(existing.origins, incoming.origins);
  mergeCountMap(existing.pages, incoming.pages);
  mergeCountMap(existing.sourceFiles, incoming.sourceFiles);
  existing.samples = uniqueLimited([...existing.samples, ...incoming.samples], 5);
  existing.lines = uniqueLimited([...existing.lines, ...incoming.lines], 10);
  if (incoming.latestRecord?.occurredAt >= (existing.latestRecord?.occurredAt || 0)) {
    existing.latestRecord = incoming.latestRecord;
  }
  if (!existing.recommendation && incoming.recommendation) {
    existing.recommendation = incoming.recommendation;
  }
  return existing;
}

export function summarize(groups, recordsTotal = groups.reduce((sum, group) => sum + group.count, 0)) {
  const sourceCounts = {};
  const directiveCounts = {};
  const originCounts = {};
  let trustedCount = 0;
  let loadTestCount = 0;

  for (const group of groups) {
    sourceCounts[group.sourceKind] = (sourceCounts[group.sourceKind] || 0) + group.count;
    directiveCounts[group.directive] = (directiveCounts[group.directive] || 0) + group.count;
    trustedCount += group.countTrusted;
    loadTestCount += group.countLoadTest;
    for (const [origin, count] of Object.entries(group.origins || {})) {
      originCounts[origin] = (originCounts[origin] || 0) + count;
    }
  }

  return {
    total: recordsTotal,
    groups: groups.length,
    trusted: trustedCount,
    loadTest: loadTestCount,
    sourceCounts,
    directiveCounts,
    originCounts: sortObject(originCounts),
    generatedAt: new Date().toISOString()
  };
}

export function sortGroups(groups) {
  return groups.sort((left, right) => {
    const priorityDelta = (PRIORITY_WEIGHT[right.recommendation?.priority] || 0)
      - (PRIORITY_WEIGHT[left.recommendation?.priority] || 0);
    if (priorityDelta !== 0) {
      return priorityDelta;
    }
    if (right.count !== left.count) {
      return right.count - left.count;
    }
    return right.lastSeen - left.lastSeen;
  });
}

export function filterGroups(groups, filters = {}) {
  const directive = filters.directive || '';
  const sourceKind = filters.sourceKind || '';
  const origin = filters.origin || '';
  const query = text(filters.query).trim().toLowerCase();
  const hideLoadTest = Boolean(filters.hideLoadTest);

  return groups.filter((group) => {
    if (hideLoadTest && group.count - group.countLoadTest <= 0) {
      return false;
    }
    if (directive && group.directive !== directive) {
      return false;
    }
    if (sourceKind && group.sourceKind !== sourceKind) {
      return false;
    }
    if (origin && !(origin in (group.origins || {}))) {
      return false;
    }
    if (query) {
      const haystack = [
        group.directive,
        group.sourceKind,
        group.blockedURI,
        group.samples.join(' '),
        Object.keys(group.origins || {}).join(' '),
        group.recommendation?.title || ''
      ].join(' ').toLowerCase();
      if (!haystack.includes(query)) {
        return false;
      }
    }
    return true;
  });
}

export function serializeGroup(group) {
  return {
    fingerprint: group.fingerprint,
    firstSeen: new Date(group.firstSeen).toISOString(),
    lastSeen: new Date(group.lastSeen).toISOString(),
    count: group.count,
    countTrusted: group.countTrusted,
    countLoadTest: group.countLoadTest,
    directive: group.directive,
    disposition: group.disposition,
    sourceKind: group.sourceKind,
    blockedURI: group.blockedURI,
    origins: group.origins,
    pages: group.pages,
    sourceFiles: group.sourceFiles,
    samples: group.samples,
    lines: group.lines,
    recommendation: group.recommendation
  };
}

export function toReport(groups, { includeRaw = false, records = [], nonce = '' } = {}) {
  const sortedGroups = sortGroups(groups.map((group) => ({ ...group })));
  const report = {
    schemaVersion: 1,
    reportKind: 'csp-violations',
    summary: summarize(sortedGroups),
    groups: sortedGroups.map(serializeGroup)
  };
  if (includeRaw) {
    report.rawEvents = records.map((record) => ({
      ...record,
      occurredAt: new Date(record.occurredAt).toISOString(),
      receivedAt: new Date(record.receivedAt).toISOString(),
      recommendation: undefined,
      source: record.source
    }));
  }
  return report;
}

export function reportToCsv(groups) {
  const header = [
    'fingerprint',
    'count',
    'directive',
    'sourceKind',
    'disposition',
    'firstSeen',
    'lastSeen',
    'origins',
    'blockedURI',
    'sourceFiles',
    'samples',
    'priority',
    'recommendation',
    'actions',
    'snippets'
  ];
  const rows = sortGroups(groups).map((group) => [
    group.fingerprint,
    group.count,
    group.directive,
    group.sourceKind,
    group.disposition,
    new Date(group.firstSeen).toISOString(),
    new Date(group.lastSeen).toISOString(),
    formatCountMap(group.origins),
    group.blockedURI,
    formatCountMap(group.sourceFiles),
    group.samples.join(' | '),
    group.recommendation?.priority || '',
    group.recommendation?.title || '',
    (group.recommendation?.actions || []).join(' | '),
    (group.recommendation?.snippets || []).map((snippet) => `${snippet.label}: ${snippet.code}`).join(' | ')
  ]);
  return `\uFEFF${[header, ...rows].map((row) => row.map(csvCell).join(',')).join('\n')}`;
}

function toTimestamp(value) {
  const timestamp = Number(value);
  return Number.isFinite(timestamp) && timestamp > 0 ? timestamp : Date.now();
}

function normalizeDisposition(value) {
  return text(value).trim().toLowerCase() === 'report' ? 'report' : 'enforce';
}

function chooseDisposition(left, right) {
  return left === 'enforce' || right === 'enforce' ? 'enforce' : 'report';
}

function incrementMap(target, key) {
  const normalized = key || '(none)';
  target[normalized] = (target[normalized] || 0) + 1;
  return target;
}

function mergeCountMap(target, source) {
  for (const [key, value] of Object.entries(source || {})) {
    target[key] = (target[key] || 0) + value;
  }
  return target;
}

function addUnique(list, value, limit) {
  if (!value || list.includes(value) || list.length >= limit) {
    return list;
  }
  list.push(value);
  return list;
}

function uniqueLimited(values, limit) {
  return [...new Set(values.filter((value) => value !== undefined && value !== null && value !== ''))].slice(0, limit);
}

function sortObject(object) {
  return Object.fromEntries(Object.entries(object).sort((left, right) => right[1] - left[1]));
}

function formatCountMap(object) {
  return Object.entries(object || {}).map(([key, value]) => `${key} (${value})`).join(' | ');
}

function csvCell(value) {
  return `"${text(value).replace(/"/g, '""')}"`;
}

function cryptoRandomId() {
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function navigatorAgent() {
  return typeof globalThis.navigator === 'undefined' ? '' : globalThis.navigator.userAgent;
}

function documentHref() {
  return typeof globalThis.location === 'undefined' ? '' : globalThis.location.href;
}
