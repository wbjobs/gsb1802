// Aggregation engine. A group is one fixable issue: same directive, same
// blocked resource identity (inline/eval/data/blobs grouped apart from hosts)
// and same page origin. Within a group each unique violation location gets its
// own count so both roll-up numbers and per-location drill-down stay exact.

import { isInlineSource } from './normalize.js';

const MAX_SAMPLES = 5;
const MAX_LOCATIONS = 500;

export function groupKey(ev) {
  const directive = ev.effectiveDirective || 'unknown';
  const blocked = ev.blockedUri || '';

  if (ev.blockedKind === 'eval') return `eval:${directive}:${ev.pageOrigin || ''}`;
  if (ev.blockedKind === 'inline' || (!blocked && isInlineSource(blocked, directive))) {
    return `inline:${directive}:${ev.pageOrigin || ''}`;
  }
  if (ev.blockedKind === 'data-uri') {
    const mime = /^data:([^,;]+)/i.exec(blocked);
    return `data:${directive}:${(mime && mime[1]) || ''}`;
  }
  if (ev.blockedKind === 'blob-uri') {
    return `blob:${directive}:${ev.blockedOrigin || ''}`;
  }
  if (ev.blockedKind === 'url' && ev.blockedOrigin) {
    return `url:${directive}:${ev.blockedOrigin}`;
  }
  // Last resort: keep exact blocked value so distinct tokens never merge.
  return `other:${directive}:${blocked}`;
}

export function locationFingerprint(ev) {
  return [
    ev.blockedUri || '',
    ev.sourceFile || '',
    ev.lineNumber || 0,
    ev.columnNumber || 0,
    ev.sample || '',
  ].join('|');
}

export function createAggregate(ev) {
  return {
    key: groupKey(ev),
    count: 0,
    firstSeen: ev.ts,
    lastSeen: ev.ts,
    pageOrigin: ev.pageOrigin || null,
    effectiveDirective: ev.effectiveDirective,
    resourceType: ev.resourceType,
    blockedKind: ev.blockedKind,
    blockedUri: ev.blockedUri,
    blockedOrigin: ev.blockedOrigin,
    disposition: ev.disposition,
    sources: {}, // sourceFile -> count
    origins: {}, // blockedOrigin -> count
    locations: {}, // fingerprint -> { count, firstSeen, lastSeen, blockedUri, sourceFile, line, col, sample }
    samples: [],
  };
}

export function mergeInto(agg, ev) {
  agg.count += 1;
  agg.firstSeen = Math.min(agg.firstSeen, ev.ts);
  agg.lastSeen = Math.max(agg.lastSeen, ev.ts);

  if (ev.blockedOrigin) {
    agg.origins[ev.blockedOrigin] = (agg.origins[ev.blockedOrigin] || 0) + 1;
  }
  const source = ev.sourceFile || '(inline)';
  agg.sources[source] = (agg.sources[source] || 0) + 1;

  const fp = locationFingerprint(ev);
  let loc = agg.locations[fp];
  if (!loc) {
    if (Object.keys(agg.locations).length < MAX_LOCATIONS) {
      loc = {
        count: 0,
        firstSeen: ev.ts,
        lastSeen: ev.ts,
        blockedUri: ev.blockedUri,
        sourceFile: ev.sourceFile,
        line: ev.lineNumber,
        col: ev.columnNumber,
        sample: ev.sample,
      };
      agg.locations[fp] = loc;
    }
  }
  if (loc) {
    loc.count += 1;
    loc.lastSeen = Math.max(loc.lastSeen, ev.ts);
  }

  if (ev.sample && !agg.samples.includes(ev.sample) && agg.samples.length < MAX_SAMPLES) {
    agg.samples.push(ev.sample);
  }
  return agg;
}

export function mergeAggregate(target, incoming) {
  target.count += incoming.count;
  target.firstSeen = Math.min(target.firstSeen, incoming.firstSeen);
  target.lastSeen = Math.max(target.lastSeen, incoming.lastSeen);
  for (const [o, c] of Object.entries(incoming.origins)) {
    target.origins[o] = (target.origins[o] || 0) + c;
  }
  for (const [s, c] of Object.entries(incoming.sources)) {
    target.sources[s] = (target.sources[s] || 0) + c;
  }
  for (const [fp, loc] of Object.entries(incoming.locations)) {
    const existing = target.locations[fp];
    if (existing) {
      existing.count += loc.count;
      existing.firstSeen = Math.min(existing.firstSeen, loc.firstSeen);
      existing.lastSeen = Math.max(existing.lastSeen, loc.lastSeen);
    } else if (Object.keys(target.locations).length < MAX_LOCATIONS) {
      target.locations[fp] = { ...loc };
    }
  }
  for (const sample of incoming.samples) {
    if (!target.samples.includes(sample) && target.samples.length < MAX_SAMPLES) {
      target.samples.push(sample);
    }
  }
  return target;
}

// Aggregate an arbitrary list of normalized events. Used by tests and by the
// worker when rebuilding from stored raw events.
export function aggregateEvents(events) {
  const map = new Map();
  for (const ev of events) {
    const key = groupKey(ev);
    let agg = map.get(key);
    if (!agg) {
      agg = createAggregate(ev);
      map.set(key, agg);
    }
    mergeInto(agg, ev);
  }
  return [...map.values()];
}

export function sortAggregates(aggs) {
  return [...aggs].sort((a, b) => b.count - a.count || b.lastSeen - a.lastSeen);
}

// Fixed-size time buckets (ms), returned oldest-first, for the trend chart.
// The series is capped to maxBuckets: a page reopened after long idle would
// otherwise produce a huge mostly-empty range.
export function timeline(events, bucketMs, now = Date.now(), maxBuckets = 60) {
  const buckets = new Map();
  for (const ev of events) {
    const slot = Math.floor(ev.ts / bucketMs) * bucketMs;
    buckets.set(slot, (buckets.get(slot) || 0) + 1);
  }
  const slots = [...buckets.keys()].sort((x, y) => x - y);
  const lastSlot = Math.floor(now / bucketMs) * bucketMs;
  let start = slots.length ? slots[0] : lastSlot;
  const latestData = slots.length ? slots[slots.length - 1] : start;
  const end = Math.max(now, latestData);
  const minStart = end - (maxBuckets - 1) * bucketMs;
  if (start < minStart) start = Math.floor(minStart / bucketMs) * bucketMs;
  const out = [];
  for (let t = start; t <= end; t += bucketMs) {
    out.push({ t, count: buckets.get(t) || 0 });
  }
  return out;
}
