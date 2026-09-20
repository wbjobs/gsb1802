// Core pipeline shared by the worker and the test harness:
// store raw events -> aggregate -> analyze -> answer dashboard queries.

import { CspStore } from './store.js';
import { createAggregate, mergeInto, groupKey, sortAggregates, aggregateEvents, timeline } from './aggregate.js';
import { annotateAggregates } from './remediation.js';
import { analyzeOrigins } from './sources.js';
import { buildReport } from './export.js';

export class CspController {
  constructor(idbFactory) {
    this.store = new CspStore(idbFactory);
    this.aggMap = new Map();
    this.pageOrigin = null;
    this.ready = false;
  }

  async init(pageOrigin) {
    if (pageOrigin) this.pageOrigin = pageOrigin;
    const stored = await this.store.getAllAggregates();
    for (const agg of stored) this.aggMap.set(agg.key, agg);
    this.ready = true;
  }

  // Ingest a batch of normalized events. All storage work happens off the
  // main thread; this is the hot path so aggregation is incremental and the
  // aggregate snapshot is written once per batch.
  async ingest(events) {
    if (!events.length) return { ingested: 0 };
    const stamped = events.map((ev) => ({ ...ev, groupKey: groupKey(ev) }));
    const stored = await this.store.addEvents(stamped);
    await this.store.trimEvents();
    for (const ev of stored) {
      let agg = this.aggMap.get(ev.groupKey);
      if (!agg) {
        agg = createAggregate(ev);
        this.aggMap.set(ev.groupKey, agg);
      }
      mergeInto(agg, ev);
    }
    await this.store.putAggregates([...this.aggMap.values()]);
    return { ingested: stored.length };
  }

  getAggregates() {
    return sortAggregates([...this.aggMap.values()]);
  }

  summary() {
    const aggs = [...this.aggMap.values()];
    const total = aggs.reduce((n, a) => n + a.count, 0);
    const disposition = new Map();
    for (const a of aggs) disposition.set(a.disposition || 'enforce', (disposition.get(a.disposition || 'enforce') || 0) + a.count);
    return {
      totalEvents: total,
      totalIssues: aggs.length,
      pageOrigin: this.pageOrigin,
      disposition: [...disposition.entries()].map(([name, count]) => ({ name, count })),
      lastSeen: aggs.reduce((m, a) => Math.max(m, a.lastSeen), 0) || null,
    };
  }

  async dashboard({ includeEvents = false, eventLimit = 500, bucketMs = 60000 } = {}) {
    const aggregates = annotateAggregates(this.getAggregates());
    let events = [];
    let trend = [];
    if (includeEvents) {
      const all = await this.store.getAllEvents();
      events = all.sort((a, b) => b.ts - a.ts).slice(0, eventLimit);
      trend = timeline(all, bucketMs).slice(-60);
    } else {
      // Trend from aggregates' per-location timestamps is not exact; require
      // raw events for the chart. Derive a cheap range summary instead.
      trend = null;
    }
    const originAnalysis = analyzeOrigins(aggregates, {
      pageOrigin: this.pageOrigin,
      weighted: true,
    });
    return { summary: this.summary(), originAnalysis, aggregates, events, trend };
  }

  async exportReport(format) {
    const dash = await this.dashboard({ includeEvents: format !== 'html', eventLimit: Number.POSITIVE_INFINITY });
    return buildReport(dash, format);
  }

  async clear() {
    await this.store.clear();
    this.aggMap.clear();
  }

  // Test/recovery utility: rebuild aggregates from raw events.
  async rebuild() {
    const events = await this.store.getAllEvents();
    this.aggMap = new Map();
    for (const agg of aggregateEvents(events)) this.aggMap.set(agg.key, agg);
    await this.store.putAggregates([...this.aggMap.values()]);
  }
}
