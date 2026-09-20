// Report exporters: machine-readable JSON, CSV of issues/events and a
// standalone HTML report. Pure string builders so they run in the worker and
// are testable in Node.

function csvCell(value) {
  const s = value == null ? '' : String(value);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(rows, columns) {
  const header = columns.map((c) => csvCell(c.label)).join(',');
  const body = rows
    .map((row) => columns.map((c) => csvCell(typeof c.value === 'function' ? c.value(row) : row[c.value])).join(','))
    .join('\r\n');
  return `${header}\r\n${body}\r\n`;
}

const ISSUE_COLUMNS = [
  { label: 'count', value: (a) => a.count },
  { label: 'directive', value: (a) => a.effectiveDirective },
  { label: 'kind', value: (a) => a.blockedKind },
  { label: 'blocked_origin', value: (a) => a.blockedOrigin || '' },
  { label: 'blocked_uri', value: (a) => a.blockedUri || '' },
  { label: 'resource_type', value: (a) => a.resourceType },
  { label: 'first_seen', value: (a) => new Date(a.firstSeen).toISOString() },
  { label: 'last_seen', value: (a) => new Date(a.lastSeen).toISOString() },
  { label: 'severity', value: (a) => (a.remediation && a.remediation.severity) || '' },
  { label: 'title', value: (a) => (a.remediation && a.remediation.title) || '' },
  { label: 'policy_snippet', value: (a) => (a.remediation && a.remediation.policySnippet) || '' },
];

const EVENT_COLUMNS = [
  { label: 'ts', value: (e) => new Date(e.ts).toISOString() },
  { label: 'disposition', value: (e) => e.disposition },
  { label: 'directive', value: (e) => e.effectiveDirective },
  { label: 'resource_type', value: (e) => e.resourceType },
  { label: 'blocked_kind', value: (e) => e.blockedKind },
  { label: 'blocked_uri', value: (e) => e.blockedUri },
  { label: 'blocked_origin', value: (e) => e.blockedOrigin || '' },
  { label: 'source_file', value: (e) => e.sourceFile },
  { label: 'line', value: (e) => e.lineNumber },
  { label: 'column', value: (e) => e.columnNumber },
  { label: 'sample', value: (e) => e.sample },
  { label: 'page_origin', value: (e) => e.pageOrigin || '' },
  { label: 'document_uri', value: (e) => e.documentUri },
];

export function buildCsv(aggregates, events = []) {
  return (
    '# Aggregated issues\r\n' +
    toCsv(aggregates, ISSUE_COLUMNS) +
    '\r\n# Raw events (' + events.length + ')\r\n' +
    toCsv(events, EVENT_COLUMNS)
  );
}

export function buildJson(dashboard) {
  return JSON.stringify(
    {
      tool: 'csp-violation-monitor',
      exportedAt: new Date().toISOString(),
      summary: dashboard.summary,
      originAnalysis: dashboard.originAnalysis,
      issues: dashboard.aggregates,
      events: dashboard.events || [],
    },
    null,
    2
  );
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function barRows(entries, total) {
  if (!entries || !entries.length) return '<p class="muted">None</p>';
  return entries
    .map((e) => {
      const pct = total ? Math.round((e.count / total) * 100) : 0;
      return (
        `<div class="bar-row"><span class="bar-label">${esc(e.name)}</span>` +
        `<span class="bar-track"><span class="bar-fill" style="width:${pct}%"></span></span>` +
        `<span class="bar-count">${e.count} (${pct}%)</span></div>`
      );
    })
    .join('');
}

export function buildHtmlReport(dashboard) {
  const s = dashboard.summary;
  const o = dashboard.originAnalysis;
  const issues = dashboard.aggregates;
  const rows = issues
    .map((a, i) => {
      const r = a.remediation || {};
      const steps = (r.steps || []).map((step) => `<li>${esc(step)}</li>`).join('');
      const locs = Object.values(a.locations || {})
        .sort((x, y) => y.count - x.count)
        .slice(0, 5)
        .map(
          (l) =>
            `<li>${esc(l.sourceFile || '(inline)')}:${l.line}:${l.col} ×${l.count}` +
            (l.sample ? ` — <code>${esc(l.sample.slice(0, 120))}</code>` : '') +
            `</li>`
        )
        .join('');
      return `
      <section class="issue sev-${esc(r.severity || 'low')}">
        <h3>#${i + 1} ${esc(r.title || a.effectiveDirective)} <span class="badge">×${a.count}</span></h3>
        <p class="meta">${esc(a.effectiveDirective)} · ${esc(a.blockedKind)} · ${esc(a.blockedOrigin || a.blockedUri || 'inline')}</p>
        <p>${esc(r.description || '')}</p>
        <h4>Suggested policy</h4>
        <pre>${esc(r.policySnippet || '')}</pre>
        ${r.before ? `<h4>Before / after</h4><pre class="diff">${esc(r.before)}\n---\n${esc(r.after || '')}</pre>` : ''}
        <h4>Steps</h4><ol>${steps}</ol>
        <h4>Top locations</h4><ul>${locs || '<li>n/a</li>'}</ul>
      </section>`;
    })
    .join('');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CSP Violation Report - ${esc(new Date().toISOString())}</title>
<style>
  body{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:960px;color:#1d2433;background:#f7f8fa}
  h1{margin-bottom:.2rem}.muted{color:#6b7280}
  .cards{display:flex;gap:1rem;margin:1rem 0;flex-wrap:wrap}
  .card{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:.8rem 1.2rem;min-width:120px}
  .card b{font-size:1.6rem;display:block}
  .issue{background:#fff;border:1px solid #e5e7eb;border-left-width:4px;border-radius:8px;padding:1rem 1.2rem;margin:1rem 0}
  .sev-high{border-left-color:#dc2626}.sev-medium{border-left-color:#d97706}.sev-low{border-left-color:#2563eb}
  pre{background:#0f172a;color:#e2e8f0;padding:.7rem 1rem;border-radius:6px;overflow:auto;white-space:pre-wrap}
  code{background:#eef2ff;padding:0 .3rem;border-radius:3px}
  pre code{background:none;padding:0}.badge{background:#eef2ff;border-radius:10px;padding:0 .6rem;font-size:.85rem}
  .meta{color:#6b7280;font-size:.85rem}
  .bar-row{display:grid;grid-template-columns:220px 1fr 110px;gap:.6rem;align-items:center;margin:.25rem 0}
  .bar-track{background:#e5e7eb;height:10px;border-radius:5px;overflow:hidden}
  .bar-fill{display:block;height:100%;background:#4f46e5}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
  h4{margin:.8rem 0 .3rem}
</style>
</head>
<body>
  <h1>CSP Violation Report</h1>
  <p class="muted">Generated ${esc(new Date().toLocaleString())} · page ${esc(s.pageOrigin || '-')} · mode ${esc(s.disposition)}</p>
  <div class="cards">
    <div class="card"><b>${s.totalEvents}</b>violations</div>
    <div class="card"><b>${s.totalIssues}</b>unique issues</div>
    <div class="card"><b>${o.firstParty}</b>first-party</div>
    <div class="card"><b>${o.thirdParty}</b>third-party</div>
    <div class="card"><b>${o.inline}</b>inline/eval</div>
  </div>
  <div class="grid2">
    <section><h2>Top origins</h2>${barRows(o.topOrigins, o.thirdParty + o.firstParty)}</section>
    <section><h2>By directive</h2>${barRows(o.directives, o.total)}</section>
  </div>
  <h2>Issues and fixes (${issues.length})</h2>
  ${rows || '<p>No violations captured.</p>'}
</body>
</html>`;
}

export function buildReport(dashboard, format) {
  switch (format) {
    case 'json':
      return { mime: 'application/json', ext: 'json', content: buildJson(dashboard) };
    case 'csv':
      return { mime: 'text/csv', ext: 'csv', content: buildCsv(dashboard.aggregates, dashboard.events || []) };
    case 'html':
      return { mime: 'text/html', ext: 'html', content: buildHtmlReport(dashboard) };
    default:
      throw new Error(`unknown export format: ${format}`);
  }
}
