import { createMonitor } from '../src/monitor.js';

const monitor = createMonitor();
const logEl = document.getElementById('trigger-log');

function log(message) {
  const line = document.createElement('div');
  line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

function esc(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ---- Test-fixture triggers -------------------------------------------------

const TRIGGERS = {
  inline() {
    const s = document.createElement('script');
    s.textContent = "console.log('injected inline script ran')";
    document.body.appendChild(s);
    return 'injected an inline <script>';
  },
  eval() {
    try {
      // eslint-disable-next-line no-eval
      eval('1 + 1');
    } catch (e) {
      return 'eval() threw (expected when enforced)';
    }
    return 'eval() executed (policy likely report-only)';
  },
  'inline-handler'() {
    const b = document.createElement('button');
    b.textContent = 'I have an inline onclick';
    b.setAttribute('onclick', 'window.__probeFired && window.__probeFired()');
    document.getElementById('trigger-panel').appendChild(b);
    return 'added an element with onclick=""';
  },
  'external-script'() {
    const s = document.createElement('script');
    s.src = 'https://cdn.example-csp-test.test/widget.js';
    document.head.appendChild(s);
    return 'loaded <script src=https://cdn.example-csp-test.test/...>';
  },
  'external-image'() {
    const img = document.createElement('img');
    img.src = 'https://images.example-csp-test.test/pixel.png';
    img.alt = 'blocked image';
    document.getElementById('trigger-panel').appendChild(img);
    return 'loaded <img src=https://images.example-csp-test.test/...>';
  },
  'inline-style'() {
    const d = document.createElement('div');
    d.setAttribute('style', 'color: hotpink');
    d.textContent = 'styled via attribute';
    document.getElementById('trigger-panel').appendChild(d);
    return 'set style="color: hotpink" via setAttribute';
  },
  'style-tag'() {
    const st = document.createElement('style');
    st.textContent = '.x { color: red; }';
    document.head.appendChild(st);
    return 'injected a <style> block';
  },
  'data-script'() {
    const s = document.createElement('script');
    s.src = "data:text/javascript,console.log('data uri script')";
    document.head.appendChild(s);
    return 'loaded a data: script';
  },
  connect() {
    fetch('https://collector.example-csp-test.test/collect', { mode: 'no-cors' }).catch(() => {});
    return 'fetch() to https://collector.example-csp-test.test/collect';
  },
};

document.getElementById('trigger-panel').addEventListener('click', (e) => {
  const action = e.target.getAttribute && e.target.getAttribute('data-action');
  if (action && TRIGGERS[action]) {
    log(TRIGGERS[action]());
  }
});

// The two auto-violations baked into the HTML source:
log('page loaded — inline <script> and onclick="" in source already reported');

// ---- Dashboard rendering ---------------------------------------------------

function barRows(container, entries, total) {
  if (!entries || !entries.length) {
    container.innerHTML = '<p class="empty">No data yet.</p>';
    return;
  }
  container.innerHTML = entries
    .map((entry) => {
      const pct = total ? Math.max(2, Math.round((entry.count / total) * 100)) : 0;
      return (
        `<div class="bar-row"><span class="bar-label" title="${esc(entry.name)}">${esc(entry.name)}</span>` +
        `<span class="bar-track"><span class="bar-fill" style="width:${pct}%"></span></span>` +
        `<span class="bar-count">${entry.count}</span></div>`
      );
    })
    .join('');
}

function renderCards(summary, analysis) {
  const cards = [
    [summary.totalEvents, 'violations'],
    [summary.totalIssues, 'unique issues'],
    [analysis.firstParty, 'first-party'],
    [analysis.thirdParty, 'third-party'],
    [analysis.inline, 'inline / eval'],
  ];
  document.getElementById('cards').innerHTML = cards
    .map(([n, label]) => `<div class="card"><b>${n}</b><span>${label}</span></div>`)
    .join('');
}

function renderTrend(trend) {
  const el = document.getElementById('trend');
  if (!trend || !trend.length) {
    el.innerHTML = '<p class="empty">No data yet.</p>';
    return;
  }
  const max = Math.max(1, ...trend.map((b) => b.count));
  el.innerHTML = `<div class="trend">${trend
    .map((b) => `<span style="height:${Math.round((b.count / max) * 100)}%" title="${new Date(b.t).toLocaleTimeString()}: ${b.count}"></span>`)
    .join('')}</div>`;
}

function renderIssue(agg, index) {
  const r = agg.remediation || {};
  const locations = Object.values(agg.locations || {})
    .sort((a, b) => b.count - a.count)
    .slice(0, 6)
    .map(
      (l) =>
        `<li>${esc(l.sourceFile || '(inline)')}:${l.line}:${l.col} ×${l.count}` +
        (l.sample ? ` — <code>${esc(l.sample.slice(0, 140))}</code>` : '') +
        `</li>`
    )
    .join('');
  const steps = (r.steps || []).map((step) => `<li>${esc(step)}</li>`).join('');
  const target = esc(agg.blockedOrigin || agg.blockedUri || '(inline)');
  return `
    <div class="issue severity-${esc(r.severity || 'low')}" data-key="${esc(agg.key)}">
      <div class="issue-head">
        <div>
          <div class="issue-title">#${index + 1} ${esc(r.title || agg.effectiveDirective)}</div>
          <div class="issue-meta">${esc(agg.effectiveDirective)} · ${esc(agg.blockedKind)} · ${target}</div>
        </div>
        <div><span class="pill ${esc(r.severity || 'low')}">${esc(r.severity || 'low')}</span> <span class="pill">×${agg.count}</span></div>
      </div>
      <div class="issue-body">
        <p>${esc(r.description || '')}</p>
        <h4>Suggested CSP change</h4>
        <pre class="code">${esc(r.policySnippet || '')}</pre>
        ${r.before ? `<h4>Before / after</h4><pre class="code">${esc(r.before)}\n---\n${esc(r.after || '')}</pre>` : ''}
        <h4>Steps</h4><ol>${steps}</ol>
        <h4>Top violating locations</h4>
        <ul class="locs">${locations || '<li>n/a</li>'}</ul>
      </div>
    </div>`;
}

let lastDashboard = null;

async function refresh() {
  const dash = await monitor.getDashboard();
  lastDashboard = dash;
  const filter = document.getElementById('filter').value.trim().toLowerCase();

  renderCards(dash.summary, dash.originAnalysis);
  barRows(document.getElementById('origins'), dash.originAnalysis.topOrigins, dash.originAnalysis.firstParty + dash.originAnalysis.thirdParty);
  barRows(document.getElementById('directives'), dash.originAnalysis.directives, dash.originAnalysis.total);
  barRows(document.getElementById('categories'), dash.originAnalysis.categories, dash.originAnalysis.total);
  renderTrend(dash.trend);

  const filtered = dash.aggregates.filter((a) => {
    if (!filter) return true;
    const hay = `${a.effectiveDirective} ${a.blockedUri || ''} ${a.blockedOrigin || ''} ${a.blockedKind} ${(a.remediation && a.remediation.title) || ''}`.toLowerCase();
    return hay.includes(filter);
  });
  const issuesEl = document.getElementById('issues');
  issuesEl.innerHTML = filtered.length
    ? filtered.map((a, i) => renderIssue(a, i)).join('')
    : '<p class="empty">No matching issues. Try the buttons above to generate violations.</p>';

  const tbody = document.querySelector('#events-table tbody');
  tbody.innerHTML = dash.events
    .slice(0, 50)
    .map(
      (e) =>
        `<tr><td>${new Date(e.ts).toLocaleTimeString()}</td><td>${esc(e.effectiveDirective)}</td>` +
        `<td>${esc(e.blockedKind)}</td><td>${esc((e.blockedUri || '(inline)').slice(0, 80))}</td>` +
        `<td>${esc((e.sourceFile || '(inline)').split('/').slice(-1)[0])}:${e.lineNumber}</td></tr>`
    )
    .join('');
}

document.getElementById('issues').addEventListener('click', (e) => {
  const issue = e.target.closest('.issue');
  if (issue) issue.classList.toggle('open');
});
document.getElementById('refresh').addEventListener('click', () => refresh().catch(console.error));
document.getElementById('filter').addEventListener('input', () => refresh());

// Coalesce bursts of ingested events into one dashboard refresh.
let dirtyTimer = 0;
monitor.on('dirty', () => {
  if (!document.getElementById('auto-refresh').checked) return;
  clearTimeout(dirtyTimer);
  dirtyTimer = setTimeout(() => refresh().catch(console.error), 300);
});
setInterval(() => {
  if (document.getElementById('auto-refresh').checked) refresh().catch(() => {});
}, 5000);

// ---- Export / clear --------------------------------------------------------

async function downloadReport(format) {
  const report = await monitor.exportReport(format);
  const blob = new Blob([report.content], { type: report.mime });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `csp-report-${new Date().toISOString().replace(/[:.]/g, '-')}.${report.ext}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  log(`exported ${format.toUpperCase()} report`);
}

document.getElementById('export-json').addEventListener('click', () => downloadReport('json').catch(console.error));
document.getElementById('export-csv').addEventListener('click', () => downloadReport('csv').catch(console.error));
document.getElementById('export-html').addEventListener('click', () => downloadReport('html').catch(console.error));
document.getElementById('clear').addEventListener('click', async () => {
  if (confirm('Delete all stored violations and aggregates?')) {
    await monitor.clear();
    log('cleared IndexedDB store');
    await refresh();
  }
});

refresh().catch(console.error);
