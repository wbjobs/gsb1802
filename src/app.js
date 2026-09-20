import { filterGroups, summarize } from './aggregation.js';
import { directiveLabel, generateNonce } from './csp.js';
import { downloadReport, timestampForFilename } from './export-report.js';
import { bindDocumentListener, createCspMonitor, generateLoad, simulateViolation } from './monitor.js';

const state = {
  groups: [],
  stats: {},
  filters: {
    directive: '',
    sourceKind: '',
    origin: '',
    query: '',
    hideLoadTest: false
  },
  expanded: new Set(),
  performance: {
    renderMs: 0,
    lastLoadMs: 0,
    loadCount: 0
  }
};

const elements = {};
const MAX_RENDERED_GROUPS = 100;

init();

function init() {
  cacheElements();
  const monitor = createCspMonitor({
    workerUrl: './src/csp-worker.js',
    nonce: window.__CSP_NONCE__ || ''
  });
  bindDocumentListener(monitor);
  monitor.drainEarlyQueue(window.__CSP_QUEUE__);

  monitor.subscribe((message) => {
    if (message.type === 'STATE') {
      state.groups = message.groups || [];
      state.stats = message.stats || {};
      render();
      updatePerformance(monitor);
    }
    if (message.type === 'EXPORT_READY') {
      downloadReport(`csp-report-${timestampForFilename()}.${message.format}`, message.content, message.mimeType);
    }
    if (message.type === 'ERROR') {
      elements.status.textContent = `Worker 错误：${message.error}`;
    }
  });

  elements.filterForm.addEventListener('input', render);
  elements.filterForm.addEventListener('change', render);
  elements.exportJson.addEventListener('click', () => monitor.send({ type: 'EXPORT', options: { format: 'json', includeRaw: false } }));
  elements.exportJsonRaw.addEventListener('click', () => monitor.send({ type: 'EXPORT', options: { format: 'json', includeRaw: true } }));
  elements.exportCsv.addEventListener('click', () => monitor.send({ type: 'EXPORT', options: { format: 'csv', includeRaw: false } }));
  elements.clearAll.addEventListener('click', () => monitor.send({ type: 'CLEAR', scope: 'all' }));
  elements.clearLoadTest.addEventListener('click', () => monitor.send({ type: 'CLEAR', scope: 'load-test' }));
  elements.trustInline.addEventListener('click', () => globalThis.location.reload());
  elements.trustHandler.addEventListener('click', triggerInlineHandler);
  elements.trustExternal.addEventListener('click', () => {
    const image = new Image();
    image.src = 'https://blocked-images.example.test/denied.png';
    image.alt = 'blocked external image';
    elements.demoHost.append(image);
  });
  elements.synthetic.addEventListener('click', () => simulateViolation());
  elements.loadTest.addEventListener('click', async () => {
    elements.loadTest.disabled = true;
    const result = await generateLoad(monitor, { count: 1000 });
    state.performance.lastLoadMs = result.dispatchMs;
    state.performance.loadCount = result.count;
    elements.loadTest.disabled = false;
    render();
  });
  elements.rotateNonce.addEventListener('click', async () => {
    elements.rotatedNonce.textContent = await generateNonce();
  });

  elements.groupList.addEventListener('click', (event) => {
    const button = event.target.closest('[data-action="toggle-group"]');
    if (!button) {
      return;
    }
    const fingerprint = button.getAttribute('data-fingerprint');
    if (state.expanded.has(fingerprint)) {
      state.expanded.delete(fingerprint);
    } else {
      state.expanded.add(fingerprint);
    }
    render();
  });

  window.__cspApp = { monitor, state };
}

function cacheElements() {
  for (const id of [
    'filterForm',
    'fDirective',
    'fKind',
    'fOrigin',
    'fQuery',
    'fHideLoadTest',
    'totalEvents',
    'groupCount',
    'trustedEvents',
    'loadTestEvents',
    'originSummary',
    'directiveSummary',
    'groupList',
    'exportJson',
    'exportJsonRaw',
    'exportCsv',
    'clearAll',
    'clearLoadTest',
    'trustInline',
    'trustHandler',
    'trustExternal',
    'synthetic',
    'loadTest',
    'rotateNonce',
    'rotatedNonce',
    'status',
    'demoHost',
    'perfQueue',
    'perfBatch',
    'perfRender',
    'perfLoad',
    'perfDropped'
  ]) {
    elements[toCamel(id)] = document.getElementById(id);
  }
}

function render() {
  const started = performance.now();
  readFilters();
  const filtered = filterGroups(state.groups, state.filters);
  const summary = summarize(state.groups, state.stats.total || 0);
  renderSummary(summary, filtered.length);
  renderFilterOptions(summary);
  renderGroupList(filtered.slice(0, MAX_RENDERED_GROUPS), filtered.length);
  state.performance.renderMs = performance.now() - started;
  updatePerformance(window.__cspApp.monitor);
}

function readFilters() {
  state.filters.directive = elements.fDirective.value;
  state.filters.sourceKind = elements.fKind.value;
  state.filters.origin = elements.fOrigin.value;
  state.filters.query = elements.fQuery.value;
  state.filters.hideLoadTest = elements.fHideLoadTest.checked;
}

function renderSummary(summary, filteredCount) {
  elements.totalEvents.textContent = summary.total;
  elements.groupCount.textContent = `${filteredCount}/${summary.groups}`;
  elements.trustedEvents.textContent = summary.trusted;
  elements.loadTestEvents.textContent = summary.loadTest;
  elements.originSummary.replaceChildren(...renderTopCounts(summary.originCounts));
  elements.directiveSummary.replaceChildren(...Object.entries(summary.directiveCounts)
    .sort((left, right) => right[1] - left[1])
    .map(([directive, count]) => metricLine(`${directiveLabel(directive)} (${directive})`, count)));
}

function renderTopCounts(object) {
  const entries = Object.entries(object).slice(0, 6);
  if (!entries.length) {
    return [emptyLine('暂无数据')];
  }
  return entries.map(([name, count]) => metricLine(name, count));
}

function renderFilterOptions(summary) {
  syncSelect(elements.fDirective, Object.keys(summary.directiveCounts), state.filters.directive, (value) => `${directiveLabel(value)} · ${value}`);
  syncSelect(elements.fKind, Object.keys(summary.sourceCounts), state.filters.sourceKind, sourceKindLabel);
  syncSelect(elements.fOrigin, Object.keys(summary.originCounts), state.filters.origin, (value) => value);
}

function syncSelect(select, values, selected, labelFactory) {
  const current = selected || '';
  const options = ['<all>'].concat(values.sort());
  select.replaceChildren(...options.map((value) => {
    const option = document.createElement('option');
    option.value = value === '<all>' ? '' : value;
    option.textContent = value === '<all>' ? '全部' : labelFactory(value);
    option.selected = option.value === current;
    return option;
  }));
}

function renderGroupList(filtered, totalFiltered = filtered.length) {
  if (!filtered.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = state.groups.length ? '没有匹配当前筛选条件的违规。' : '尚未捕获 CSP 违规。点击“制造内联脚本违规”验证 nonce 建议。';
    elements.groupList.replaceChildren(empty);
    return;
  }

  const cards = filtered.map((group) => {
    const article = document.createElement('article');
    article.className = `violation-card priority-${group.recommendation?.priority || 'medium'}`;

    const header = document.createElement('button');
    header.className = 'card-header';
    header.type = 'button';
    header.dataset.action = 'toggle-group';
    header.dataset.fingerprint = group.fingerprint;
    header.setAttribute('aria-expanded', state.expanded.has(group.fingerprint) ? 'true' : 'false');
    header.append(
      strong(`${sourceKindLabel(group.sourceKind)} · ${group.count} 次`),
      span(group.directive, 'tag'),
      span(group.disposition === 'report' ? '报告模式' : '强制模式', `tag ${group.disposition}`),
      span(`${priorityLabel(group.recommendation?.priority)}`, 'tag priority-tag'),
      span(formatDate(group.lastSeen), 'muted')
    );
    article.append(header);

    if (state.expanded.has(group.fingerprint)) {
      article.append(renderDetails(group));
    }
    return article;
  });
  if (totalFiltered > filtered.length) {
    const more = document.createElement('div');
    more.className = 'empty';
    more.textContent = `仅渲染前 ${filtered.length}/${totalFiltered} 个聚合，请使用筛选缩小范围。`;
    cards.push(more);
  }
  elements.groupList.replaceChildren(...cards);
}

function renderDetails(group) {
  const details = document.createElement('div');
  details.className = 'details';

  const sourceGrid = document.createElement('div');
  sourceGrid.className = 'source-grid';
  sourceGrid.append(
    infoBlock('来源分析', [
      `类型：${sourceKindLabel(group.sourceKind)}`,
      `指令：${group.directive}`,
      `被阻止：${group.blockedURI || '(inline)'}`,
      `首次：${formatDate(group.firstSeen)}`,
      `最近：${formatDate(group.lastSeen)}`
    ]),
    infoBlock('命中位置', Object.entries(group.origins || {}).map(([origin, count]) => `${origin} · ${count} 次`)
      .concat(Object.keys(group.sourceFiles || {}).slice(0, 3).map((file) => `文件：${file}`))
      .concat(group.lines.map((line) => `行号：${line}`))),
    infoBlock('样本', (group.samples.length ? group.samples : ['无样本']).slice(0, 3))
  );
  details.append(sourceGrid);

  const recommendation = group.recommendation;
  if (recommendation) {
    const repair = document.createElement('section');
    repair.className = 'repair';
    repair.append(strong(recommendation.title));
    const rationale = document.createElement('p');
    rationale.textContent = recommendation.rationale;
    repair.append(rationale);
    const list = document.createElement('ol');
    list.append(...recommendation.actions.map((action) => {
      const item = document.createElement('li');
      item.textContent = action;
      return item;
    }));
    repair.append(list);
    for (const snippet of recommendation.snippets || []) {
      repair.append(codeBlock(snippet));
    }
    details.append(repair);
  }

  return details;
}

function infoBlock(title, lines) {
  const block = document.createElement('div');
  block.className = 'info-block';
  block.append(strong(title));
  const list = document.createElement('ul');
  list.append(...lines.map((line) => {
    const item = document.createElement('li');
    item.textContent = line;
    return item;
  }));
  block.append(list);
  return block;
}

function codeBlock(snippet) {
  const wrapper = document.createElement('div');
  wrapper.className = 'code-block';
  const label = document.createElement('div');
  label.className = 'code-label';
  label.textContent = snippet.label;
  const pre = document.createElement('pre');
  const code = document.createElement('code');
  code.className = `language-${snippet.language}`;
  code.textContent = snippet.code;
  pre.append(code);
  wrapper.append(label, pre);
  return wrapper;
}

function updatePerformance(monitor) {
  const metrics = monitor.metrics();
  elements.perfQueue.textContent = `${metrics.queued}/${metrics.maxQueueSize}`;
  elements.perfBatch.textContent = `${metrics.lastBatchDuration.toFixed(2)} ms（每批 ${metrics.maxBatchSize}）`;
  elements.perfRender.textContent = `${state.performance.renderMs.toFixed(2)} ms`;
  elements.perfLoad.textContent = state.performance.loadCount
    ? `${state.performance.loadCount} 条 / ${state.performance.lastLoadMs.toFixed(2)} ms`
    : '未运行';
  elements.perfDropped.textContent = metrics.dropped;
}

function triggerInlineHandler() {
  const button = document.createElement('button');
  button.type = 'button';
  button.setAttribute('onclick', 'return false');
  button.textContent = '被 CSP 阻止的内联处理器';
  elements.demoHost.append(button);
}

function metricLine(name, count) {
  const line = document.createElement('div');
  line.className = 'metric-line';
  line.append(span(name, 'metric-name'), span(String(count), 'metric-value'));
  return line;
}

function emptyLine(text) {
  const line = document.createElement('div');
  line.className = 'muted';
  line.textContent = text;
  return line;
}

function strong(text) {
  const element = document.createElement('strong');
  element.textContent = text;
  return element;
}

function span(text, className = '') {
  const element = document.createElement('span');
  if (className) {
    element.className = className;
  }
  element.textContent = text;
  return element;
}

function sourceKindLabel(kind) {
  const labels = {
    'inline-script': '内联脚本',
    'inline-handler': '内联事件',
    'inline-style': '内联样式块',
    'inline-style-attribute': '内联 style 属性',
    eval: 'eval 动态执行',
    'external-resource': '外部资源',
    'data-url': 'data: URL',
    other: '其他'
  };
  return labels[kind] || kind;
}

function priorityLabel(priority) {
  return {
    critical: '严重',
    high: '高',
    medium: '中',
    low: '低'
  }[priority] || '中';
}

function formatDate(value) {
  return new Intl.DateTimeFormat('zh-CN', {
    hour12: false,
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  }).format(new Date(value));
}

function toCamel(id) {
  return id.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
}
