# CSP Violation Monitor

监听页面的 `securitypolicyviolation` 事件，在 **Web Worker** 中做聚合与来源分析，
原始事件和聚合结果持久化到 **IndexedDB**，并给出可操作的 CSP 修复建议与可导出报告。
零依赖、无构建步骤。

## 功能

- **违规捕获**：捕获阶段监听 `securitypolicyviolation`；`src/boot.js` 在 `<head>`
  最先加载，可捕获解析期内联脚本违规（模块脚本加载前的事件不丢失）。
- **违规聚合**：按「指令 + 资源身份（内联 / eval / data: / blob: / 来源 origin）+
  页面 origin」精确分组，组内再按「文件:行:列:样本」记录每个位置的次数，
  总数与分组数始终精确。
- **来源分析**：一方 / 三方拆分（eTLD+1 判定）、Top 来源、服务商分类
  （analytics / cdn / ads / social / fonts）、指令分布、每分钟趋势。
- **修复建议**：每种问题给出严重级别、说明、可直接粘贴的 CSP 片段、
  before/after 代码和分步操作。内联脚本违规明确建议 **per-response nonce**，
  并示范如何把 `onclick=""` 改写为 `addEventListener`。
- **报告导出**：JSON（含全部原始事件）、CSV（问题 + 原始事件两段）、
  独立 HTML 报告（图表 + 修复步骤）。
- **性能**：主线程只做轻量规范化；事件按 1s/100 条微批次交给 Worker；
  IndexedDB 读写、聚合、导出全部在 Worker 内；Worker 串行化消息避免
  事务冲突；原始事件上限 5000 条自动裁剪；趋势序列最多 60 个时间桶。

## 快速开始

```bash
npm start          # http://127.0.0.1:8080/
npm test           # Node 内置 test runner，6 个测试文件
```

页面本身带一条严格的 CSP（`default-src 'none'; script-src 'self'; …`），
HTML 源码里故意放置内联 `<script>` 和 `onclick`，打开页面即可看到
**内联脚本违规被捕获并给出 nonce 建议**。上方按钮可制造 eval、三方脚本 /
图片、内联样式、data: 脚本、被拦截的 fetch 等各类违规。

> 必须通过 HTTP 访问（ES Module + Worker 要求），不要用 `file://`。

## 接入自己的页面

```html
<head>
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; worker-src 'self'">
  <script src="/src/boot.js"></script>
  <script type="module">
    import { createMonitor } from '/src/monitor.js';
    const monitor = createMonitor();
    monitor.getDashboard().then(console.log);
    // const report = await monitor.exportReport('html'); // json | csv | html
  </script>
</head>
```

生产环境建议先用响应头 `Content-Security-Policy-Report-Only` 观察，
配合本工具收集报告后再切换为强制模式。

## 目录结构

| 路径 | 职责 |
| --- | --- |
| `src/boot.js` | 最早加载的微型捕获器，缓冲早期违规事件 |
| `src/monitor.js` | 主线程入口：监听、规范化、微批次、Worker RPC |
| `src/worker.js` | Worker：串行消息处理 |
| `src/controller.js` | 核心管线：入库 → 增量聚合 → 分析 → 导出 |
| `src/normalize.js` | `SecurityPolicyViolationEvent` → 紧凑记录 |
| `src/aggregate.js` | 分组键、位置指纹、增量合并、时间桶 |
| `src/remediation.js` | 修复建议规则（nonce / eval / origin / data/blob 等） |
| `src/sources.js` | 一方三方判定、分类与来源统计 |
| `src/export.js` | JSON / CSV / HTML 报告构建 |
| `src/store.js` | IndexedDB 封装（事件 5000 条裁剪 + 聚合表） |
| `public/` | 演示仪表盘（自带严格 CSP 的测试夹具） |
| `test/` | 纯逻辑单测 + 内存假 IndexedDB 的端到端管线测试 |

## 验收对照

- 捕获内联脚本违规并建议 nonce：`test/normalize.test.js`、`test/remediation.test.js`、
  演示页源码中的内联脚本。
- 聚合准确：`test/aggregate.test.js`（同组次数、不同指令 / 主机不合并、
  重启后续聚合仍精确）。
- 报告可导出：`test/export.test.js`、`test/pipeline.test.js`（JSON/CSV/HTML）。
- 性能可接受：`test/pipeline.test.js` 中 2000 条事件的入库与查询耗时断言；
  主线程零 IndexedDB / 聚合开销。
- 修复建议可操作：每条建议含策略片段、before/after、分步说明。
