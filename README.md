# CSP 违规观测台

一个零构建依赖的静态 Web 应用，用 `SecurityPolicyViolationEvent` 捕获内容安全策略违规，在 Web Worker 中通过 IndexedDB 持久化并聚合，提供来源分析、可操作修复建议和 JSON/CSV 报告导出。

## 功能

- **违规捕获**：捕获阶段监听 `securitypolicyviolation`，最早的引导脚本会暂存解析期事件。
- **违规聚合**：按 CSP 指令、来源类型、外部 origin/path、源码位置和代码模式生成稳定指纹。
- **来源分析**：统计 origin、页面、来源文件、行号、样本、可信浏览器事件和压力测试事件。
- **修复建议**：内联脚本建议随机 nonce 与 `strict-dynamic`，内联事件建议 `addEventListener`，外链建议最小 origin 与 SRI。
- **报告导出**：支持聚合 JSON、含原始事件 JSON 和 CSV，CSV 带 UTF-8 BOM，适合 Excel 打开。
- **性能保护**：主线程 100 条批量上报，队列上限 2000；聚合和 IndexedDB 在 Worker；UI 最多渲染 100 张卡片。
- **持久化降级**：IndexedDB 不可用时自动退回 Worker 内存模式，不阻断采集。

## 本地运行

ESM Worker 不能通过 `file://` 加载，请使用静态 HTTP 服务：

```bash
npm start
```

然后打开：

```text
http://127.0.0.1:4173/
```

运行测试：

```bash
npm test
```

## 验收路径

1. 页面加载后自动出现一个可信内联脚本违规：`index.html` 中故意放置了缺少 nonce 的 `<script>`。
2. 展开聚合卡片，可看到 `script-src 'nonce-...' 'strict-dynamic'` 响应头和带 nonce 的 HTML 示例。
3. 点击“制造内联事件违规”或“制造外部图片违规”，验证不同来源分类和建议。
4. 点击“导出 JSON / CSV”，验证报告可下载。
5. 点击“生成 1000 条压力事件”，观察队列、批量投递和渲染耗时。

## 架构

```text
Document CSP Event
  → src/bootstrap.js 捕获解析期事件
  → src/monitor.js 去重、限流、批量投递
  → src/csp-worker.js 聚合与 IndexedDB
  → src/app.js 渲染、筛选、导出
```

核心纯逻辑位于：

- `src/csp.js`：事件字段、来源分类、稳定指纹、nonce 工具。
- `src/aggregation.js`：记录建模、聚合、筛选、报告结构。
- `src/recommendations.js`：修复建议模板和代码片段。
- `src/export-report.js`：JSON/CSV 构建与浏览器下载。

## 生产 nonce 要求

页面中的 `demo-20260920-static-change-per-request` 仅用于本地演示，生产环境必须由服务端对每个响应生成新的不可猜测随机值，并保证 CSP 响应头和 `script nonce` 完全一致。不要把 nonce 写入可缓存的静态 HTML，也不要同时依赖 `unsafe-inline`。

推荐脚本策略形态：

```http
Content-Security-Policy: script-src 'nonce-每请求随机值' 'strict-dynamic'; object-src 'none'; base-uri 'none'
```
