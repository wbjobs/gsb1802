import {
  NONE,
  directiveLabel,
  normalizeDirective,
  originOf,
  pathOf,
  safeText,
  text
} from './csp.js';

export function buildRecommendation(record, nonce) {
  const directive = normalizeDirective(record.directive);
  const source = record.source || {};

  if (source.kind === 'inline-script') {
    return inlineScriptRecommendation(record, nonce);
  }
  if (source.kind === 'inline-handler') {
    return inlineHandlerRecommendation(record, nonce);
  }
  if (source.kind === 'inline-style' || source.kind === 'inline-style-attribute') {
    return inlineStyleRecommendation(record, source.kind, nonce);
  }
  if (source.kind === 'eval') {
    return evalRecommendation(record);
  }
  if (source.kind === 'data-url') {
    return dataUrlRecommendation(record);
  }
  if (source.kind === 'external-resource') {
    return externalResourceRecommendation(record);
  }
  if (directive === 'frame-ancestors') {
    return frameAncestorsRecommendation(record);
  }
  if (directive === 'base-uri') {
    return baseUriRecommendation(record);
  }
  return genericRecommendation(record);
}

function inlineScriptRecommendation(record, nonce) {
  const generatedNonce = nonce || 'SERVER_GENERATED_NONCE';
  const directive = normalizeDirective(record.directive);
  const policyDirective = directive === 'script-src-elem' ? directive : 'script-src';
  return {
    priority: 'critical',
    title: '为内联脚本添加一次性 nonce，优先把代码移到外部文件',
    rationale: '当前 CSP 没有允许该内联脚本。nonce 必须由服务端为每次响应随机生成，不要把固定 nonce 用于生产环境。',
    actions: [
      '为响应生成 16 字节以上的随机 base64 nonce，并让 CSP 响应头与 script 标签使用同一个值。',
      '给被拦截脚本添加 nonce 属性；如果能重构，优先改为外部静态脚本。',
      '确认 CSP 中没有同时使用 unsafe-inline，nonce 存在时现代浏览器会忽略 unsafe-inline。'
    ],
    snippets: [
      {
        label: '响应头',
        language: 'http',
        code: `Content-Security-Policy: ${policyDirective} 'nonce-${generatedNonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'`
      },
      {
        label: 'HTML',
        language: 'html',
        code: `<script nonce="${generatedNonce}">${safeText(record.sample || 'console.log(\'safe inline\')', 120)}</script>`
      }
    ]
  };
}

function inlineHandlerRecommendation(record, nonce) {
  const generatedNonce = nonce || 'SERVER_GENERATED_NONCE';
  const eventMatch = text(record.sample).match(/\bon([a-z]+)/i);
  const eventName = eventMatch ? eventMatch[1].toLowerCase() : 'click';
  return {
    priority: 'high',
    title: '移除内联事件处理器，使用 addEventListener 绑定',
    rationale: '内联 on* 属性属于 script-src-attr 违规；即使加入 nonce，也不能直接给事件属性授权。',
    actions: [
      '删除 HTML 中 onclick、onload、onerror 等内联事件属性。',
      '在带 nonce 的外部脚本或已授权脚本中使用 addEventListener。',
      '为动态模板统一通过事件委托绑定，避免再次生成内联处理器。'
    ],
    snippets: [
      {
        label: 'HTML',
        language: 'html',
        code: '<button type="button" data-action="save">保存</button>'
      },
      {
        label: 'JavaScript',
        language: 'javascript',
        code: `<script nonce="${generatedNonce}">\ndocument.querySelector('[data-action="save"]')\n  .addEventListener('${eventName}', handleSave);\n</script>`
      }
    ]
  };
}

function inlineStyleRecommendation(record, kind, nonce) {
  const generatedNonce = nonce || 'SERVER_GENERATED_NONCE';
  const directive = normalizeDirective(record.directive);
  const policyDirective = directive.startsWith('style-src') ? directive : 'style-src';
  if (kind === 'inline-style-attribute') {
    return {
      priority: 'medium',
      title: '把内联 style 属性迁移到样式类',
      rationale: '元素 style 属性不能使用 nonce 授权。应使用 CSS 类，或在确认框架注入风险后再使用更宽松策略。',
      actions: [
        '将固定样式写入 CSS class；运行时状态通过切换 class 完成。',
        '检查是否由 UI 框架注入样式，必要时为框架生成的 style 元素添加 nonce。'
      ],
      snippets: [
        {
          label: 'CSS',
          language: 'css',
          code: '.is-danger { color: #b91c1c; }'
        },
        {
          label: 'HTML',
          language: 'html',
          code: '<p class="is-danger">需要警示的内容</p>'
        },
        {
          label: '临时兼容策略',
          language: 'http',
          code: `Content-Security-Policy: ${policyDirective} 'self' 'unsafe-hashes' 'sha256-...';`
        }
      ]
    };
  }

  return {
    priority: 'medium',
    title: '为内联样式块使用 nonce 或迁移到外部 CSS',
    rationale: '<style> 块可以通过 nonce 授权，但 style 属性不能。静态样式最好移到外部 CSS 文件。',
    actions: [
      '为 style 元素添加与 CSP 响应头一致的随机 nonce。',
      '静态样式迁移到 .css 文件后使用 link rel="stylesheet" 加载。'
    ],
    snippets: [
      {
          label: '响应头',
          language: 'http',
          code: `Content-Security-Policy: ${policyDirective} 'self' 'nonce-${generatedNonce}';`
      },
      {
          label: 'HTML',
          language: 'html',
          code: `<style nonce="${generatedNonce}">.panel { display: grid; }</style>`
      }
    ]
  };
}

function evalRecommendation(record) {
  return {
    priority: 'high',
    title: '消除 eval / Function 构造器，谨慎使用 unsafe-eval',
    rationale: "'unsafe-eval' 会显著扩大 XSS 影响面，应先改造动态执行代码；只在无法立即替换的第三方库上作为临时例外。",
    actions: [
      '把 eval(jsonString) 替换为 JSON.parse，把动态函数改为显式映射表。',
      '检查 setTimeout("...")、setInterval("...") 和 new Function。',
      '若第三方库强制依赖，隔离该库并单独评估风险，避免全站放开 unsafe-eval。'
    ],
    snippets: [
      {
        label: '安全替换',
        language: 'javascript',
        code: "const data = JSON.parse(jsonString);\nconst handlers = { save: handleSave, delete: handleDelete };\nhandlers[actionName]?.();"
      },
      {
        label: '不推荐的临时策略',
        language: 'http',
        code: "Content-Security-Policy: script-src 'self' 'unsafe-eval';"
      }
    ]
  };
}

function externalResourceRecommendation(record) {
  const source = record.source || {};
  const origin = source.origin || originOf(record.blockedURI);
  const path = source.path || pathOf(record.blockedURI);
  const directive = normalizeDirective(record.directive);
  const host = origin === NONE ? 'https://trusted.example.com' : origin;
  return {
    priority: 'high',
    title: `将可信来源加入 ${directiveLabel(directive)}`,
    rationale: '只添加实际需要的最小来源，优先使用 origin 或路径隔离；不要为了消除单个告警直接放开 https:、data: 或 *。',
    actions: [
      `确认 ${host}${path === '/' ? '' : path} 是业务必需且由可信方提供。`,
      `把该来源追加到 ${directive}；同源资源应使用 'self'。`,
      '为脚本加载添加 SRI 与 crossorigin；能自托管的第三方脚本优先自托管。'
    ],
    snippets: [
      {
        label: '响应头',
        language: 'http',
        code: `Content-Security-Policy: ${directive} 'self' ${host};`
      },
      {
        label: '带完整性校验的脚本',
        language: 'html',
        code: '<script src="https://trusted.example.com/app.js" integrity="sha384-..." crossorigin="anonymous"></script>'
      }
    ]
  };
}

function dataUrlRecommendation(record) {
  const directive = normalizeDirective(record.directive);
  return {
    priority: 'medium',
    title: '避免使用 data: URL，必要时最小授权',
    rationale: 'data: 可携带可执行内容或绕过来源边界，脚本场景尤其不应全局放开。',
    actions: [
      '把资源改成同源静态文件或可信 CDN 文件。',
      `图片/字体确需 data: 时，只在 ${directive} 中添加 data:，不要加入 script-src。`,
      '检查用户输入是否能控制 data: 的 MIME 类型或内容。'
    ],
    snippets: [
      {
        label: '响应头',
        language: 'http',
        code: `Content-Security-Policy: ${directive} 'self' data:;`
      }
    ]
  };
}

function frameAncestorsRecommendation(record) {
  const origin = originOf(record.blockedURI || record.documentURI);
  return {
    priority: 'high',
    title: '限制允许嵌入当前页面的父级来源',
    rationale: 'frame-ancestors 用于防点击劫持，应明确列出可信父页面，而不是放开为 *。',
    actions: [
      `确认父页面 ${origin} 是否应允许嵌入。`,
      "不需要被嵌入时设置 frame-ancestors 'none'。",
      '需要嵌入时仅列出来源，例如 https://app.example.com。'
    ],
    snippets: [
      {
        label: '响应头',
        language: 'http',
        code: `Content-Security-Policy: frame-ancestors ${origin === NONE ? "'none'" : origin};`
      }
    ]
  };
}

function baseUriRecommendation(record) {
  return {
    priority: 'high',
    title: "锁定 base-uri，防止相对脚本 URL 被重写",
    rationale: "页面不使用 <base> 时通常应设置为 'none'；需要时仅允许可信来源。",
    actions: [
      "不使用 base 标签：设置 base-uri 'none'。",
      '检查页面是否存在用户可控的 base 标签。'
    ],
    snippets: [
      {
        label: '响应头',
        language: 'http',
        code: "Content-Security-Policy: base-uri 'none';"
      }
    ]
  };
}

function genericRecommendation(record) {
  const directive = normalizeDirective(record.directive);
  return {
    priority: 'medium',
    title: `检查并收紧 ${directiveLabel(directive)} 策略`,
    rationale: '该违规未落入内置模板，请根据被拦截资源、来源文件和当前策略确认业务需求。',
    actions: [
      '先验证触发路径是否可信、是否为业务必需。',
      `只向 ${directive} 添加最小必要来源或关键字。`,
      '先在 Content-Security-Policy-Report-Only 模式验证，再切换为强制策略。'
    ],
    snippets: [
      {
        label: '报告模式',
        language: 'http',
        code: `Content-Security-Policy-Report-Only: ${directive} 'self'; report-uri /csp-report;`
      }
    ]
  };
}
