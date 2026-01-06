# AI-Vuln-Reproduce

AI 全自动漏洞复现智能体平台 - 基于 Claude Code 的多智能体协作系统

## 项目简介

本项目利用 Claude Code CLI 的智能体能力，实现从漏洞报告到复现验证的端到端自动化。通过多智能体协作，自动完成环境搭建、测试数据准备、PoC 构造和漏洞验证。

## 快速开始

### 一键安装

```bash
# 克隆项目
git clone https://github.com/Clouditera/AI-Vuln-Reproduce.git
cd AI-Vuln-Reproduce

# 运行安装脚本
chmod +x setup.sh
./setup.sh
```

安装脚本会自动完成：
- ✅ 检查系统依赖 (Node.js 18+)
- ✅ 安装 Playwright Chromium 浏览器
- ✅ 配置 Claude Code MCP

### 手动安装

<details>
<summary>点击展开手动安装步骤</summary>

1. **安装依赖**
```bash
# 安装 Playwright 浏览器
npx playwright install chromium
npx playwright install-deps chromium  # Linux 需要
```

2. **配置 MCP**

将 `config/mcp-settings.json` 内容合并到 `~/.claude/settings.json`：

```json
{
  "mcpServers": {
    "playwright": {
      "command": "npx",
      "args": ["@executeautomation/playwright-mcp-server"]
    }
  }
}
```

3. **重启 Claude Code**
```bash
claude
```

</details>

## 架构设计

```
/vuln-reproduce (入口命令)
        ↓
┌────────────────────────────────┐
│   reproduce-orchestrator       │ ← 主编排器
│   协调整个复现流程              │
└────────────────────────────────┘
        ↓ 调用子智能体
┌─────────────┬─────────────┬─────────────┬─────────────────┐
│ env-builder │data-preparer│vuln-verifier│ browser-verifier│
│  环境搭建   │  数据准备    │ HTTP 验证   │  浏览器验证      │
└─────────────┴─────────────┴─────────────┴─────────────────┘
                                  ↑               ↑
                               curl/jq      Playwright MCP
```

## 漏洞覆盖能力

### Playwright 带来的能力提升

集成 Playwright MCP 后，新增以下漏洞类型的验证能力：

| 漏洞类型 | 无 Playwright | 有 Playwright | 提升 |
|----------|---------------|---------------|------|
| **反射型 XSS** | ⚠️ 仅检测 | ✅ 完整验证 | 检测→确认 |
| **存储型 XSS** | ❌ 无法验证 | ✅ 完整验证 | 0%→90% |
| **DOM XSS** | ❌ 无法验证 | ✅ 完整验证 | 0%→90% |
| **CSRF** | ❌ 无法验证 | ✅ 完整验证 | 0%→80% |
| **点击劫持** | ❌ 无法验证 | ✅ 完整验证 | 0%→95% |
| **OAuth 流程漏洞** | ❌ 无法验证 | ✅ 可验证 | 0%→70% |
| **开放重定向** | ⚠️ 部分 | ✅ 完整验证 | 50%→95% |
| **Session 固定** | ❌ 无法验证 | ✅ 可验证 | 0%→80% |

**整体覆盖率提升: ~60% → ~85%**

### Playwright 验证示例

#### DOM XSS 验证

```
传统方式 (curl):
  curl "http://target/search?q=<script>alert(1)</script>"
  → 只能看到 payload 在响应中，无法确认是否执行 ❌

Playwright 方式:
  1. playwright_navigate → 访问带 payload 的 URL
  2. 监听 dialog 事件 → 捕获 alert 弹窗
  3. playwright_screenshot → 截图留证
  → 确认 JS 代码被执行 ✅
```

#### CSRF 验证

```
传统方式 (curl):
  无法模拟浏览器自动带 Cookie 的行为 ❌

Playwright 方式:
  1. playwright_navigate → 登录受害者账户
  2. playwright_navigate → 访问攻击者恶意页面
  3. 恶意页面自动提交表单 → 带上受害者 Cookie
  4. 验证受害者数据是否被修改 ✅
```

#### 存储型 XSS 验证

```
Phase 1 - 攻击者注入:
  playwright_navigate("/comment")
  playwright_fill("#content", "<script>alert(document.cookie)</script>")
  playwright_click("#submit")

Phase 2 - 受害者触发:
  playwright_navigate("/comments")  # 新会话
  → 捕获 alert 弹窗 = 漏洞确认 ✅
```

### 完整覆盖矩阵

| 状态 | 漏洞类型 |
|------|----------|
| ✅ **HTTP 验证** | IDOR、SQL注入、命令注入、路径遍历、文件上传、批量赋值、认证绕过、信息泄露、SSRF(有回显) |
| ✅ **浏览器验证** | XSS(反射/存储/DOM)、CSRF、点击劫持、OAuth流程、开放重定向、Session固定、前端逻辑 |
| ❌ **暂不支持** | 盲注(需OOB)、WebSocket、时序攻击、反序列化RCE |

## 目录结构

```
.
├── .claude/
│   ├── commands/
│   │   └── vuln-reproduce.md         # 入口命令
│   └── agents/
│       ├── reproduce-orchestrator.md # 主编排器
│       ├── env-builder.md            # 环境搭建
│       ├── data-preparer.md          # 数据准备
│       └── vuln-verifier.md          # 漏洞验证
│
├── config/
│   └── mcp-settings.json             # MCP 配置模板
│
├── setup.sh                          # 一键安装脚本
└── README.md
```

## 使用方法

### 复现漏洞

```bash
# 启动 Claude Code
claude

# 执行漏洞复现
/vuln-reproduce @漏洞报告.md http://target:3000
```

### 输入格式

```bash
# 在线环境
/vuln-reproduce @report.md http://target-host:port

# Docker Compose
/vuln-reproduce @report.md @/path/to/docker-compose.yml

# 项目目录
/vuln-reproduce @report.md @/path/to/project
```

### 漏洞报告格式

```markdown
## 漏洞标题
{标题}

## 漏洞类型
{IDOR/SQLi/XSS/CSRF/命令注入/...}

## 风险等级
{严重/高危/中危/低危}

## 漏洞端点
{HTTP方法} {路径}

## 漏洞描述
{详细描述}

## 攻击路径
{利用步骤}
```

## 判定标准

| 结论 | 条件 |
|------|------|
| ✅ **真实漏洞** | PoC 执行成功，观察到预期攻击效果 |
| ❌ **误报** | PoC 无法执行，或未观察到攻击效果 |
| ⚠️ **休眠漏洞** | 代码存在风险，但当前无法触发 |
| ⏸️ **待验证** | 需要特殊配置才能验证 |

## Playwright MCP 工具

安装后可用的浏览器自动化工具：

| 工具 | 功能 | 漏洞验证场景 |
|------|------|-------------|
| `playwright_navigate` | 导航到 URL | 所有浏览器场景 |
| `playwright_click` | 点击元素 | 表单提交、CSRF |
| `playwright_fill` | 填充表单 | XSS 注入、登录 |
| `playwright_screenshot` | 截图取证 | 证据保存 |
| `playwright_console_logs` | 获取控制台日志 | XSS 调试 |
| `playwright_evaluate` | 执行 JavaScript | DOM 操作验证 |
| `playwright_get_visible_html` | 获取页面 HTML | XSS payload 检查 |

## License

MIT

## 作者

Clouditera Security Team
