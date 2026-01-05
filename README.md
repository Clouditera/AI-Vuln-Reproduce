# AI-Vuln-Reproduce

AI 全自动漏洞复现智能体平台 - 基于 Claude Code 的多智能体协作系统

## 项目简介

本项目利用 Claude Code CLI 的智能体能力，实现从漏洞报告到复现验证的端到端自动化。通过多智能体协作，自动完成环境搭建、测试数据准备、PoC 构造和漏洞验证。

## 架构设计

```
/vuln-reproduce (入口命令)
        ↓
┌────────────────────────────────┐
│   reproduce-orchestrator       │ ← 主编排器
│   协调整个复现流程              │
└────────────────────────────────┘
        ↓ 调用三个子智能体
┌─────────────┬─────────────┬─────────────┐
│ env-builder │data-preparer│vuln-verifier│
│  环境搭建   │  数据准备    │  漏洞验证    │
└─────────────┴─────────────┴─────────────┘
```

## 目录结构

```
.
├── .claude/
│   ├── commands/
│   │   └── vuln-reproduce.md    # 入口命令
│   └── agents/
│       ├── reproduce-orchestrator.md  # 编排智能体
│       ├── env-builder.md             # 环境搭建智能体
│       ├── data-preparer.md           # 数据准备智能体
│       └── vuln-verifier.md           # 漏洞验证智能体
│
├── vulnerabilities/             # 漏洞报告库
│   ├── VULN-001-SQL-Injection-UpdateQuery.md
│   ├── VULN-002-SQL-Injection-InsertQuery.md
│   ├── VULN-003-IDOR-UpdateCustomer.md
│   └── ...
│
└── .workspace/                  # 运行时工作空间
    └── reproduced/              # 复现结果
        └── VULN-XXX/
            ├── verdict.md       # 研判报告
            ├── poc.sh           # PoC 脚本
            └── evidence/        # 证据文件
```

## 使用方法

### 前置要求

- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) 已安装
- Docker (用于本地环境搭建)

### 复现漏洞

```bash
# 进入项目目录
cd AI-Vuln-Reproduce

# 启动 Claude Code
claude

# 执行漏洞复现命令
/vuln-reproduce @vulnerabilities/VULN-003-IDOR-UpdateCustomer.md http://target:3000
```

### 输入格式

支持多种环境信息格式：

```bash
# 在线环境
/vuln-reproduce @漏洞报告.md http://target-host:port

# Docker Compose
/vuln-reproduce @漏洞报告.md @/path/to/docker-compose.yml

# 项目目录
/vuln-reproduce @漏洞报告.md @/path/to/project

# GitHub 仓库
/vuln-reproduce @漏洞报告.md https://github.com/user/repo
```

## 核心特性

### 双重验证机制

1. **代码分析**：理解漏洞根因、定位脆弱代码、分析数据流
2. **API 测试**：从攻击者视角，通过 HTTP 接口验证可利用性

### 判定标准

| 结论 | 条件 |
|------|------|
| ✅ 真实漏洞 | PoC 执行成功，观察到预期攻击效果 |
| ❌ 误报 | PoC 无法执行，或未观察到攻击效果 |
| ⚠️ 休眠漏洞 | 代码存在风险，但当前版本无法触发 |
| ⏸️ 待验证 | 需要特殊配置才能验证 |

### 支持的漏洞类型

- IDOR (不安全的直接对象引用)
- SQL 注入
- 命令注入
- 路径遍历
- 文件上传
- 批量赋值
- 认证绕过
- 配置错误
- 信息泄露

## 漏洞报告格式

```markdown
## 漏洞标题
{标题}

## 漏洞类型
{IDOR/SQLi/XSS/SSRF/命令注入/路径遍历/...}

## 风险等级
{严重/高危/中危/低危}

## 漏洞端点
{HTTP方法} {路径}

## 漏洞描述
{详细描述}

## 攻击路径（可选）
{利用步骤}

## 受影响文件（可选）
{代码文件路径}
```

## 局限性

当前版本无法覆盖以下场景：

- 需要 OOB 服务器的盲注类漏洞
- 需要浏览器执行的 DOM XSS、CSRF
- WebSocket/gRPC 等非 HTTP 协议
- 需要精确时序控制的竞态条件
- 反序列化 RCE 等需要二进制分析的漏洞

## License

MIT

## 作者

Clouditera Security Team
