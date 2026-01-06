# AI 漏洞复现智能体配置

## 目录结构

```
.claude/
├── README.md                    # 本文件
├── output-spec.md               # 产出规范
├── agents/                      # 智能体配置
│   ├── reproduce-orchestrator.md   # 复现编排器 (入口)
│   ├── env-builder.md              # 环境搭建器
│   ├── data-preparer.md            # 数据准备器
│   └── vuln-verifier.md            # 漏洞验证器
└── commands/                    # 用户命令
    └── vuln-reproduce.md           # /vuln-reproduce 命令

.workspace/                      # 工作目录 (运行时生成)
└── reproduced/                  # 复现结果
    └── {VULN_ID}/
        ├── verdict.md           # 复现报告
        ├── poc.py               # PoC 脚本
        └── evidence/            # 证据截图
```

## 智能体说明

| 智能体 | 文件 | 职责 |
|--------|------|------|
| **复现编排器** | `reproduce-orchestrator.md` | 协调整个复现流程 |
| **环境搭建器** | `env-builder.md` | 探测环境、识别技术栈 |
| **数据准备器** | `data-preparer.md` | 创建用户、会话、资源 |
| **漏洞验证器** | `vuln-verifier.md` | 编写 PoC、截图、生成报告 |

## 使用方式

```bash
/vuln-reproduce '<漏洞报告路径>' <目标URL>
```

## 产出规范

详见 `output-spec.md`

- **VULN_ID**: `{类型}-{模块}-{日期}` (如 `SXSS-ProductAttr-20260106`)
- **产出文件**: verdict.md, poc.py, evidence/
