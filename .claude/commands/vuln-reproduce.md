---
description: AI 全自动漏洞复现，根据漏洞报告生成独立复现报告
argument-hint: @<漏洞报告.md> <环境地址|docker-compose.yml> [代码路径]
---

# 漏洞复现命令

## 核心目标

**根据漏洞报告，为每个漏洞生成独立的复现报告**

## 核心原则

- **以漏洞报告为准**：漏洞类型、复现方法均从报告提取
- **智能选择复现模式**：根据漏洞特征自动选择最佳验证方式
- **每个漏洞独立报告**：完整步骤 + 证据 + PoC
- **上下文节约**：详细内容写文件，只返回摘要
- **支持恢复**：中断后可继续未完成的漏洞
- **批次执行**：每批最多 3 个漏洞并行

---

## 上下文管理（关键）

### 输出约束

```yaml
子 Agent 返回格式（必须 < 300 字符）:
  status: success | failed
  vuln_id: "VUL-001"
  summary: "XSS 漏洞复现成功"
  report: ".workspace/.../report.md"

禁止返回:
  - 完整报告内容
  - HTTP 请求/响应
  - 代码片段
```

### 恢复机制

检查 `state.json` 跳过已完成：

```bash
# 继续上次任务
/vuln-reproduce --resume

# 重新开始
/vuln-reproduce @report.md http://target
```

---

## 使用方式

```bash
# 基本用法
/vuln-reproduce @<漏洞报告.md> <环境地址>

# 带 Docker 环境
/vuln-reproduce @<漏洞报告.md> <docker-compose.yml>

# 带源码路径（用于 Mock 模式）
/vuln-reproduce @<漏洞报告.md> <环境地址> <代码路径>
```

### 示例

```bash
/vuln-reproduce @/path/to/audit-report.md http://localhost:8080
/vuln-reproduce @/path/to/audit-report.md ./docker-compose.yml
/vuln-reproduce @/path/to/audit-report.md http://localhost:8080 ./src
```

---

## 三层复现模式

AI 根据漏洞报告自动选择最适合的复现模式：

| 层级 | 模式 | 适用场景 | 判断条件 |
|------|------|---------|---------|
| **L1** | Playwright 黑盒 | 简单漏洞 | 步骤简单 + 页面操作为主 + 无复杂前提 |
| **L2** | API 接口复现 | 有 API 的漏洞 | 涉及 API 调用 / 有明确接口路径 |
| **L3** | Mock 代码模块 | 复杂漏洞 | 需特定权限/复杂前提 + 有源码 |

### 模式选择流程

```
分析漏洞报告
    ↓
识别漏洞特征（步骤复杂度、API 接口、前提条件）
    ↓
选择初始模式
    ↓
执行失败？→ 自动降级到下一模式
    ↓
生成报告
```

### 模式降级规则

- L1 失败 → 尝试 L2（如果有 API）
- L2 失败 → 尝试 L3（如果有源码）
- L3 失败 → 记录失败原因，标记 NOT_REPRODUCED

---

## L1: Playwright 黑盒模式

### 执行策略

```
执行步骤 → 卡住？→ 抓 DOM 分析 → 找到目标？→ 继续执行
                                    ↓ 没找到
                          探索性点击（最多5次）→ 再分析
                                    ↓ 仍失败
                          记录 + 截图 + 继续后续步骤
```

### 卡住判断

| 情况 | 判断条件 |
|------|---------|
| 找不到元素 | selector 匹配失败 |
| 点击无效 | 点击后页面没变化 |
| 预期外页面 | 出现报错页、登录页等 |
| 执行超时 | 操作超过设定时间 |

### DOM 探索策略

1. **抓取当前页面 DOM 结构**
2. **AI 分析 DOM**，匹配漏洞步骤中的关键词
3. **找不到？** → 探索性点击菜单/导航类元素
4. **探索限制**：最多 5 次，优先菜单/导航/按钮

---

## L2: API 接口复现模式

### 执行策略

1. **从漏洞报告提取 API 信息**
2. **构造请求并发送**
3. **验证响应是否符合漏洞预期**
4. **成功后尝试 Playwright 截图取证**
5. **截图失败？** → 用 API 返回结果作为证据

### 证据要求

- API 请求/响应完整记录
- 尽量获取页面截图
- 实在无法截图时，API 响应也可作为证据

---

## L3: Mock 代码模块模式

### 执行策略

1. **获取源码**
   - Docker 环境：从容器中提取
   - 环境链接：使用用户提供的代码路径
2. **分析漏洞模块**：定位漏洞所在的代码模块
3. **构造测试环境**：mock 相关依赖
4. **执行验证**：直接调用漏洞代码

### 重要标记

Mock 复现成功时，报告必须注明：

> **验证方式**: Mock 单独代码测试
> **注意**: 可能缺失全局性数据校验，需完整真实环境验证

---

## 输入处理

### 必需输入

- 漏洞报告（md 文档，包含漏洞描述 + PoC）
- 环境地址 或 docker-compose.yml

### 可选输入

- 账号密码（管理员/普通用户）
- 源码路径（L3 模式需要）

### 缺失信息处理

AI 分析漏洞报告后，如果发现缺失关键信息，会主动询问用户：

```
缺失信息检查：
  - 需要管理员权限但未提供凭据？→ 询问用户
  - L3 模式需要源码但未提供？→ 询问用户
  - 需要特定测试数据？→ 询问用户
```

---

## 执行流程

### STEP 1: 检查恢复点

```python
state_file = ".workspace/reproduced/{project}/state.json"
if exists(state_file):
    # 恢复模式：跳过已完成的漏洞
    pending_vulns = load_pending_from_state()
else:
    # 新任务：解析漏洞报告
    pending_vulns = parse_vuln_report()
```

### STEP 2: 环境检测

```bash
curl -s -o /dev/null -w "%{http_code}" {BASE_URL}
```

### STEP 3: 输入完整性检查

检查是否缺失关键信息，缺失则询问用户。

### STEP 4: 批次执行（关键优化）

```yaml
批次大小: 3
执行策略:
  1. 将漏洞分成批次
  2. 每批最多 3 个漏洞并行执行
  3. 等待当前批次全部完成
  4. 更新 state.json
  5. 执行下一批次
```

```
批次 1: [VUL-001, VUL-002, VUL-003] → 并行执行
        ↓ 等待完成，更新状态
批次 2: [VUL-004, VUL-005, VUL-006] → 并行执行
        ↓ 等待完成，更新状态
批次 N: ...
```

**每个子 Agent 完成后只返回摘要**：
```
✓ VUL-001: CONFIRMED (L1) → report.md
✓ VUL-002: CONFIRMED (L2) → report.md
✗ VUL-003: NOT_REPRODUCED → report.md
```

### STEP 5: 生成汇总

汇总到 `verdict.md`

---

## 输出目录

```
.workspace/reproduced/{项目名}/
├── verdict.md                  # 汇总报告
├── individual_reports/         # 独立报告
│   └── {VULN_ID}_{名称}.md
├── poc/                        # PoC 脚本
│   └── {VULN_ID}_poc.py
└── evidence/                   # 证据
    └── {VULN_ID}/
        ├── screenshots/
        └── http/
```

---

## 单个报告要求

| 章节 | 内容 | 必须 |
|------|------|------|
| 基本信息 | 从报告提取 | 是 |
| 漏洞描述 | 从报告提取 | 是 |
| **验证模式** | L1/L2/L3 及选择原因 | 是 |
| 复现步骤 | 按报告 + 截图 | 是 |
| HTTP证据 | 请求 + 响应 | 是 |
| PoC脚本 | 可运行 | 是 |
| 修复建议 | 从报告提取 | 是 |
| **注意事项** | L3 模式的局限性说明 | L3 必须 |

---

## 判定标准

| 结果 | 条件 |
|------|------|
| **CONFIRMED** | 按报告步骤复现成功 |
| **CONFIRMED_MOCK** | Mock 模式复现成功（需注明局限性） |
| **NOT_REPRODUCED** | 所有模式均无法复现 |
| **PARTIAL** | 部分复现成功 |

---

## 输出示例

```markdown
## 漏洞复现完成

| 漏洞ID | 名称 | 等级 | 模式 | 结果 | 报告 |
|--------|------|------|------|------|------|
| VUL-001 | xxx | High | L1 | CONFIRMED | [查看](./individual_reports/...) |
| VUL-002 | xxx | Medium | L2 | CONFIRMED | [查看](./individual_reports/...) |
| VUL-003 | xxx | High | L3 | CONFIRMED_MOCK | [查看](./individual_reports/...) |
| VUL-004 | xxx | Low | - | NOT_REPRODUCED | [查看](./individual_reports/...) |
```
