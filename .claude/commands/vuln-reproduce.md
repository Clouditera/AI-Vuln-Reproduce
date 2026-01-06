---
description: AI 全自动漏洞复现，@ 引用漏洞报告文件，提供环境链接或 Docker 配置，自动完成环境搭建、数据准备、PoC 验证
argument-hint: @<漏洞报告.md> <环境地址/Docker配置>
---

# 漏洞复现命令

收到用户输入后，执行全自动漏洞复现流程。

## 使用方式

用户 @ 引用 MD 格式的漏洞报告文件，并提供测试环境信息。

## 输入格式

```
@<漏洞报告文件路径.md> <环境信息>
```

### 环境信息支持以下格式：

1. **在线环境地址**：`http://target-host:port`
2. **Docker Compose 文件**：`@/path/to/docker-compose.yml`
3. **项目目录**：`@/path/to/project`

## 执行流程

### STEP 1: 解析输入

从用户输入中提取：
- 漏洞报告文件路径
- 环境地址或配置

### STEP 2: 读取漏洞报告

使用 Read 工具读取漏洞报告，提取关键信息：
- 漏洞名称、类型、风险等级
- 攻击端点、复现步骤
- 受影响文件

### STEP 3: 环境检测

```bash
curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 {BASE_URL}
```

### STEP 4: 凭据处理 (关键)

**检查顺序：**

1. 漏洞报告中是否包含凭据
2. 尝试系统默认凭据
3. **如果失败，必须询问用户**

**常见默认凭据：**

| 系统 | 用户名 | 密码 |
|------|--------|------|
| nopCommerce | admin@yourStore.com | admin |
| WordPress | admin | admin |
| Magento | admin | admin123 |
| Django | admin | admin |

### STEP 5: 调用验证智能体

**优先尝试编排智能体：**

```
Task(subagent_type="reproduce-orchestrator", prompt="...")
```

**如果编排失败，降级直接调用：**

```
Task(subagent_type="vuln-verifier", prompt="...")
```

### STEP 6: 生成报告

报告保存位置：`.workspace/reproduced/{VULN_ID}/verdict.md`

**报告必须包含：**
1. 研判结论
2. 复现步骤（每步配截图）
3. HTTP 攻击证据
4. PoC 脚本
5. 修复建议

## 降级策略

```
reproduce-orchestrator 失败 (413/超时)
    ↓
直接调用 vuln-verifier
    ↓
如果仍失败，手动执行关键步骤：
    1. 环境检测 (curl)
    2. 登录验证 (Playwright)
    3. 漏洞注入 (Playwright)
    4. 结果验证 (curl)
    5. 生成报告
```

## 错误处理

| 错误 | 处理方式 |
|------|----------|
| 环境不可达 | 报告错误，终止 |
| 登录失败 | 询问用户凭据 |
| 智能体超时 | 降级处理 |
| 413 错误 | 减少 prompt 长度，重试 |

## 调用示例

```
/vuln-reproduce @/path/to/vuln-report.md http://localhost:8080
```

## 输出格式

完成后输出：

```markdown
## 漏洞复现完成

### 研判结论：{CONFIRMED/NOT_REPRODUCED/DORMANT}

| 项目 | 详情 |
|------|------|
| 漏洞名称 | {name} |
| 目标环境 | {url} |
| 验证结果 | {result} |

### 报告位置

- 完整报告：`.workspace/reproduced/{ID}/verdict.md`
- 证据截图：`.workspace/reproduced/{ID}/evidence/`
- PoC 脚本：`.workspace/reproduced/{ID}/poc.sh`

### 关键截图

[嵌入 2-3 张关键截图]
```
