# Agent 输出约束规范

## 核心原则

**所有 Agent 必须遵循：输出到文件，返回摘要**

## 输出约束

### 强制规则

1. **返回内容 < 500 字符**
   - Agent 返回给调用者的内容必须精简
   - 详细内容写入文件，只返回摘要

2. **结构化返回格式**
   ```yaml
   status: success | failed | partial
   summary: "一句话描述结果"
   output_files:
     - path/to/report.md
     - path/to/poc.py
   next_action: null | retry | escalate
   ```

3. **禁止返回的内容**
   - 完整的代码内容（写入文件）
   - 完整的 HTTP 请求/响应（写入文件）
   - 完整的截图路径列表（写入文件）
   - 冗长的分析过程（写入文件）

### 返回示例

```yaml
# 正确 ✓
status: success
summary: "VUL-001 XSS 漏洞复现成功，PoC 已验证"
output_files:
  - .workspace/reproduced/codimd/individual_reports/VUL-001_xss.md
  - .workspace/reproduced/codimd/poc/VUL-001_poc.py

# 错误 ✗
status: success
summary: "VUL-001 XSS 漏洞复现成功..."
http_request: "POST /api/xxx HTTP/1.1\nHost:..."  # 不要包含这些
http_response: "HTTP/1.1 200 OK\n..."             # 不要包含这些
full_report: "# VUL-001 漏洞报告\n..."            # 不要包含这些
```

## 进度持久化

### 状态文件

每个复现任务必须维护状态文件：

```
.workspace/reproduced/{project}/
├── state.json          # 进度状态
├── verdict.md          # 汇总报告
└── individual_reports/ # 独立报告
```

### state.json 格式

```json
{
  "project": "codimd",
  "started_at": "2026-01-08T10:00:00Z",
  "updated_at": "2026-01-08T10:30:00Z",
  "total_vulns": 10,
  "completed": 5,
  "status": "in_progress",
  "vulns": {
    "VUL-001": {"status": "CONFIRMED", "mode": "L1", "report": "...path..."},
    "VUL-002": {"status": "CONFIRMED", "mode": "L2", "report": "...path..."},
    "VUL-003": {"status": "in_progress", "mode": "L3", "report": null},
    "VUL-004": {"status": "pending", "mode": null, "report": null}
  }
}
```

### 恢复机制

Agent 启动时检查状态文件：

```python
def resume_or_start(project_dir):
    state_file = f"{project_dir}/state.json"

    if os.path.exists(state_file):
        state = load_json(state_file)
        # 跳过已完成的，继续未完成的
        pending_vulns = [v for v in state['vulns'] if state['vulns'][v]['status'] in ['pending', 'in_progress']]
        return pending_vulns
    else:
        # 新任务
        return all_vulns
```

## 并行控制

### 限制并发数

```yaml
max_concurrent_agents: 3  # 最多同时 3 个 Agent

parallel_groups:
  - [VUL-001, VUL-002, VUL-003]  # 第一批
  - [VUL-004, VUL-005, VUL-006]  # 等第一批完成再启动
```

### 批次执行

```
批次 1: VUL-001, VUL-002, VUL-003 (并行)
    ↓ 全部完成
批次 2: VUL-004, VUL-005, VUL-006 (并行)
    ↓ 全部完成
批次 3: ...
```

## 上下文管理

### Agent 调用模板

```markdown
执行漏洞复现，完成后：
1. 将报告写入 {output_path}
2. 只返回以下格式的摘要（不超过 300 字符）：

---
status: {success|failed}
summary: {一句话结果}
report: {报告路径}
---

禁止在返回中包含：
- 完整报告内容
- HTTP 请求/响应原文
- 代码片段
```

### 主 Orchestrator 处理

```python
# 收到 Agent 返回后
def handle_agent_result(result):
    # 只保留摘要信息
    summary = {
        'vuln_id': result['vuln_id'],
        'status': result['status'],
        'report_path': result['report']
    }

    # 更新状态文件
    update_state_file(summary)

    # 不要将完整结果放入上下文
    return f"✓ {result['vuln_id']}: {result['status']}"
```
