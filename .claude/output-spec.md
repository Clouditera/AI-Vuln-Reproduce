# 漏洞复现产出规范

## 目录结构

```
.workspace/
├── reproduced/                          # 所有复现结果的根目录
│   └── {VULN_ID}/                       # 单个漏洞的复现目录
│       ├── verdict.md                   # 复现报告 (必须)
│       ├── poc.py                       # Python PoC 脚本 (首选)
│       ├── poc.sh                       # Shell PoC 脚本 (备选)
│       ├── poc.js                       # JavaScript PoC (Playwright)
│       ├── request.http                 # HTTP 原始请求
│       └── evidence/                    # 证据目录 (必须)
│           ├── 01_login_page.png        # 登录页面
│           ├── 02_login_filled.png      # 填写凭据
│           ├── 03_after_login.png       # 登录成功
│           ├── 04_vuln_page.png         # 漏洞页面
│           ├── 05_payload_input.png     # 注入 Payload
│           ├── 06_after_submit.png      # 提交后
│           ├── 07_poc_effect.png        # PoC 效果 (关键!)
│           ├── 08_final_result.png      # 最终验证
│           └── metadata.json            # 截图元数据
└── temp/                                # 临时工作目录
    └── {session_id}/                    # 按会话隔离
```

## 命名规范

### VULN_ID 格式

```
{漏洞类型}-{模块名}-{日期}
```

**漏洞类型缩写:**

| 类型 | 缩写 | 示例 |
|------|------|------|
| 存储型 XSS | `SXSS` | SXSS-ProductAttr-20260106 |
| 反射型 XSS | `RXSS` | RXSS-Search-20260106 |
| DOM XSS | `DXSS` | DXSS-Comment-20260106 |
| SQL 注入 | `SQLI` | SQLI-Login-20260106 |
| 竞态条件 | `RACE` | RACE-Discount-20260106 |
| IDOR | `IDOR` | IDOR-Order-20260106 |
| CSRF | `CSRF` | CSRF-Profile-20260106 |
| 认证绕过 | `AUTH` | AUTH-Admin-20260106 |
| 文件上传 | `UPLOAD` | UPLOAD-Avatar-20260106 |
| 命令注入 | `CMDI` | CMDI-Export-20260106 |
| 路径遍历 | `PATH` | PATH-Download-20260106 |
| SSRF | `SSRF` | SSRF-Webhook-20260106 |
| XXE | `XXE` | XXE-Import-20260106 |
| 反序列化 | `DESER` | DESER-Session-20260106 |
| 权限提升 | `PRIV` | PRIV-Role-20260106 |
| 信息泄露 | `INFO` | INFO-Debug-20260106 |

**模块名规则:**
- 使用 PascalCase
- 最多 2-3 个单词
- 描述漏洞所在功能模块

**示例:**
```
SXSS-ProductAttribute-20260106
RACE-DiscountCoupon-20260106
SQLI-UserSearch-20260106
IDOR-OrderHistory-20260106
```

### 截图命名规范

```
{序号}_{阶段描述}.png
```

**标准序号:**

| 序号 | 阶段 | 文件名 | 说明 |
|------|------|--------|------|
| 01 | 登录页面 | `01_login_page.png` | 访问登录页 |
| 02 | 填写凭据 | `02_login_filled.png` | 输入用户名密码 |
| 03 | 登录成功 | `03_after_login.png` | 进入系统 |
| 04 | 漏洞页面 | `04_vuln_page.png` | 到达漏洞位置 |
| 05 | 输入 Payload | `05_payload_input.png` | 注入恶意数据 |
| 06 | 提交保存 | `06_after_submit.png` | 提交后状态 |
| 07 | **PoC 效果** | `07_poc_effect.png` | **漏洞触发效果** |
| 08 | 最终验证 | `08_final_result.png` | 最终证据 |

**扩展序号 (特殊场景):**

```
# 多用户场景 (IDOR)
03a_user_a_login.png
03b_user_b_login.png

# 并发场景 (竞态条件)
07a_poc_effect_session_1.png
07b_poc_effect_session_2.png
07c_poc_effect_summary.png

# 多步骤 Payload
05a_payload_step1.png
05b_payload_step2.png
```

## 文件内容规范

### verdict.md (复现报告)

```markdown
# {漏洞名称} - 复现报告

## 研判结论：{CONFIRMED | NOT_REPRODUCED | BLOCKED | DORMANT}

| 项目 | 详情 |
|------|------|
| **VULN_ID** | {VULN_ID} |
| **研判时间** | {YYYY-MM-DD} |
| **目标环境** | {URL} ({系统名称 版本}) |
| **漏洞类型** | {漏洞类型} |
| **风险等级** | {CRITICAL | HIGH | MEDIUM | LOW} |
| **验证方式** | {HTTP 请求 | Playwright | 数据库查询} |

---

## 1. 漏洞概述

{漏洞描述，包含漏洞位置和原理}

**漏洞代码位置：**
- 文件: `{file_path}:{line_number}`

---

## 2. 复现步骤

### 步骤 1: {步骤标题}

{步骤描述}

![{截图描述}](./evidence/01_xxx.png)

---

### 步骤 N: PoC 效果验证

**关键截图 - 漏洞触发成功：**

![PoC效果](./evidence/07_poc_effect.png)

---

## 3. HTTP 攻击证据

### 攻击请求

```http
{HTTP 请求}
```

### curl 命令

```bash
{curl 命令}
```

---

## 4. 验证结果

| 指标 | 预期值 | 实际值 | 结论 |
|------|--------|--------|------|
| ... | ... | ... | ... |

---

## 5. PoC 脚本

**文件**: `./poc.py`

```python
{PoC 代码摘要}
```

**执行方式:**
```bash
{执行命令}
```

---

## 6. 修复建议

{修复建议}

---

**报告生成时间：** {YYYY-MM-DD HH:MM}
**验证工具：** {工具列表}
```

### metadata.json (截图元数据)

```json
{
  "vuln_id": "SXSS-ProductAttribute-20260106",
  "created_at": "2026-01-06T10:30:00Z",
  "environment": {
    "base_url": "http://localhost:8080",
    "tech_stack": "nopCommerce 4.90.0"
  },
  "screenshots": [
    {
      "file": "01_login_page.png",
      "step": 1,
      "description": "登录页面",
      "timestamp": "2026-01-06T10:30:01Z"
    },
    {
      "file": "07_poc_effect.png",
      "step": 7,
      "description": "PoC 执行成功效果",
      "timestamp": "2026-01-06T10:32:15Z",
      "is_key_evidence": true
    }
  ],
  "verdict": "CONFIRMED",
  "poc_files": ["poc.py", "poc.sh"]
}
```

### request.http (HTTP 请求)

```http
### 漏洞触发请求
POST /Admin/ProductAttribute/Edit/1 HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Cookie: .Nop.Customer=xxx; .Nop.Antiforgery=yyy

Name=Color&Description=<script>alert('XSS')</script>&__RequestVerificationToken=zzz
```

### poc.py (Python PoC)

```python
#!/usr/bin/env python3
"""
漏洞 PoC: {VULN_ID}
目标: {目标系统}
类型: {漏洞类型}
作者: AI Security Analyst
日期: {YYYY-MM-DD}
"""

import requests
import sys

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"

def exploit():
    """执行漏洞利用"""
    # PoC 代码
    pass

def verify():
    """验证漏洞是否触发"""
    # 验证代码
    pass

if __name__ == "__main__":
    print(f"[*] Target: {BASE_URL}")
    exploit()
    if verify():
        print("[+] VULNERABILITY CONFIRMED!")
    else:
        print("[-] Exploitation failed")
```

## 判定标准

| 判定结果 | 条件 | 报告要求 |
|----------|------|----------|
| **CONFIRMED** | PoC 成功执行，07_poc_effect.png 清晰展示效果 | 完整报告 + 所有截图 |
| **NOT_REPRODUCED** | PoC 失败，截图显示被拦截或无效 | 报告 + 失败截图 |
| **BLOCKED** | 环境不匹配或缺少必要条件 | 简要报告 + 阻塞原因 |
| **DORMANT** | 代码存在风险但无法触发 | 代码分析报告 |

## 自动化检查

生成报告前，验证以下内容：

```bash
#!/bin/bash
# check_output.sh

VULN_DIR=".workspace/reproduced/$1"

# 必须文件检查
[ -f "$VULN_DIR/verdict.md" ] || echo "ERROR: Missing verdict.md"
[ -d "$VULN_DIR/evidence" ] || echo "ERROR: Missing evidence/"
[ -f "$VULN_DIR/evidence/07_poc_effect.png" ] || echo "ERROR: Missing 07_poc_effect.png"

# 截图完整性检查
for i in 01 02 03 04 05 06 07 08; do
    ls "$VULN_DIR/evidence/${i}_"*.png 2>/dev/null || echo "WARNING: Missing step $i screenshot"
done

# 报告格式检查
grep -q "## 研判结论" "$VULN_DIR/verdict.md" || echo "ERROR: Missing verdict section"
grep -q "07_poc_effect.png" "$VULN_DIR/verdict.md" || echo "ERROR: PoC screenshot not embedded"
```

## 示例输出

```
.workspace/reproduced/
├── SXSS-ProductAttribute-20260106/
│   ├── verdict.md
│   ├── poc.py
│   ├── request.http
│   └── evidence/
│       ├── 01_login_page.png
│       ├── 02_login_filled.png
│       ├── 03_after_login.png
│       ├── 04_vuln_page.png
│       ├── 05_payload_input.png
│       ├── 06_after_submit.png
│       ├── 07_poc_effect.png
│       ├── 08_final_result.png
│       └── metadata.json
│
├── RACE-DiscountCoupon-20260106/
│   ├── verdict.md
│   ├── poc.py
│   ├── request.http
│   └── evidence/
│       ├── 01_login_page.png
│       ├── ...
│       ├── 07a_poc_effect_session_1.png
│       ├── 07b_poc_effect_session_2.png
│       ├── 07c_poc_effect_summary.png
│       └── metadata.json
│
└── IDOR-OrderHistory-20260106/
    ├── verdict.md
    ├── poc.py
    └── evidence/
        ├── 03a_user_a_login.png
        ├── 03b_user_b_login.png
        ├── ...
        └── metadata.json
```
