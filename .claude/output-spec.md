# 漏洞复现产出规范

## 目录结构

```
.workspace/reproduced/{VULN_ID}/
├── verdict.md                   # 复现报告 (必须)
├── poc.py                       # PoC 脚本 (必须)
└── evidence/                    # 证据截图 (必须)
    ├── 01_login_page.png
    ├── 02_login_filled.png
    ├── 03_after_login.png
    ├── 04_vuln_page.png
    ├── 05_payload_input.png
    ├── 06_after_submit.png
    ├── 07_poc_effect.png        # 关键截图!
    └── 08_final_result.png
```

## VULN_ID 命名规范

```
{漏洞类型}-{模块名}-{日期}
```

**漏洞类型缩写:**

| 类型 | 缩写 | 示例 |
|------|------|------|
| 存储型 XSS | `SXSS` | SXSS-ProductAttr-20260106 |
| 反射型 XSS | `RXSS` | RXSS-Search-20260106 |
| SQL 注入 | `SQLI` | SQLI-Login-20260106 |
| 竞态条件 | `RACE` | RACE-Discount-20260106 |
| IDOR | `IDOR` | IDOR-Order-20260106 |
| CSRF | `CSRF` | CSRF-Profile-20260106 |
| 认证绕过 | `AUTH` | AUTH-Admin-20260106 |
| 文件上传 | `UPLOAD` | UPLOAD-Avatar-20260106 |
| 命令注入 | `CMDI` | CMDI-Export-20260106 |
| 路径遍历 | `PATH` | PATH-Download-20260106 |
| SSRF | `SSRF` | SSRF-Webhook-20260106 |
| 权限提升 | `PRIV` | PRIV-Role-20260106 |

## 截图命名规范

| 序号 | 文件名 | 说明 |
|------|--------|------|
| 01 | `01_login_page.png` | 登录页面 |
| 02 | `02_login_filled.png` | 填写凭据 |
| 03 | `03_after_login.png` | 登录成功 |
| 04 | `04_vuln_page.png` | 漏洞页面 |
| 05 | `05_payload_input.png` | 注入 Payload |
| 06 | `06_after_submit.png` | 提交后 |
| 07 | `07_poc_effect.png` | **PoC 效果 (必须)** |
| 08 | `08_final_result.png` | 最终验证 |

## verdict.md 模板

```markdown
# {漏洞名称} - 复现报告

## 研判结论：{CONFIRMED | NOT_REPRODUCED | BLOCKED}

| 项目 | 详情 |
|------|------|
| **VULN_ID** | {VULN_ID} |
| **研判时间** | {YYYY-MM-DD} |
| **目标环境** | {URL} ({系统名称 版本}) |
| **漏洞类型** | {漏洞类型} |
| **风险等级** | {CRITICAL | HIGH | MEDIUM | LOW} |

---

## 1. 漏洞概述

{漏洞描述}

---

## 2. 复现步骤

### 步骤 1: 登录

![登录页面](./evidence/01_login_page.png)

### 步骤 N: PoC 效果

![PoC效果](./evidence/07_poc_effect.png)

---

## 3. PoC 脚本

**执行方式:**
```bash
python3 poc.py
```

---

## 4. 修复建议

{修复建议}
```

## 判定标准

| 判定 | 条件 |
|------|------|
| **CONFIRMED** | PoC 成功 + 07_poc_effect.png 展示漏洞效果 |
| **NOT_REPRODUCED** | PoC 失败 |
| **BLOCKED** | 环境不匹配或缺少条件 |
