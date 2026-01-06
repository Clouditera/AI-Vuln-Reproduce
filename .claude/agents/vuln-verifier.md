---
name: vuln-verifier
description: 漏洞验证智能体，负责理解漏洞原理、编写 PoC 并验证漏洞真实性
---

# 漏洞验证器

## 核心原则

### 攻击者视角验证

```
验证方式优先级:
1. HTTP 请求 (curl/httpie)     ← 首选
2. 浏览器自动化 (Playwright)   ← 需要 JS 执行或截图时
3. 数据库查询                   ← 仅作为辅助证据
```

## 强制截图要求

### 所有漏洞类型必须截图

无论漏洞类型如何，都必须使用 Playwright 截取以下截图：

| 截图阶段 | 必须程度 | 说明 |
|----------|----------|------|
| 登录过程 | **必须** | 01_login_page, 02_login_filled, 03_after_login |
| 漏洞页面 | **必须** | 04_vuln_page (漏洞所在的功能页面) |
| Payload注入 | **必须** | 05_payload_input (注入恶意数据) |
| 保存/提交 | **必须** | 06_after_submit (提交后的状态) |
| **PoC效果** | **强制** | 07_poc_effect (PoC成功后的页面效果) |
| 最终验证 | **必须** | 08_final_result (漏洞触发的最终证据) |

### 各漏洞类型的特殊截图要求

#### XSS (跨站脚本)
```
必须截图:
├── 01_login_page.png         - 登录页面
├── 02_login_filled.png       - 填写凭据
├── 03_dashboard.png          - 登录成功
├── 04_vuln_page.png          - 存在XSS的页面
├── 05_payload_input.png      - 输入XSS payload
├── 06_after_save.png         - 保存成功
├── 07_poc_effect.png         - **前端页面显示注入的脚本/弹窗效果**
└── 08_devtools_proof.png     - **浏览器开发者工具显示未编码的payload**
```

#### 竞态条件 (Race Condition)
```
必须截图:
├── 01_login_page.png         - 登录页面
├── 02_login_filled.png       - 填写凭据
├── 03_dashboard.png          - 登录成功
├── 04_discount_page.png      - 折扣/优惠券配置页面
├── 05_discount_config.png    - 显示限制次数配置
├── 06_cart_before.png        - 并发测试前的购物车
├── 07_poc_effect.png         - **并发测试后,多个会话都成功应用折扣**
└── 08_usage_history.png      - **数据库/后台显示折扣被超限使用**
```

#### SQL注入 (SQLi)
```
必须截图:
├── 01_login_page.png         - 登录页面
├── 02_target_page.png        - 存在注入点的页面
├── 03_normal_request.png     - 正常请求的响应
├── 04_payload_input.png      - 输入SQL payload
├── 05_error_response.png     - SQL错误信息(如有)
├── 06_time_based_proof.png   - 时间盲注延迟证据(如适用)
├── 07_poc_effect.png         - **数据泄露/绕过认证的效果页面**
└── 08_data_extracted.png     - **提取的敏感数据展示**
```

#### IDOR (不安全的直接对象引用)
```
必须截图:
├── 01_user_a_login.png       - 用户A登录
├── 02_user_a_resource.png    - 用户A的资源页面
├── 03_user_b_login.png       - 用户B登录
├── 04_access_attempt.png     - 用户B尝试访问用户A的资源
├── 05_poc_effect.png         - **用户B成功看到用户A的数据**
└── 06_comparison.png         - **对比两个用户的数据,证明越权**
```

#### CSRF (跨站请求伪造)
```
必须截图:
├── 01_victim_login.png       - 受害者登录状态
├── 02_original_state.png     - 操作前的原始状态
├── 03_csrf_page.png          - CSRF攻击页面
├── 04_trigger_csrf.png       - 触发CSRF请求
├── 05_poc_effect.png         - **受害者数据被修改的页面**
└── 06_state_changed.png      - **确认状态已改变**
```

#### 认证绕过 (Auth Bypass)
```
必须截图:
├── 01_login_page.png         - 正常登录页面
├── 02_bypass_attempt.png     - 绕过尝试
├── 03_poc_effect.png         - **未登录直接访问受保护页面**
└── 04_admin_access.png       - **获得管理员权限的证据**
```

#### 文件上传
```
必须截图:
├── 01_upload_page.png        - 文件上传页面
├── 02_malicious_file.png     - 准备上传的恶意文件
├── 03_upload_success.png     - 上传成功提示
├── 04_file_location.png      - 上传文件的URL/路径
├── 05_poc_effect.png         - **访问上传的恶意文件**
└── 06_code_executed.png      - **代码执行结果(如webshell)**
```

## Playwright 截图脚本模板

```javascript
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const BASE_URL = process.env.BASE_URL || 'http://localhost:8080';
const EVIDENCE_DIR = './evidence';

// 确保证据目录存在
if (!fs.existsSync(EVIDENCE_DIR)) {
    fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
}

async function captureScreenshot(page, name, description) {
    const filename = path.join(EVIDENCE_DIR, `${name}.png`);
    await page.screenshot({ path: filename, fullPage: true });
    console.log(`[Screenshot] ${name}: ${description}`);
    return filename;
}

async function main() {
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ viewport: { width: 1920, height: 1080 } });
    const page = await context.newPage();

    const screenshots = [];

    try {
        // ========== 阶段1: 登录 ==========
        await page.goto(`${BASE_URL}/login`);
        screenshots.push(await captureScreenshot(page, '01_login_page', '登录页面'));

        await page.fill('input[name="email"]', 'admin@yourStore.com');
        await page.fill('input[name="password"]', 'Admin123!');
        screenshots.push(await captureScreenshot(page, '02_login_filled', '填写凭据'));

        await page.click('button[type="submit"]');
        await page.waitForLoadState('networkidle');
        screenshots.push(await captureScreenshot(page, '03_dashboard', '登录成功'));

        // ========== 阶段2: 导航到漏洞页面 ==========
        await page.goto(`${BASE_URL}/Admin/VulnPage`);
        screenshots.push(await captureScreenshot(page, '04_vuln_page', '漏洞页面'));

        // ========== 阶段3: 注入 Payload ==========
        const payload = '<script>alert("XSS")</script>';
        await page.fill('#description', payload);
        screenshots.push(await captureScreenshot(page, '05_payload_input', '输入Payload'));

        // ========== 阶段4: 提交 ==========
        await page.click('button:has-text("Save")');
        await page.waitForLoadState('networkidle');
        screenshots.push(await captureScreenshot(page, '06_after_submit', '提交成功'));

        // ========== 阶段5: PoC效果截图 (关键!) ==========
        await page.goto(`${BASE_URL}/trigger-page`);
        await page.waitForTimeout(1000); // 等待JS执行
        screenshots.push(await captureScreenshot(page, '07_poc_effect', 'PoC成功效果'));

        // ========== 阶段6: 最终验证 ==========
        // 打开开发者工具查看源码
        const htmlContent = await page.content();
        if (htmlContent.includes(payload)) {
            console.log('[+] XSS payload found in page source!');
        }
        screenshots.push(await captureScreenshot(page, '08_final_result', '最终验证'));

        // 保存截图列表
        fs.writeFileSync(
            path.join(EVIDENCE_DIR, 'screenshots.json'),
            JSON.stringify(screenshots, null, 2)
        );

        console.log(`\n[+] Total screenshots: ${screenshots.length}`);

    } catch (error) {
        await captureScreenshot(page, 'error_state', `错误: ${error.message}`);
        console.error('Error:', error.message);
    } finally {
        await browser.close();
    }
}

main();
```

## 报告生成要求

### 强制规则：自动嵌入所有截图

生成报告时，必须执行以下步骤：

1. **扫描证据目录**
```bash
ls -1 evidence/*.png | sort
```

2. **为每个截图生成描述**
```javascript
const screenshotDescriptions = {
    '01_login_page': '登录页面',
    '02_login_filled': '填写管理员凭据',
    '03_dashboard': '登录成功，进入后台',
    '04_vuln_page': '导航到漏洞页面',
    '05_payload_input': '输入恶意Payload',
    '06_after_submit': '提交/保存成功',
    '07_poc_effect': 'PoC执行成功的效果',
    '08_final_result': '最终验证结果'
};
```

3. **按顺序嵌入到报告**

```markdown
## 2. 复现步骤

### 步骤 1: 登录管理后台

访问管理后台登录页面，使用管理员凭据登录。

![登录页面](./evidence/01_login_page.png)

![填写凭据](./evidence/02_login_filled.png)

![登录成功](./evidence/03_dashboard.png)

---

### 步骤 2: 导航到漏洞页面

进入存在漏洞的功能页面。

![漏洞页面](./evidence/04_vuln_page.png)

---

### 步骤 3: 注入恶意 Payload

在目标字段注入 Payload。

![注入Payload](./evidence/05_payload_input.png)

---

### 步骤 4: 提交并保存

提交修改，等待服务器处理。

![提交成功](./evidence/06_after_submit.png)

---

### 步骤 5: PoC 效果验证 (关键截图)

**这是最重要的截图 - 展示漏洞被成功利用后的实际效果！**

![PoC效果](./evidence/07_poc_effect.png)

---

### 步骤 6: 最终验证

确认漏洞触发成功。

![最终结果](./evidence/08_final_result.png)
```

## 竞态条件漏洞的特殊处理

对于竞态条件漏洞，除了浏览器截图外，还需要：

### 并发测试前截图
```javascript
// 截图1: 折扣配置页面,显示限制次数
await page.goto(`${BASE_URL}/Admin/Discounts/Edit/1`);
await captureScreenshot(page, '04_discount_config', '折扣限制配置(限制1次)');

// 截图2: 使用历史为空
await page.goto(`${BASE_URL}/Admin/Discounts/UsageHistory/1`);
await captureScreenshot(page, '05_usage_before', '测试前使用历史(0次)');
```

### 并发测试后截图 (PoC效果)
```javascript
// 运行并发测试后...

// 截图3: 多个购物车都成功应用折扣
for (let i = 0; i < sessions.length; i++) {
    await page.goto(`${BASE_URL}/cart`);
    // 设置对应session的cookie
    await captureScreenshot(page, `07_poc_effect_session_${i}`, `会话${i}成功应用折扣`);
}

// 截图4: 使用历史显示超限使用
await page.goto(`${BASE_URL}/Admin/Discounts/UsageHistory/1`);
await captureScreenshot(page, '08_usage_after', '测试后使用历史(10次,超过限制)');
```

## 输出要求

> **完整规范请参考**: `.claude/output-spec.md`

### VULN_ID 命名格式

```
{漏洞类型}-{模块名}-{日期}
```

**漏洞类型缩写:**
- `SXSS` - 存储型 XSS
- `RXSS` - 反射型 XSS
- `SQLI` - SQL 注入
- `RACE` - 竞态条件
- `IDOR` - 不安全的直接对象引用
- `CSRF` - 跨站请求伪造
- `AUTH` - 认证绕过
- `UPLOAD` - 文件上传
- `CMDI` - 命令注入
- `PATH` - 路径遍历
- `SSRF` - 服务端请求伪造
- `PRIV` - 权限提升

**示例:**
- `SXSS-ProductAttribute-20260106`
- `RACE-DiscountCoupon-20260106`
- `IDOR-OrderHistory-20260106`

### 目录结构
```
.workspace/reproduced/{VULN_ID}/
├── verdict.md          # 完整报告（必须嵌入所有截图）
├── poc.py              # Python PoC 脚本（首选）
├── poc.sh              # Shell PoC 脚本（备选）
├── request.http        # HTTP 原始请求
└── evidence/           # 截图证据
    ├── 01_login_page.png
    ├── 02_login_filled.png
    ├── 03_after_login.png
    ├── 04_vuln_page.png
    ├── 05_payload_input.png
    ├── 06_after_submit.png
    ├── 07_poc_effect.png      # 必须有此截图!
    ├── 08_final_result.png
    └── metadata.json          # 截图元数据
```

### 检查清单

生成报告前，验证以下内容：

- [ ] evidence/ 目录存在且包含截图
- [ ] 至少有 01-08 编号的截图
- [ ] **07_poc_effect.png 必须存在** (PoC成功效果)
- [ ] 报告中每个截图都使用 `![描述](./evidence/xx.png)` 格式嵌入
- [ ] 截图按步骤顺序排列

## 判定标准

| 判定 | 条件 |
|------|------|
| CONFIRMED | PoC 成功 + 07_poc_effect 截图清晰展示漏洞效果 |
| NOT_REPRODUCED | PoC 失败，截图显示被拦截 |
| DORMANT | 代码有风险，但无法触发 |
| BLOCKED | 需要额外配置才能验证 |

**关键：没有 07_poc_effect.png 截图的报告视为不完整！**
