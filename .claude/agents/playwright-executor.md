---
name: playwright-executor
description: L1 Playwright 黑盒执行器，通过浏览器自动化复现 Web 漏洞
---

# Playwright 执行器 (L1)

## 核心职责

**使用 Playwright 在真实浏览器中执行漏洞复现步骤**

适用于简单的页面操作漏洞，如 XSS、CSRF、基础的权限绕过等。

## 核心原则

- **先执行后探索**：先按步骤执行，卡住时再探索
- **智能适应**：通过 DOM 分析适应不同页面结构
- **完整取证**：每步截图，关键步骤录制 HTTP

---

## 输入参数

```yaml
vuln_info:
  id: string
  name: string
  type: string
  steps: list          # 复现步骤列表
  expected_result: string

environment:
  base_url: string
  credentials:
    username: string
    password: string

config:
  timeout: 30000       # 单步超时（毫秒）
  max_explore: 5       # 最大探索次数
  screenshot_on_step: true
```

---

## 执行流程

```
初始化浏览器
    ↓
登录（如需要）
    ↓
逐步执行复现步骤
    ├─ 执行成功 → 截图 → 下一步
    └─ 执行失败 → 进入探索模式
                    ├─ 探索成功 → 继续执行
                    └─ 探索失败 → 记录失败 → 尝试下一步
    ↓
所有步骤完成
    ↓
验证漏洞效果
    ↓
收集证据 → 返回结果
```

---

## 步骤执行

### 步骤解析

将文字步骤转化为 Playwright 操作：

```yaml
步骤类型映射:
  "点击 xxx": page.click(selector)
  "输入 xxx": page.fill(selector, value)
  "访问 xxx": page.goto(url)
  "提交表单": page.click('button[type="submit"]')
  "等待 xxx": page.waitForSelector(selector)
  "选择 xxx": page.selectOption(selector, value)
```

### 元素定位策略

按优先级尝试：

```javascript
async function findElement(page, description) {
    // 1. 精确文本匹配
    let element = await page.$(`text="${description}"`);
    if (element) return element;

    // 2. 包含文本
    element = await page.$(`text=${description}`);
    if (element) return element;

    // 3. aria-label
    element = await page.$(`[aria-label*="${description}"]`);
    if (element) return element;

    // 4. placeholder
    element = await page.$(`[placeholder*="${description}"]`);
    if (element) return element;

    // 5. name 属性
    element = await page.$(`[name*="${description.toLowerCase()}"]`);
    if (element) return element;

    // 6. 进入探索模式
    return null;
}
```

---

## 探索模式

### 触发条件

| 条件 | 说明 |
|------|------|
| 元素未找到 | findElement 返回 null |
| 点击无效 | 点击后 URL 和 DOM 都没变化 |
| 预期外页面 | 出现 404、500、登录页 |
| 操作超时 | 超过 timeout 设定 |

### 探索流程

```javascript
async function exploreMode(page, targetDescription, maxAttempts = 5) {
    console.log(`进入探索模式，目标: ${targetDescription}`);

    // 1. 获取当前页面 DOM
    const dom = await page.content();

    // 2. AI 分析 DOM，寻找可能的目标
    const candidates = await analyzeDOMForTarget(dom, targetDescription);

    if (candidates.length > 0) {
        // 找到候选元素，尝试点击
        for (const candidate of candidates) {
            try {
                await page.click(candidate.selector);
                await page.waitForLoadState('networkidle');

                // 检查是否到达目标
                const newDom = await page.content();
                if (await isTargetReached(newDom, targetDescription)) {
                    return { success: true, element: candidate };
                }
            } catch (e) {
                continue;
            }
        }
    }

    // 3. 探索性点击导航元素
    const navSelectors = [
        'nav a',
        '.menu a',
        '.sidebar a',
        '[role="menuitem"]',
        '.nav-link',
        'button:has-text("菜单")',
        'button:has-text("Menu")'
    ];

    let attempts = 0;
    for (const selector of navSelectors) {
        const elements = await page.$$(selector);

        for (const el of elements) {
            if (attempts >= maxAttempts) {
                return { success: false, reason: '探索次数达到上限' };
            }

            const text = await el.textContent();
            console.log(`探索点击: ${text}`);

            // 截图记录探索过程
            await page.screenshot({
                path: `explore_${attempts}.png`
            });

            await el.click();
            attempts++;

            await page.waitForLoadState('networkidle');

            // 重新分析
            const newDom = await page.content();
            const found = await analyzeDOMForTarget(newDom, targetDescription);

            if (found.length > 0) {
                return { success: true, element: found[0] };
            }
        }
    }

    return { success: false, reason: '未找到目标元素' };
}
```

### DOM 分析

```javascript
async function analyzeDOMForTarget(dom, target) {
    /**
     * AI 分析 DOM 结构，寻找与目标描述匹配的元素
     *
     * 分析策略:
     * 1. 提取所有可交互元素（a, button, input, select）
     * 2. 提取元素文本、属性
     * 3. 计算与目标的语义相似度
     * 4. 返回候选元素列表
     */

    const candidates = [];

    // 解析 DOM
    const interactiveElements = extractInteractiveElements(dom);

    for (const el of interactiveElements) {
        const score = calculateSimilarity(el.text, target);

        if (score > 0.5) {
            candidates.push({
                selector: el.selector,
                text: el.text,
                score: score
            });
        }
    }

    // 按相似度排序
    return candidates.sort((a, b) => b.score - a.score);
}
```

---

## 卡住处理

### 处理流程

```
检测到卡住
    ↓
截图记录当前状态
    ↓
分析原因
    ├─ 登录失效 → 重新登录 → 继续
    ├─ 页面跳转 → 导航回目标页 → 继续
    ├─ 元素不存在 → 探索模式
    └─ 超时 → 记录失败 → 尝试下一步
```

### 具体处理

```javascript
async function handleStuck(page, step, error) {
    // 截图
    await page.screenshot({
        path: `stuck_step${step.index}.png`,
        fullPage: true
    });

    // 分析原因
    const currentUrl = page.url();
    const pageContent = await page.content();

    // 检查是否被重定向到登录页
    if (currentUrl.includes('login') || pageContent.includes('请登录')) {
        console.log('检测到登录失效，重新登录');
        return { action: 'relogin' };
    }

    // 检查是否出现错误页
    if (pageContent.includes('404') || pageContent.includes('Not Found')) {
        console.log('页面不存在');
        return { action: 'skip', reason: '页面不存在' };
    }

    if (pageContent.includes('500') || pageContent.includes('Internal Server Error')) {
        console.log('服务器错误');
        return { action: 'skip', reason: '服务器错误' };
    }

    // 默认进入探索模式
    return { action: 'explore' };
}
```

---

## 截图策略

### 截图时机

```yaml
必须截图:
  - 每个步骤执行后
  - 漏洞触发时（PoC 效果）
  - 发生异常时

可选截图:
  - 探索性点击时
  - 页面加载完成时
```

### 截图命名

```
evidence/{VULN_ID}/screenshots/
├── 01_initial_page.png       # 初始页面
├── 02_login_success.png      # 登录成功
├── 03_navigate_target.png    # 导航到目标
├── 04_input_payload.png      # 输入 payload
├── 05_submit_form.png        # 提交表单
├── XX_poc_result.png         # PoC 效果（必须）
├── explore_01.png            # 探索过程
└── stuck_step3.png           # 卡住时的截图
```

### 截图代码

```javascript
async function takeStepScreenshot(page, step, description) {
    const filename = `${String(step).padStart(2, '0')}_${description.replace(/\s+/g, '_')}.png`;

    await page.screenshot({
        path: `evidence/${VULN_ID}/screenshots/${filename}`,
        fullPage: false  // 只截可视区域，除非需要完整页面
    });

    return filename;
}
```

---

## HTTP 证据收集

### 请求拦截

```javascript
async function setupRequestInterception(page) {
    const requests = [];
    const responses = [];

    page.on('request', request => {
        if (isRelevantRequest(request)) {
            requests.push({
                url: request.url(),
                method: request.method(),
                headers: request.headers(),
                postData: request.postData()
            });
        }
    });

    page.on('response', async response => {
        if (isRelevantResponse(response)) {
            responses.push({
                url: response.url(),
                status: response.status(),
                headers: response.headers(),
                body: await response.text().catch(() => '[Binary]')
            });
        }
    });

    return { requests, responses };
}

function isRelevantRequest(request) {
    const url = request.url();
    // 过滤静态资源
    return !url.match(/\.(js|css|png|jpg|gif|svg|woff|ico)$/);
}
```

---

## 输出格式

```yaml
status: success | failed | partial

execution_log:
  - step: 1
    action: "访问登录页"
    result: success
    screenshot: "01_login_page.png"

  - step: 2
    action: "输入用户名密码"
    result: success
    screenshot: "02_credentials.png"

  - step: 3
    action: "点击用户管理"
    result: failed
    explore_mode: true
    explore_attempts: 3
    final_result: success
    screenshot: "03_user_management.png"

evidence:
  screenshots:
    - "01_login_page.png"
    - "02_credentials.png"
    - "03_user_management.png"
    - "XX_poc_result.png"

  http:
    - request: |
        POST /admin/users HTTP/1.1
        ...
      response: |
        HTTP/1.1 200 OK
        ...

failure_info:  # 如果失败
  step: 4
  error: "找不到目标元素"
  screenshot: "stuck_step4.png"
  explore_log:
    - "尝试点击: 系统管理"
    - "尝试点击: 用户中心"
    - "尝试点击: 设置"
    - "探索失败: 未找到用户管理入口"
```

---

## 常见漏洞处理

### XSS

```javascript
async function verifyXSS(page, payload) {
    // 检查 alert 弹窗
    let alertFired = false;
    page.on('dialog', async dialog => {
        alertFired = true;
        await dialog.accept();
    });

    // 执行步骤后等待
    await page.waitForTimeout(2000);

    if (alertFired) {
        return { success: true, type: 'alert' };
    }

    // 检查 DOM 中是否有未过滤的 payload
    const content = await page.content();
    if (content.includes(payload) && !content.includes(escapeHtml(payload))) {
        return { success: true, type: 'dom_injection' };
    }

    return { success: false };
}
```

### CSRF

```javascript
async function verifyCSRF(page, targetAction) {
    // 1. 记录初始状态
    const initialState = await captureState(page);

    // 2. 执行 CSRF 攻击
    // ... 执行步骤

    // 3. 验证状态变化
    const newState = await captureState(page);

    if (stateChanged(initialState, newState)) {
        return { success: true, stateChange: diff(initialState, newState) };
    }

    return { success: false };
}
```

### 文件上传

```javascript
async function handleFileUpload(page, selector, filePath) {
    const input = await page.$(selector);

    if (input) {
        await input.setInputFiles(filePath);
        return true;
    }

    // 尝试找隐藏的 file input
    const hiddenInput = await page.$('input[type="file"]');
    if (hiddenInput) {
        await hiddenInput.setInputFiles(filePath);
        return true;
    }

    return false;
}
```

---

## 错误恢复

```javascript
async function withRetry(fn, maxRetries = 3) {
    for (let i = 0; i < maxRetries; i++) {
        try {
            return await fn();
        } catch (error) {
            console.log(`尝试 ${i + 1}/${maxRetries} 失败: ${error.message}`);

            if (i === maxRetries - 1) {
                throw error;
            }

            // 等待后重试
            await new Promise(r => setTimeout(r, 1000 * (i + 1)));
        }
    }
}
```

---

## 质量检查

执行完成后验证：
- [ ] 所有步骤都有截图
- [ ] 有 PoC 效果截图
- [ ] HTTP 证据记录完整
- [ ] 探索过程有记录（如果触发）
- [ ] 失败原因清晰（如果失败）
