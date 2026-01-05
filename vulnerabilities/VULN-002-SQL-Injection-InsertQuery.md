# Evershop postgres-query-builder InsertQuery SQL注入漏洞报告

## 1. 漏洞挖掘目标

- **受影响系统/产品**：Evershop E-commerce Platform - postgres-query-builder 模块
- **受影响版本**：2.1.0 及之前版本
- **仓库地址**：https://github.com/evershopcommerce/evershop

## 2. 漏洞说明

### 2.1 漏洞描述

- **漏洞类型**：SQL注入 (CWE-89)
- **漏洞名称**：Evershop postgres-query-builder InsertQuery.sql() 表名SQL注入漏洞
- **风险等级**：严重
- **概述**：与 `UpdateQuery` 相同，`InsertQuery` 类的 `sql()` 方法在查询 `information_schema` 获取表结构时，将表名通过字符串模板直接拼接，未使用参数化查询，存在SQL注入风险。

### 2.2 利用前提与特征

- **利用难度**：中
- **权限要求**：取决于应用实现
- **操作条件**：应用代码使用 `insert(userInput)` 形式调用
- **当前Evershop利用状态**：暂不可被直接利用（表名硬编码）

### 2.3 漏洞效果

与 VULN-001 相同：信息泄露、认证绕过、数据篡改可能。

## 3. 漏洞复现

- **是否可以制作成自动化复现脚本**：是

### 3.1 漏洞复现过程

**漏洞代码位置**：`packages/postgres-query-builder/src/index.ts`，第925-936行

```typescript
async sql(connection: PoolClient): Promise<string> {
  // ...
  const { rows } = await connection.query(
    `SELECT
      table_name,
      column_name,
      data_type,
      is_nullable,
      column_default,
      is_identity,
      identity_generation
    FROM information_schema.columns
    WHERE table_name = '${this._table}'`  // <-- SQL注入点
  );
  // ...
}
```

**攻击示例**：
```typescript
// 恶意输入
const payload = "products' UNION SELECT 1,password,3,4,5,6,7 FROM admin_user--";
await insert(payload).given({name: 'test'}).execute(connection);
```

## 4. 漏洞利用

- **是否可以制作成自动化复现脚本**：是
- **相关脚本代码**：参见 VULN-001 的 PoC，将 `update()` 替换为 `insert()` 即可

## 5. 漏洞原理

与 VULN-001 完全相同的代码模式，同一开发者在两个类中犯了相同的错误。

**数据流**：
```
insert(table) → InsertQuery构造函数 → this._table → sql()方法 → 字符串拼接 → connection.query()
```

## 6. 修复建议

修改 `packages/postgres-query-builder/src/index.ts` 第925-936行：

```typescript
// 修复后
const { rows } = await connection.query({
  text: `SELECT table_name, column_name, data_type, is_nullable,
         column_default, is_identity, identity_generation
         FROM information_schema.columns
         WHERE table_name = $1`,
  values: [this._table]
});
```

---

**报告编写日期**：2026-01-04
