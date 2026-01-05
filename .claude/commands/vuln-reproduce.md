---
description: AI 全自动漏洞复现，@ 引用漏洞报告文件，提供环境链接或 Docker 配置，自动完成环境搭建、数据准备、PoC 验证
argument-hint: @<漏洞报告.md> <环境地址/Docker配置>
---

# 漏洞复现命令

收到用户输入后，调用 reproduce-orchestrator 智能体进行全自动漏洞复现。

## 使用方式

用户 @ 引用 MD 格式的漏洞报告文件，并提供测试环境信息。

## 输入格式

```
@<漏洞报告文件路径.md> <环境信息>
```

### 环境信息支持以下格式：

1. **在线环境地址**：
   ```
   @/path/to/vuln-report.md http://target-host:port
   ```

2. **Docker Compose 文件路径**：
   ```
   @/path/to/vuln-report.md @/path/to/docker-compose.yml
   ```

3. **项目目录（含 docker-compose）**：
   ```
   @/path/to/vuln-report.md @/path/to/project
   ```

4. **GitHub 仓库地址**：
   ```
   @/path/to/vuln-report.md https://github.com/user/repo
   ```

### 漏洞报告文件格式

漏洞报告 MD 文件应包含以下字段：

```markdown
## 漏洞标题
{标题}

## 漏洞类型
{IDOR/SQLi/XSS/SSRF/CSRF/命令注入/路径遍历/文件上传/竞态条件/认证绕过/批量赋值}

## 风险等级
{严重/高危/中危/低危}

## 漏洞端点
{HTTP方法} {路径}

## 漏洞描述
{详细描述}

## 攻击路径（可选）
{利用步骤}

## 受影响文件（可选）
{代码文件路径}
```

## 执行流程

1. 解析漏洞报告，提取关键信息
2. 使用 Task 工具调用 reproduce-orchestrator 智能体
3. 智能体将协调 env-builder、data-preparer、vuln-verifier 完成复现
4. 输出最终复现报告

## 调用智能体

收到输入后，立即使用以下方式调用编排智能体：

```
Task(subagent_type="reproduce-orchestrator", prompt="<用户的完整输入>")
```
