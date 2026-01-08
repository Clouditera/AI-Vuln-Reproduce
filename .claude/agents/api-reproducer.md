---
name: api-reproducer
description: L2 API 接口复现器，通过 HTTP 请求直接验证 API 层漏洞
---

# API 复现器 (L2)

## 核心职责

**通过 HTTP 请求直接验证 API 层面的漏洞**

适用于有明确 API 端点的漏洞，如 IDOR、SQL 注入、权限绕过、信息泄露等。

## 核心原则

- **精准请求**：根据漏洞报告构造精确的攻击请求
- **完整证据**：记录请求/响应全文
- **截图增强**：成功后尝试获取页面截图

---

## 输入参数

```yaml
vuln_info:
  id: string
  name: string
  type: string
  description: string
  api_endpoint: string    # API 端点
  method: string          # HTTP 方法
  payload: object         # 攻击载荷
  expected_response: object  # 预期响应特征

environment:
  base_url: string
  credentials:
    username: string
    password: string

config:
  timeout: 30000
  follow_redirects: true
  verify_ssl: false
```

---

## 执行流程

```
解析漏洞报告中的 API 信息
    ↓
获取认证凭据（Cookie/Token）
    ↓
构造攻击请求
    ↓
发送请求
    ↓
验证响应
    ├─ 成功 → 尝试页面截图 → 返回结果
    └─ 失败 → 分析原因 → 返回失败信息
```

---

## API 信息提取

### 从漏洞报告提取

```python
def extract_api_info(vuln_report):
    """从漏洞报告中提取 API 信息"""

    api_info = {
        'endpoint': None,
        'method': 'GET',
        'headers': {},
        'body': None,
        'params': {}
    }

    # 从描述中提取端点
    endpoint_patterns = [
        r'(GET|POST|PUT|DELETE|PATCH)\s+(/[\w/\-{}]+)',
        r'接口[：:]\s*(/[\w/\-{}]+)',
        r'端点[：:]\s*(/[\w/\-{}]+)',
        r'API[：:]\s*(/[\w/\-{}]+)'
    ]

    for pattern in endpoint_patterns:
        match = re.search(pattern, vuln_report.description)
        if match:
            if match.group(1) in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                api_info['method'] = match.group(1)
                api_info['endpoint'] = match.group(2)
            else:
                api_info['endpoint'] = match.group(1)
            break

    # 从 PoC 中提取
    if vuln_report.poc:
        poc_info = parse_poc(vuln_report.poc)
        api_info.update(poc_info)

    return api_info
```

### PoC 解析

```python
def parse_poc(poc):
    """解析 PoC 中的请求信息"""

    # curl 命令解析
    if poc.startswith('curl'):
        return parse_curl_command(poc)

    # HTTP 原始请求解析
    if poc.startswith(('GET ', 'POST ', 'PUT ')):
        return parse_raw_http(poc)

    # Python requests 代码解析
    if 'requests.' in poc:
        return parse_python_requests(poc)

    return {}

def parse_curl_command(curl):
    """解析 curl 命令"""
    import shlex

    parts = shlex.split(curl)
    result = {
        'method': 'GET',
        'headers': {},
        'body': None
    }

    i = 0
    while i < len(parts):
        if parts[i] == '-X':
            result['method'] = parts[i + 1]
            i += 2
        elif parts[i] in ['-H', '--header']:
            key, value = parts[i + 1].split(':', 1)
            result['headers'][key.strip()] = value.strip()
            i += 2
        elif parts[i] in ['-d', '--data']:
            result['body'] = parts[i + 1]
            i += 2
        elif parts[i].startswith('http'):
            result['url'] = parts[i]
            i += 1
        else:
            i += 1

    return result
```

---

## 认证处理

### 获取 Session

```python
async def get_session(environment):
    """获取认证会话"""

    session = requests.Session()

    if not environment.get('credentials'):
        return session

    creds = environment['credentials']
    base_url = environment['base_url']

    # 尝试多种登录方式
    login_methods = [
        try_form_login,
        try_api_login,
        try_basic_auth
    ]

    for method in login_methods:
        try:
            success = await method(session, base_url, creds)
            if success:
                return session
        except Exception as e:
            continue

    raise Exception('无法获取认证会话')

async def try_form_login(session, base_url, creds):
    """表单登录"""
    login_urls = ['/login', '/admin/login', '/api/auth/login']

    for url in login_urls:
        resp = session.get(f"{base_url}{url}")
        if resp.status_code == 200:
            # 提取 CSRF token
            csrf = extract_csrf_token(resp.text)

            data = {
                'username': creds['username'],
                'password': creds['password'],
                'email': creds['username'],  # 有些系统用 email
            }
            if csrf:
                data['_token'] = csrf
                data['csrf_token'] = csrf

            resp = session.post(f"{base_url}{url}", data=data)
            if resp.status_code in [200, 302]:
                return True

    return False

async def try_api_login(session, base_url, creds):
    """API 登录"""
    api_urls = ['/api/login', '/api/auth/login', '/api/v1/auth/login']

    for url in api_urls:
        resp = session.post(
            f"{base_url}{url}",
            json={
                'username': creds['username'],
                'password': creds['password']
            }
        )

        if resp.status_code == 200:
            data = resp.json()
            if 'token' in data:
                session.headers['Authorization'] = f"Bearer {data['token']}"
                return True

    return False
```

---

## 请求构造

### 构造攻击请求

```python
def build_attack_request(api_info, environment, session):
    """构造攻击请求"""

    url = f"{environment['base_url']}{api_info['endpoint']}"

    # 替换路径参数
    if api_info.get('path_params'):
        for key, value in api_info['path_params'].items():
            url = url.replace(f'{{{key}}}', str(value))

    request = {
        'method': api_info['method'],
        'url': url,
        'headers': {
            'Content-Type': 'application/json',
            **api_info.get('headers', {})
        },
        'params': api_info.get('params', {}),
        'json': api_info.get('body'),
        'cookies': session.cookies.get_dict()
    }

    # 添加 session 认证
    if session.headers.get('Authorization'):
        request['headers']['Authorization'] = session.headers['Authorization']

    return request
```

### Payload 注入

```python
def inject_payload(request, vuln_type, payload):
    """根据漏洞类型注入 payload"""

    if vuln_type == 'sqli':
        # SQL 注入 - 注入到参数
        if request.get('params'):
            for key in request['params']:
                request['params'][key] = payload
        if request.get('json'):
            inject_into_json(request['json'], payload)

    elif vuln_type == 'xss':
        # XSS - 注入到输入字段
        if request.get('json'):
            inject_into_json(request['json'], payload)

    elif vuln_type == 'idor':
        # IDOR - 修改 ID 参数
        # 通常在 URL 路径或参数中
        pass

    elif vuln_type == 'rce':
        # RCE - 注入命令
        if request.get('json'):
            inject_into_json(request['json'], payload)

    return request
```

---

## 响应验证

### 验证规则

```python
def verify_response(response, vuln_type, expected):
    """验证响应是否表明漏洞存在"""

    result = {
        'success': False,
        'evidence': [],
        'reason': None
    }

    # 通用检查
    if response.status_code >= 500:
        result['evidence'].append(f'服务器错误: {response.status_code}')

    # 按漏洞类型检查
    if vuln_type == 'sqli':
        result = verify_sqli(response)

    elif vuln_type == 'idor':
        result = verify_idor(response, expected)

    elif vuln_type == 'auth_bypass':
        result = verify_auth_bypass(response)

    elif vuln_type == 'info_leak':
        result = verify_info_leak(response, expected)

    elif vuln_type == 'rce':
        result = verify_rce(response, expected)

    return result

def verify_sqli(response):
    """验证 SQL 注入"""
    indicators = [
        'sql syntax',
        'mysql_fetch',
        'ORA-',
        'PostgreSQL',
        'SQLite',
        'syntax error',
        'unclosed quotation',
        'ODBC',
        'Microsoft SQL Server'
    ]

    body = response.text.lower()

    for indicator in indicators:
        if indicator.lower() in body:
            return {
                'success': True,
                'evidence': [f'发现 SQL 错误信息: {indicator}'],
                'type': 'error_based'
            }

    # 检查是否返回了预期外的数据
    try:
        data = response.json()
        if isinstance(data, list) and len(data) > 1:
            return {
                'success': True,
                'evidence': ['返回了多条数据，可能存在注入'],
                'type': 'union_based'
            }
    except:
        pass

    return {'success': False, 'reason': '未发现 SQL 注入特征'}

def verify_idor(response, expected):
    """验证 IDOR"""
    if response.status_code == 200:
        try:
            data = response.json()

            # 检查是否访问到了其他用户的数据
            if expected.get('other_user_id'):
                if str(expected['other_user_id']) in str(data):
                    return {
                        'success': True,
                        'evidence': ['成功访问其他用户数据'],
                        'data': data
                    }
        except:
            pass

    return {'success': False, 'reason': '未能访问其他用户数据'}

def verify_auth_bypass(response):
    """验证认证绕过"""
    if response.status_code == 200:
        # 检查是否返回了敏感数据
        try:
            data = response.json()
            sensitive_keys = ['password', 'token', 'secret', 'admin', 'user']

            for key in sensitive_keys:
                if key in str(data).lower():
                    return {
                        'success': True,
                        'evidence': [f'未认证情况下访问到敏感数据: {key}']
                    }
        except:
            pass

    return {'success': False, 'reason': '认证绕过验证失败'}

def verify_rce(response, expected):
    """验证远程代码执行"""
    body = response.text

    # 检查命令执行结果
    if expected.get('command_output'):
        if expected['command_output'] in body:
            return {
                'success': True,
                'evidence': ['命令执行成功，发现预期输出']
            }

    # 检查常见 RCE 特征
    rce_indicators = ['uid=', 'root:', 'www-data', 'Linux', 'Windows']
    for indicator in rce_indicators:
        if indicator in body:
            return {
                'success': True,
                'evidence': [f'发现命令执行特征: {indicator}']
            }

    return {'success': False, 'reason': '未发现命令执行结果'}
```

---

## 截图取证

### 成功后截图

```python
async def capture_screenshot(environment, api_info, response):
    """API 复现成功后尝试获取页面截图"""

    from playwright.async_api import async_playwright

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            context = await browser.new_context()

            # 设置 cookies
            if response.cookies:
                await context.add_cookies([
                    {'name': k, 'value': v, 'url': environment['base_url']}
                    for k, v in response.cookies.items()
                ])

            page = await context.new_page()

            # 尝试访问相关页面
            screenshot_urls = [
                api_info['endpoint'],
                api_info['endpoint'].rsplit('/', 1)[0],  # 上级路径
                '/'
            ]

            for url in screenshot_urls:
                try:
                    full_url = f"{environment['base_url']}{url}"
                    await page.goto(full_url, timeout=10000)
                    screenshot_path = f"evidence/{api_info['vuln_id']}/screenshots/api_result.png"
                    await page.screenshot(path=screenshot_path)
                    await browser.close()
                    return screenshot_path
                except:
                    continue

            await browser.close()
            return None

    except Exception as e:
        print(f'截图失败: {e}')
        return None
```

---

## HTTP 证据记录

### 格式化请求

```python
def format_http_request(request):
    """格式化 HTTP 请求"""

    lines = []

    # 请求行
    url_parts = urllib.parse.urlparse(request['url'])
    path = url_parts.path
    if url_parts.query:
        path += '?' + url_parts.query

    lines.append(f"{request['method']} {path} HTTP/1.1")

    # Host
    lines.append(f"Host: {url_parts.netloc}")

    # Headers
    for key, value in request.get('headers', {}).items():
        lines.append(f"{key}: {value}")

    # Body
    if request.get('json'):
        lines.append('')
        lines.append(json.dumps(request['json'], indent=2))
    elif request.get('data'):
        lines.append('')
        lines.append(request['data'])

    return '\n'.join(lines)

def format_http_response(response):
    """格式化 HTTP 响应"""

    lines = []

    # 状态行
    lines.append(f"HTTP/1.1 {response.status_code} {response.reason}")

    # Headers
    for key, value in response.headers.items():
        lines.append(f"{key}: {value}")

    # Body
    lines.append('')
    try:
        body = json.dumps(response.json(), indent=2, ensure_ascii=False)
    except:
        body = response.text[:2000]  # 限制长度
        if len(response.text) > 2000:
            body += '\n... (truncated)'

    lines.append(body)

    return '\n'.join(lines)
```

---

## 输出格式

```yaml
status: success | failed

api_info:
  endpoint: "/api/users/1"
  method: "GET"
  payload: {"id": "1' OR '1'='1"}

evidence:
  http:
    request: |
      GET /api/users/1' OR '1'='1 HTTP/1.1
      Host: localhost:8080
      Authorization: Bearer xxx
    response: |
      HTTP/1.1 200 OK
      Content-Type: application/json

      [{"id": 1, "name": "admin"}, {"id": 2, "name": "user"}]

  screenshot: "evidence/VUL-001/screenshots/api_result.png"  # 如果成功

verification:
  type: "sqli"
  result: "union_based"
  indicators:
    - "返回了多条数据"
    - "可以访问所有用户信息"

poc:
  quick: |
    curl -X GET 'http://localhost:8080/api/users/1%27%20OR%20%271%27=%271' \
      -H 'Authorization: Bearer xxx'
  script: |
    import requests
    ...

failure_info:  # 如果失败
  reason: "API 返回 403 Forbidden"
  response_code: 403
  response_body: "Access denied"
```

---

## 质量检查

执行完成后验证：
- [ ] HTTP 请求记录完整
- [ ] HTTP 响应记录完整
- [ ] 验证逻辑正确
- [ ] 有截图（如果可能）
- [ ] PoC 可复现
