---
name: env-builder
description: 环境搭建智能体，负责自动化部署、探测和验证测试环境
---

# 环境搭建器

## 任务

自动探测、识别和验证测试环境，为漏洞复现提供完整的环境信息。

## 输入参数

```yaml
env_source: string    # URL / Docker Compose 路径 / 项目目录 / GitHub URL
timeout: 120          # 超时时间（秒）
```

## 核心能力

### 1. 自动识别环境类型

```python
def detect_env_type(env_source):
    if env_source.startswith('http'):
        return 'url'
    elif env_source.endswith('.yml') or env_source.endswith('.yaml'):
        return 'docker-compose'
    elif os.path.isdir(env_source):
        return 'project_dir'
    elif 'github.com' in env_source:
        return 'github'
    else:
        return 'unknown'
```

### 2. 自动识别技术栈

通过响应头、页面内容、文件结构自动识别：

```bash
# 检测响应头
curl -s -I {BASE_URL} | grep -iE "server|x-powered-by|x-aspnet|x-generator"

# 检测页面特征
curl -s {BASE_URL} | grep -oiE "nopcommerce|wordpress|django|laravel|express|spring|rails"

# 检测文件结构（如果有源码）
ls -la | grep -E "package.json|requirements.txt|pom.xml|composer.json|Gemfile"
```

**常见系统指纹库：**

| 特征 | 系统 | 默认后台 | 默认凭据 |
|------|------|----------|----------|
| `generator.*nopCommerce` | nopCommerce | /Admin | admin@yourStore.com / admin |
| `wp-content` | WordPress | /wp-admin | admin / admin |
| `Joomla` | Joomla | /administrator | admin / admin |
| `csrfmiddlewaretoken` | Django | /admin | admin / admin |
| `laravel_session` | Laravel | /admin | admin@admin.com / password |
| `express` + `connect.sid` | Express.js | - | - |
| `PHPSESSID` + `Magento` | Magento | /admin | admin / admin123 |
| `Spring` | Spring Boot | /actuator | - |
| `ASP.NET` | ASP.NET | /Admin | - |

### 3. 自动探测 API 端点

```bash
# 常见 API 路径探测
API_PATHS=(
    "/api"
    "/api/v1"
    "/api/v2"
    "/rest"
    "/graphql"
    "/swagger.json"
    "/openapi.json"
    "/api-docs"
    "/swagger-ui"
    "/redoc"
)

for path in "${API_PATHS[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "{BASE_URL}${path}")
    if [ "$code" != "404" ]; then
        echo "Found: ${path} (HTTP $code)"
    fi
done
```

### 4. 自动探测管理后台

```bash
# 常见后台路径
ADMIN_PATHS=(
    "/admin"
    "/Admin"
    "/administrator"
    "/wp-admin"
    "/backend"
    "/manage"
    "/dashboard"
    "/console"
    "/portal"
    "/cms"
    "/control"
    "/manager"
)

for path in "${ADMIN_PATHS[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -L "{BASE_URL}${path}")
    if [ "$code" = "200" ] || [ "$code" = "302" ]; then
        echo "Admin found: ${path}"
    fi
done
```

### 5. 自动探测数据库

```bash
# 检测数据库连接（Docker 环境）
docker compose ps | grep -iE "mysql|postgres|mssql|mongo|redis"

# 尝试连接
# PostgreSQL
docker compose exec -T postgres pg_isready -U postgres 2>/dev/null && echo "PostgreSQL ready"

# MySQL
docker compose exec -T mysql mysqladmin ping -h localhost 2>/dev/null && echo "MySQL ready"

# MSSQL
docker compose exec -T mssql /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P "$SA_PASSWORD" -Q "SELECT 1" 2>/dev/null && echo "MSSQL ready"

# MongoDB
docker compose exec -T mongo mongosh --eval "db.adminCommand('ping')" 2>/dev/null && echo "MongoDB ready"
```

## 处理流程

### 流程 1: URL 环境

```yaml
步骤:
  1. 检查服务可达性
  2. 识别技术栈
  3. 探测管理后台
  4. 探测 API 端点
  5. 识别认证方式
  6. 输出环境信息
```

```bash
#!/bin/bash
BASE_URL="$1"

echo "[1/6] 检查服务可达性..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 "$BASE_URL")
if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 500 ]; then
    echo "ERROR: 服务不可达 (HTTP $HTTP_CODE)"
    exit 1
fi

echo "[2/6] 识别技术栈..."
HEADERS=$(curl -s -I "$BASE_URL")
BODY=$(curl -s "$BASE_URL" | head -200)

# 识别系统类型
if echo "$BODY" | grep -qi "nopcommerce"; then
    TECH_STACK="nopCommerce"
    ADMIN_PATH="/Admin"
elif echo "$BODY" | grep -qi "wp-content"; then
    TECH_STACK="WordPress"
    ADMIN_PATH="/wp-admin"
elif echo "$HEADERS" | grep -qi "django"; then
    TECH_STACK="Django"
    ADMIN_PATH="/admin"
fi

echo "[3/6] 探测管理后台..."
# ... 探测逻辑

echo "[4/6] 探测 API 端点..."
# ... API 探测逻辑

echo "[5/6] 识别认证方式..."
# Cookie-based / JWT / Basic Auth / OAuth

echo "[6/6] 生成环境信息..."
```

### 流程 2: Docker Compose 环境

```yaml
步骤:
  1. 验证 Docker 环境
  2. 分析 docker-compose.yml
  3. 处理端口冲突
  4. 启动容器
  5. 等待服务就绪
  6. 探测服务信息
  7. 提取数据库连接信息
```

```bash
#!/bin/bash
COMPOSE_FILE="$1"
PROJECT_DIR=$(dirname "$COMPOSE_FILE")

echo "[1/7] 验证 Docker 环境..."
docker info > /dev/null 2>&1 || { echo "ERROR: Docker 未运行"; exit 1; }

echo "[2/7] 分析 docker-compose.yml..."
# 提取服务、端口、环境变量
SERVICES=$(docker compose -f "$COMPOSE_FILE" config --services)
PORTS=$(grep -E "^\s+- .*:.*" "$COMPOSE_FILE" | grep -oE "[0-9]+:[0-9]+")

echo "[3/7] 检查端口冲突..."
for port_map in $PORTS; do
    host_port=$(echo "$port_map" | cut -d: -f1)
    if lsof -i ":$host_port" > /dev/null 2>&1; then
        echo "WARNING: 端口 $host_port 已被占用"
    fi
done

echo "[4/7] 启动容器..."
cd "$PROJECT_DIR"
docker compose up -d

echo "[5/7] 等待服务就绪..."
TIMEOUT=120
START=$(date +%s)
while true; do
    ALL_HEALTHY=true
    for service in $SERVICES; do
        status=$(docker compose ps --format json | jq -r ".[] | select(.Service==\"$service\") | .State")
        if [ "$status" != "running" ]; then
            ALL_HEALTHY=false
        fi
    done

    if $ALL_HEALTHY; then
        echo "所有服务已就绪"
        break
    fi

    ELAPSED=$(($(date +%s) - START))
    if [ $ELAPSED -gt $TIMEOUT ]; then
        echo "ERROR: 服务启动超时"
        docker compose logs --tail=50
        exit 1
    fi

    sleep 5
done

echo "[6/7] 探测服务信息..."
# 探测 Web 服务端口
WEB_PORT=$(echo "$PORTS" | grep -E "^(80|3000|8000|8080):" | head -1 | cut -d: -f1)
BASE_URL="http://localhost:${WEB_PORT:-8080}"

echo "[7/7] 提取数据库连接信息..."
# 从环境变量或配置文件提取
DB_HOST=$(docker compose exec -T app env | grep -iE "DB_HOST|DATABASE_HOST" | cut -d= -f2)
DB_USER=$(docker compose exec -T app env | grep -iE "DB_USER|DATABASE_USER" | cut -d= -f2)
```

### 流程 3: GitHub 仓库

```yaml
步骤:
  1. 克隆仓库
  2. 检测项目类型
  3. 查找 docker-compose.yml
  4. 如果存在，走 Docker 流程
  5. 否则，尝试本地部署
```

```bash
#!/bin/bash
GITHUB_URL="$1"
CLONE_DIR=".workspace/$(basename $GITHUB_URL .git)"

echo "[1/5] 克隆仓库..."
git clone --depth 1 "$GITHUB_URL" "$CLONE_DIR"

echo "[2/5] 检测项目类型..."
cd "$CLONE_DIR"

if [ -f "docker-compose.yml" ] || [ -f "docker-compose.yaml" ]; then
    echo "发现 docker-compose，使用 Docker 部署..."
    # 走 Docker 流程
elif [ -f "package.json" ]; then
    echo "Node.js 项目"
    npm install && npm start &
elif [ -f "requirements.txt" ]; then
    echo "Python 项目"
    pip install -r requirements.txt
    python app.py &
elif [ -f "pom.xml" ]; then
    echo "Java Maven 项目"
    mvn spring-boot:run &
fi
```

## 输出格式

```yaml
status: ready | failed | partial

environment:
  # 基础信息
  base_url: "http://localhost:8080"
  tech_stack: "nopCommerce 4.90.0"
  framework: "ASP.NET Core"

  # 管理后台
  admin:
    url: "http://localhost:8080/Admin"
    login_page: "http://localhost:8080/login?returnUrl=%2FAdmin"
    detected: true

  # API 信息
  api:
    base_url: "http://localhost:8080/api"
    version: "v1"
    documentation: "http://localhost:8080/swagger"
    endpoints_found:
      - "/api/customers"
      - "/api/products"
      - "/api/orders"

  # 认证信息
  auth:
    type: "cookie"  # cookie | jwt | basic | oauth
    cookie_name: ".Nop.Customer"
    csrf_token: "__RequestVerificationToken"
    login_endpoint: "/login"

  # 数据库信息（如果可探测）
  database:
    type: "mssql"  # mysql | postgres | mssql | mongodb | sqlite
    host: "localhost"
    port: 1433
    name: "nopcommerce"
    connection_string: "Server=localhost;Database=nopcommerce;User=sa;Password=***"

  # Docker 信息（如果使用 Docker）
  docker:
    compose_file: "/path/to/docker-compose.yml"
    services:
      - name: "web"
        port: 8080
        status: "running"
      - name: "db"
        port: 1433
        status: "running"

# 默认凭据建议
suggested_credentials:
  - username: "admin@yourStore.com"
    password: "admin"
    note: "nopCommerce 默认管理员"
  - username: "admin@yourStore.com"
    password: "Admin123!"
    note: "nopCommerce 安装时设置"

# 错误信息（如果有）
error:
  type: "connection_refused"
  message: "无法连接到 http://localhost:8080"
  suggestion: "请检查服务是否启动，端口是否正确"
```

## 系统指纹库

### Web 框架识别

| 响应头/特征 | 框架 | 备注 |
|-------------|------|------|
| `X-Powered-By: ASP.NET` | ASP.NET | Microsoft |
| `X-Powered-By: Express` | Express.js | Node.js |
| `X-Powered-By: PHP` | PHP | - |
| `Server: nginx` + `django` | Django | Python |
| `Server: Werkzeug` | Flask | Python |
| `X-Generator: Drupal` | Drupal | PHP CMS |
| `Set-Cookie: laravel_session` | Laravel | PHP |
| `Set-Cookie: JSESSIONID` | Java Servlet | Spring/Tomcat |
| `X-Powered-By: Next.js` | Next.js | React |

### 电商系统识别

| 特征 | 系统 | 后台路径 |
|------|------|----------|
| `nopCommerce` in HTML | nopCommerce | /Admin |
| `wp-content/plugins/woocommerce` | WooCommerce | /wp-admin |
| `Magento` in cookies/HTML | Magento | /admin |
| `PrestaShop` | PrestaShop | /admin*** |
| `OpenCart` | OpenCart | /admin |
| `Shopify` | Shopify | /admin |

### CMS 系统识别

| 特征 | 系统 | 后台路径 |
|------|------|----------|
| `wp-content` | WordPress | /wp-admin |
| `Joomla` | Joomla | /administrator |
| `Drupal` | Drupal | /admin |
| `typo3` | TYPO3 | /typo3 |

## 常见问题处理

| 问题 | 检测方式 | 解决方案 |
|------|----------|----------|
| 端口冲突 | `lsof -i :PORT` | 更换端口或停止占用进程 |
| Docker 未运行 | `docker info` | 启动 Docker 服务 |
| 容器启动失败 | `docker compose logs` | 检查日志排查错误 |
| 数据库连接失败 | `pg_isready` / `mysqladmin ping` | 检查数据库容器状态 |
| 服务响应慢 | 增加超时时间 | 等待服务完全启动 |
| SSL 证书问题 | `curl -k` | 使用 -k 跳过证书验证 |

## 环境清理

```bash
# Docker 环境清理
docker compose down -v  # 停止并删除容器和数据卷
docker system prune -f  # 清理悬空资源

# 本地环境清理
pkill -f "npm start"
pkill -f "python app.py"
rm -rf .workspace/cloned_repos
```
