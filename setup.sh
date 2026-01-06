#!/bin/bash

#############################################
# AI-Vuln-Reproduce 环境初始化脚本
#
# 功能：
# 1. 检查系统依赖
# 2. 安装 Playwright 浏览器
# 3. 配置 Claude Code MCP
#############################################

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印函数
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# 检查命令是否存在
check_command() {
    if command -v "$1" &> /dev/null; then
        success "$1 已安装: $(command -v $1)"
        return 0
    else
        warn "$1 未安装"
        return 1
    fi
}

# 打印 Banner
print_banner() {
    echo ""
    echo -e "${GREEN}"
    echo "    _    ___   __     __    _         ____                          _                "
    echo "   / \  |_ _|  \ \   / /   | | _ __  |  _ \ ___ _ __  _ __ ___   __| |_   _  ___ ___ "
    echo "  / _ \  | |____\ \ / /   | || '_ \ | |_) / _ \ '_ \| '__/ _ \ / _\` | | | |/ __/ _ \\"
    echo " / ___ \ | |_____\ V /|___|_|| | | ||  _ <  __/ |_) | | | (_) | (_| | |_| | (_|  __/"
    echo "/_/   \_\___|     \_/       |_||_| |_||_| \_\___| .__/|_|  \___/ \__,_|\__,_|\___\___|"
    echo "                                               |_|                                   "
    echo -e "${NC}"
    echo "AI 全自动漏洞复现智能体平台 - 环境初始化脚本"
    echo "GitHub: https://github.com/Clouditera/AI-Vuln-Reproduce"
    echo ""
}

# 检查系统依赖
check_dependencies() {
    info "检查系统依赖..."
    echo ""

    local all_ok=true

    # Node.js
    if check_command node; then
        NODE_VERSION=$(node --version)
        if [[ "${NODE_VERSION}" < "v18" ]]; then
            warn "Node.js 版本过低 (${NODE_VERSION})，建议升级到 v18+"
        fi
    else
        all_ok=false
    fi

    # npm/npx
    check_command npm || all_ok=false
    check_command npx || all_ok=false

    # Claude Code
    if check_command claude; then
        success "Claude Code CLI 已安装"
    else
        warn "Claude Code CLI 未安装"
        echo ""
        echo "  安装方法: npm install -g @anthropic-ai/claude-code"
        echo ""
    fi

    echo ""
    if [ "$all_ok" = false ]; then
        error "缺少必要依赖，请先安装 Node.js 18+"
    fi

    success "系统依赖检查完成"
}

# 安装 Playwright
install_playwright() {
    info "安装 Playwright 浏览器..."
    echo ""

    # 检查是否已安装
    if ls "$HOME/.cache/ms-playwright/chromium-"* 1> /dev/null 2>&1; then
        success "Playwright Chromium 已安装"
        read -p "是否重新安装? (y/N): " reinstall
        if [[ ! "$reinstall" =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi

    # 安装 Chromium
    info "下载 Chromium 浏览器 (约 165MB)..."
    npx playwright install chromium

    # 安装系统依赖 (Linux)
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        info "安装 Playwright 系统依赖..."
        if command -v sudo &> /dev/null; then
            sudo npx playwright install-deps chromium || {
                warn "系统依赖安装失败，可能需要手动安装"
                warn "运行: sudo npx playwright install-deps chromium"
            }
        else
            warn "无 sudo 权限，跳过系统依赖安装"
            warn "如果浏览器无法启动，请手动运行: sudo npx playwright install-deps chromium"
        fi
    fi

    success "Playwright 安装完成"
}

# 配置 MCP
configure_mcp() {
    info "配置 Claude Code MCP..."
    echo ""

    CLAUDE_CONFIG_DIR="$HOME/.claude"
    CLAUDE_CONFIG_FILE="$CLAUDE_CONFIG_DIR/settings.json"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    MCP_TEMPLATE="$SCRIPT_DIR/config/mcp-settings.json"

    # 创建配置目录
    mkdir -p "$CLAUDE_CONFIG_DIR"

    # 读取现有配置或创建新配置
    if [ -f "$CLAUDE_CONFIG_FILE" ]; then
        info "发现现有配置文件: $CLAUDE_CONFIG_FILE"

        # 检查是否已配置 playwright
        if grep -q "playwright" "$CLAUDE_CONFIG_FILE"; then
            success "Playwright MCP 已配置"
            read -p "是否覆盖 MCP 配置? (y/N): " overwrite
            if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
                return 0
            fi
        fi

        # 备份现有配置
        BACKUP_FILE="$CLAUDE_CONFIG_FILE.backup.$(date +%Y%m%d%H%M%S)"
        cp "$CLAUDE_CONFIG_FILE" "$BACKUP_FILE"
        info "已备份现有配置到: $BACKUP_FILE"
    fi

    # 使用模板配置
    if [ -f "$MCP_TEMPLATE" ]; then
        # 如果存在现有配置，合并 mcpServers
        if [ -f "$CLAUDE_CONFIG_FILE" ]; then
            # 使用 jq 合并配置（如果可用）
            if command -v jq &> /dev/null; then
                jq -s '.[0] * {mcpServers: (.[0].mcpServers + .[1].mcpServers)}' \
                    "$CLAUDE_CONFIG_FILE" "$MCP_TEMPLATE" > "$CLAUDE_CONFIG_FILE.tmp" \
                    && mv "$CLAUDE_CONFIG_FILE.tmp" "$CLAUDE_CONFIG_FILE"
                success "已合并 Playwright MCP 配置"
            else
                # 无 jq，直接使用模板
                cp "$MCP_TEMPLATE" "$CLAUDE_CONFIG_FILE"
                success "已应用 Playwright MCP 配置"
            fi
        else
            cp "$MCP_TEMPLATE" "$CLAUDE_CONFIG_FILE"
            success "已创建 Playwright MCP 配置"
        fi
    else
        # 无模板文件，直接写入
        cat > "$CLAUDE_CONFIG_FILE" << 'EOF'
{
  "mcpServers": {
    "playwright": {
      "command": "npx",
      "args": ["@executeautomation/playwright-mcp-server"]
    }
  }
}
EOF
        success "已创建 Playwright MCP 配置"
    fi

    echo ""
    info "配置文件位置: $CLAUDE_CONFIG_FILE"
}

# 验证安装
verify_installation() {
    info "验证安装..."
    echo ""

    # 测试 Playwright MCP
    info "测试 Playwright MCP Server..."
    RESULT=$(echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | timeout 15 npx @executeautomation/playwright-mcp-server 2>/dev/null | head -1)

    if echo "$RESULT" | grep -q "playwright-mcp"; then
        success "Playwright MCP Server 正常"
    else
        warn "Playwright MCP Server 验证超时，可能是首次下载"
        info "请重启 Claude Code 后使用 /mcp 命令验证"
    fi

    echo ""
    success "安装完成!"
}

# 打印使用说明
print_usage() {
    echo ""
    echo "=============================================="
    echo -e "${GREEN}环境配置完成!${NC}"
    echo "=============================================="
    echo ""
    echo "Playwright MCP 新增覆盖的漏洞类型:"
    echo "  - XSS (反射型/存储型/DOM)"
    echo "  - CSRF"
    echo "  - 点击劫持"
    echo "  - OAuth 流程漏洞"
    echo "  - 开放重定向"
    echo "  - Session 固定"
    echo ""
    echo "使用方法:"
    echo ""
    echo "  1. 重启 Claude Code:"
    echo "     claude"
    echo ""
    echo "  2. 验证 MCP 状态:"
    echo "     /mcp"
    echo ""
    echo "  3. 执行漏洞复现:"
    echo "     /vuln-reproduce @漏洞报告.md http://target:3000"
    echo ""
    echo "文档: https://github.com/Clouditera/AI-Vuln-Reproduce"
    echo ""
}

# 主函数
main() {
    print_banner

    echo "本脚本将执行以下操作:"
    echo "  1. 检查系统依赖 (Node.js 18+)"
    echo "  2. 安装 Playwright Chromium 浏览器"
    echo "  3. 配置 Claude Code Playwright MCP"
    echo ""
    read -p "是否继续? (Y/n): " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        echo "已取消"
        exit 0
    fi

    echo ""
    check_dependencies
    echo ""
    install_playwright
    echo ""
    configure_mcp
    echo ""
    verify_installation
    print_usage
}

# 运行
main "$@"
