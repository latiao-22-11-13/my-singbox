#!/bin/bash
stty erase '^H'
# ==============================================================================
# Sing-box 终极管理脚本
# ==============================================================================

# --- 0. 全局变量 ---
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
PLAIN="\033[0m"

SB_ROOT="/etc/sing-box"
SB_SERVER="${SB_ROOT}/server"
SB_CLIENT="${SB_ROOT}/client"
SB_CERT="${SB_ROOT}/cert"
SB_CERT_ACME="${SB_CERT}/acme"
SB_CERT_SELF="${SB_CERT}/self"
SB_RULE="${SB_ROOT}/rule"
SB_NODES="${SB_ROOT}/nodes"
REALM_ROOT="/etc/realm"
SB_BIN="/usr/bin/sing-box"

# --- 1. 基础工具函数 ---

check_root() {
    [[ $EUID -ne 0 ]] && echo -e "${RED}错误: 必须使用 root 用户运行此脚本！${PLAIN}" && exit 1
}

purge_dpkg_residue() {
    if dpkg -l | grep -q "sing-box"; then
        echo -e "${YELLOW}>>> 检测到旧版 dpkg 残留，正在清理...${PLAIN}"
        export DEBIAN_FRONTEND=noninteractive
        dpkg -P --force-all sing-box >/dev/null 2>&1
    fi
}

install_base() {
    purge_dpkg_residue
    # 1. 依赖安装
    if ! command -v curl &> /dev/null || ! command -v jq &> /dev/null || ! command -v unzip &> /dev/null; then
        echo -e "${GREEN}>>> 正在初始化系统依赖 (含 unzip)...${PLAIN}"
        if [[ -f /etc/redhat-release ]]; then
            yum install -y curl wget jq tar socat openssl cronie net-tools unzip
            systemctl start crond && systemctl enable crond
        elif grep -q -E -i "debian|ubuntu" /etc/issue; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y && apt-get install -y curl wget jq tar socat openssl cron net-tools unzip
        fi
    fi

    # 2. 目录初始化
    mkdir -p ${SB_SERVER} ${SB_CLIENT} ${SB_CERT_ACME} ${SB_CERT_SELF} ${SB_RULE} ${SB_NODES} ${REALM_ROOT}
    for f in ${SB_SERVER}/*.json.json; do [ -e "$f" ] && mv "$f" "${f%.json}"; done

    # 3. [核心修改] 智能快捷键设置 (仅在 Sing-box 已安装时触发)
    if [[ -f "${SB_BIN}" ]]; then
        
        # 情况 A: 本地文件运行 (下载后运行的) -> 直接复制 "$0"
        if [[ -f "$0" && "$0" != "/usr/bin/sb" ]]; then
            cp -f "$0" /usr/bin/sb
            chmod +x /usr/bin/sb
            echo -e "${GREEN}>>> 检测到 Sing-box 已安装，快捷键 'sb' 维护成功 (本地模式)！${PLAIN}"

        # 情况 B: 管道运行 (bash <(curl...)) -> 从 GitHub 下载自身
        # 逻辑：如果是管道运行，且系统里还没有 sb 命令，就去你的仓库下载
        elif [[ ! -f "/usr/bin/sb" ]]; then
            echo -e "${YELLOW}>>> 检测到管道运行且已安装内核，正在配置快捷键...${PLAIN}"
            
            # 👇 已填入你的专属链接 👇
            curl -L -o /usr/bin/sb "https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/sb.sh"
            
            chmod +x /usr/bin/sb
            echo -e "${GREEN}>>> 快捷键 'sb' 已设置成功 (在线模式)！${PLAIN}"
        fi
    fi
}

format_json() {
    local file=$1
    if [[ -f "$file" ]]; then jq '.' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"; fi
}

check_port() {
    local port=$1
    [[ -z "$port" ]] && echo "端口无效" && return 1
    if [[ "$port" == "80" || "$port" == "443" ]]; then
        if systemctl is-active --quiet nginx; then echo -e "${RED}[冲突] 端口 ${port} 正被 Nginx 占用！${PLAIN}"; return 1; fi
    fi
    if command -v ss >/dev/null; then
        if ss -tuln | grep -q ":${port} "; then echo -e "${RED}[冲突] 端口 ${port} 已被系统占用 (ss)！${PLAIN}"; return 1; fi
    elif command -v netstat >/dev/null; then
        if netstat -tuln | grep -q ":${port} "; then echo -e "${RED}[冲突] 端口 ${port} 已被系统占用 (netstat)！${PLAIN}"; return 1; fi
    fi
    if grep -q "\"listen_port\": ${port}" ${SB_SERVER}/*.json 2>/dev/null; then
        echo -e "${YELLOW}[提示] 端口 ${port} 已被本脚本配置使用。${PLAIN}"
    fi
    return 0
}

get_safe_port() {
    local prompt=$1; local default=$2; local port
    while true; do
        read -p "${prompt} [默认 ${default}]: " port
        [[ -z "$port" ]] && port=$default
        if check_port $port; then echo "$port"; return 0; else echo -e "${YELLOW}端口被占用，请更换。${PLAIN}"; fi
    done
}

# --- [新增] 赛风/Warp 组件变量 ---
SB_BIN_DIR="${SB_ROOT}/bin"
SB_WPPH_BIN="${SB_BIN_DIR}/sbwpph"
SB_WPPH_LOG="${SB_ROOT}/sbwpph.log"

# --- [新增] 赛风/Warp 下载函数  ---
install_sbwpph_tool() {
    mkdir -p "${SB_BIN_DIR}"
    if [[ ! -f "${SB_WPPH_BIN}" ]]; then
        echo -e "${YELLOW}>>> 正在下载 Warp/Psiphon 组件 (sbwpph)...${PLAIN}"
        local arch=$(uname -m)
        local cpu=""
        case $arch in
            x86_64|amd64) cpu="amd64" ;;
            aarch64|arm64) cpu="arm64" ;;
            *) echo -e "${RED}不支持的架构: $arch${PLAIN}"; return 1 ;;
        esac

        # 使用 yg.sh 的源
        curl -L -o "${SB_WPPH_BIN}" -# --retry 2 --insecure "https://raw.githubusercontent.com/yonggekkk/sing-box-yg/main/sbwpph_$cpu"

        if [[ -f "${SB_WPPH_BIN}" ]]; then
            chmod +x "${SB_WPPH_BIN}"
            echo -e "${GREEN}组件下载成功！${PLAIN}"
        else
            echo -e "${RED}下载失败，请检查网络。${PLAIN}"
            return 1
        fi
    fi
}

version_ge() { test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"; }

# ==========================================================
# [新增] IP 获取逻辑 (读取物理网卡，剔除 Warp/Tun/Docker)
# ==========================================================
get_yongge_real_ip() {
    local type=$1 # 传入 "v4" 或 "v6"

    # 定义要排除的虚拟网卡关键词
    local exclude_net="docker|wgcf|warp|tun|sw"
    local ip=""

    if [[ "$type" == "v4" ]]; then
        # 逻辑：scope global (只看公网) -> 排除虚拟网卡 -> 提取 IPv4 -> 排除局域网 -> 取第一个
        ip=$(ip -o -4 addr list scope global | grep -vE "$exclude_net" | awk '{print $4}' | cut -d/ -f1 | grep -vE '^127\.|^10\.|^172\.|^192\.' | head -n 1)

        # 兜底：如果没抓到，尝试 curl，但要排除 Warp IP (104.xx)
        if [[ -z "$ip" ]]; then
            local pub_ip=$(curl -s4m3 https://api.ipify.org)
            if [[ "$pub_ip" =~ ^104\. ]]; then ip=""; else ip="$pub_ip"; fi
        fi

    elif [[ "$type" == "v6" ]]; then
        # 逻辑：scope global (只看公网) -> 排除虚拟网卡 -> 提取 IPv6 -> 排除 fe80(链路) 和 ::1(回环) -> 取第一个
        ip=$(ip -o -6 addr list scope global | grep -vE "$exclude_net" | awk '{print $4}' | cut -d/ -f1 | grep -vE '^fe80|^::1' | head -n 1)

        # 兜底：如果没抓到，尝试 curl
        if [[ -z "$ip" ]]; then
            ip=$(curl -s6m3 https://api64.ipify.org)
        fi
    fi

    echo "$ip"
}

# [新增] 统一调用入口：优先 V4，无 V4 则自动切 V6
get_final_server_ip() {
    local ip=$(get_yongge_real_ip "v4")
    if [[ -z "$ip" ]]; then
        ip=$(get_yongge_real_ip "v6")
    fi
    # 终极兜底
    if [[ -z "$ip" ]]; then ip=$(curl -s ipv4.icanhazip.com); fi
    echo "$ip"
}
# --- 2. 核心管理 ---

check_arch() {
    local arch=$(uname -m)
    case $arch in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        s390x) echo "s390x" ;;
        riscv64) echo "riscv64" ;;
        *) echo "不支持的架构: $arch"; exit 1 ;;
    esac
}

adapt_config_to_version() {
    local cur_ver=$1; local ver_num=${cur_ver#v}

    # 无论版本如何，先处理 AnyTLS (版本隔离逻辑)
    # [修正] 严格以 1.12 为分界线，与 DNS/Outbounds 逻辑保持一致
    if version_ge $ver_num "1.12"; then
        echo -e "${YELLOW}>>> 检测到新内核 (v1.12+)，正在执行兼容性清洗...${PLAIN}"

        # 1. 恢复 AnyTLS
        for f in ${SB_SERVER}/disabled_anytls_*.bak; do
            [ -e "$f" ] || continue
            local fn=$(basename "$f"); local core_name="${fn#disabled_anytls_}"; core_name="${core_name%.bak}"; core_name="${core_name%.json}"
            mv "$f" "${SB_SERVER}/40_anytls_${core_name}.json"
            [[ -f "${SB_CLIENT}/disabled_anytls_${core_name}.bak" ]] && mv "${SB_CLIENT}/disabled_anytls_${core_name}.bak" "${SB_CLIENT}/40_anytls_${core_name}.json"
        done
        download_rules_local

        # 2. Hy2/TUIC 配置清洗 (1.12 必须删除 port_hopping 字段)
        local protocols=("20_hysteria2_*.json" "30_tuic_*.json")
        for proto in "${protocols[@]}"; do
            for f in ${SB_SERVER}/$proto; do
                [ -e "$f" ] || continue

                # [清洗动作 1] 如果存在 port_hopping 字段，删掉 (防止 1.12 报错 unknown field)
                if jq -e '.inbounds[0].port_hopping' "$f" >/dev/null 2>&1; then
                    echo -e "${YELLOW}[兼容性修复] 移除文件 $f 中的 port_hopping 字段...${PLAIN}"
                    jq 'del(.inbounds[0].port_hopping)' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
                fi

                # [清洗动作 2] 如果 listen_port 是字符串 (范围)，强制转为单端口数字 (防止 1.12 报错 type error)
                # 逻辑: 取范围的第一个端口作为单端口，端口跳跃交给 iptables (如果已配置)
                if jq -e '(.inbounds[0].listen_port | type) == "string"' "$f" >/dev/null 2>&1; then
                    echo -e "${YELLOW}[兼容性修复] 将文件 $f 中的端口范围修正为单端口...${PLAIN}"
                    jq '.inbounds[0].listen_port = (.inbounds[0].listen_port | split("-")[0] | tonumber)' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
                fi
            done
        done

    else
        echo -e "${YELLOW}>>> 检测到旧内核 (<= 1.11)，执行向下兼容...${PLAIN}"

        # 1. 禁用 AnyTLS (防止旧版不兼容)
        local files=$(grep -l '"type": "anytls"' ${SB_SERVER}/*.json 2>/dev/null)
        if [[ -n "$files" ]]; then
            for f in $files; do
                local fn=$(basename "$f"); local core_name="${fn#40_anytls_}"; core_name="${core_name%.json}"
                mv "$f" "${SB_SERVER}/disabled_anytls_${core_name}.bak"
                [[ -f "${SB_CLIENT}/${fn}" ]] && mv "${SB_CLIENT}/${fn}" "${SB_CLIENT}/disabled_anytls_${core_name}.bak"
            done
        fi
        rm -rf ${SB_RULE}/*.srs

        # 2. Hy2/TUIC: 旧版本不需要做任何操作
        # 因为 "单端口 JSON + iptables" 的方案在旧版本也是 100% 兼容的。
    fi
}

download_rules_local() {
    echo -e "${YELLOW}>>> 下载最新规则集 (.srs)...${PLAIN}"
    local base_geo="https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set"
    local base_site="https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set"
    local files=("geoip-cn.srs|${base_geo}/geoip-cn.srs" "geosite-cn.srs|${base_site}/geosite-cn.srs" "geosite-openai.srs|${base_site}/geosite-openai.srs" "geosite-google-gemini.srs|${base_site}/geosite-google-gemini.srs" "geosite-netflix.srs|${base_site}/geosite-netflix.srs" "geosite-anthropic.srs|${base_site}/geosite-anthropic.srs" "geosite-category-games@cn.srs|${base_site}/geosite-category-games@cn.srs" "geosite-category-ads-all.srs|${base_site}/geosite-category-ads-all.srs" "geosite-category-ai-chat-!cn.srs|${base_site}/geosite-category-ai-chat-!cn.srs")

    for item in "${files[@]}"; do
        local fname="${item%%|*}"; local url="${item##*|}"
        for i in {1..2}; do
            curl -sL --connect-timeout 5 -o "${SB_RULE}/${fname}.tmp" "$url"
            if [[ $? -eq 0 ]]; then mv "${SB_RULE}/${fname}.tmp" "${SB_RULE}/${fname}"; break; else rm -f "${SB_RULE}/${fname}.tmp"; fi
        done
        [[ ! -f "${SB_RULE}/${fname}" ]] && echo -e "${RED}警告: ${fname} 下载失败${PLAIN}"
    done
}

generate_base_config() {
    # Tom 建议：基础配置极简，无 DNS 模块，日志静默 (error 级别)
    echo -e "${GREEN}>>> 生成极简基础配置 (00_base.json) [Tom静默版]...${PLAIN}"

    cat > ${SB_SERVER}/00_base.json <<EOF
{
  "log": { "level": "error", "timestamp": true }
}
EOF
    format_json "${SB_SERVER}/00_base.json"
}

generate_outbounds_config() {
    local cur_ver=${1#v}; [[ -z "$cur_ver" ]] && cur_ver=$(${SB_BIN} version | head -n 1 | awk '{print $3}')
    if [[ "$cur_ver" =~ ^1\.1[2-9] ]] || version_ge $cur_ver "1.12"; then
        cat > ${SB_SERVER}/02_outbounds.json <<EOF
{ "outbounds": [ { "type": "direct", "tag": "direct" } ] }
EOF
    else
        cat > ${SB_SERVER}/02_outbounds.json <<EOF
{ "outbounds": [ { "type": "direct", "tag": "direct" }, { "type": "block", "tag": "block" }, { "type": "dns", "tag": "dns-out" } ] }
EOF
    fi
    format_json "${SB_SERVER}/02_outbounds.json"
}

update_route_rules() {
    # 1. 自动获取当前版本号
    local cur_ver=${1#v}
    [[ -z "$cur_ver" ]] && cur_ver=$(${SB_BIN} version 2>/dev/null | head -n 1 | awk '{print $3}')
    cur_ver=${cur_ver#v}

    echo -e "${YELLOW}>>> [Tom最终版] 生成智能极简路由 (修复崩溃 + 保留分流)...${PLAIN}"
    rm -f ${SB_SERVER}/03_upstream_*.json

    local rules_json=""

    # 2. 遍历生成节点 Outbound
    for f in ${SB_NODES}/*.conf; do
        [[ ! -f "$f" ]] && continue
        # 清空变量
        TAG=""; IP=""; PORT=""; PASS=""; METHOD=""; RULES=""; RULE_TYPE=""; RULE_NAME=""
        source "$f"

        # --- 生成 Outbound (保持不变) ---
        if [[ "$TYPE" == "shadowsocks" ]]; then
            cat > ${SB_SERVER}/03_upstream_${TAG}.json <<EOF
{ "outbounds": [{ "type": "shadowsocks", "tag": "${TAG}", "server": "${IP}", "server_port": ${PORT}, "method": "${METHOD}", "password": "${PASS}" }] }
EOF
        elif [[ "$TYPE" == "socks" ]]; then
            cat > ${SB_SERVER}/03_upstream_${TAG}.json <<EOF
{ "outbounds": [{ "type": "socks", "tag": "${TAG}", "server": "${IP}", "server_port": ${PORT} }] }
EOF
        fi

        # --- [核心逻辑保留] 智能拆分规则类型 ---
        local site_items=$(echo "$RULES" | grep -o '"geosite-[^"]*"' | tr '\n' ',' | sed 's/,$//')
        local domain_items=$(echo "$RULES" | grep -o '"[^"]*"' | grep -v '"geosite-' | tr '\n' ',' | sed 's/,$//')

        if [[ -n "$site_items" ]]; then
             rules_json="${rules_json} { \"rule_set\": [${site_items}], \"outbound\": \"${TAG}\" },"
        fi

        if [[ -n "$domain_items" ]]; then
             rules_json="${rules_json} { \"domain_suffix\": [${domain_items}], \"outbound\": \"${TAG}\" },"
        fi
    done

    # 3. 通用规则定义 (Tom 优化版)
    # 只保留可能用于“分流”的规则，彻底删除了 Games/Ads/GeoIP-CN 的定义
    local common_rules='
      { "tag": "geosite-openai", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-openai.srs", "download_detour": "direct" },
      { "tag": "geosite-anthropic", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-anthropic.srs", "download_detour": "direct" },
      { "tag": "geosite-google-gemini", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-google-gemini.srs", "download_detour": "direct" },
      { "tag": "geosite-category-ai-chat-!cn", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ai-chat-!cn.srs", "download_detour": "direct" },
      { "tag": "geosite-netflix", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs", "download_detour": "direct" },
      { "tag": "geosite-disney", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-disney.srs", "download_detour": "direct" },
      { "tag": "geosite-tiktok", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-tiktok.srs", "download_detour": "direct" }
    '

    # 生成最终 route.json
    # 修复点：移除了 "default_domain_resolver" 和 "dns-out"
    cat > ${SB_SERVER}/01_route.json <<EOF
{
  "route": {
    "rules": [
      { "protocol": "dns", "outbound": "direct" },
      { "ip_is_private": true, "outbound": "block" },
      ${rules_json}
      { "outbound": "direct" }
    ],
    "rule_set": [
      ${common_rules}
    ],
    "final": "direct"
  }
}
EOF
    # 修复 JSON 格式
    sed -i 's/, \+{\"outbound\": \"direct\"}/, {\"outbound\": \"direct\"}/' ${SB_SERVER}/01_route.json
    format_json ${SB_SERVER}/01_route.json
}

# --- 3. 安装模块 ---

install_singbox() {
    clear
    local is_first_install=0
    [[ ! -f "${SB_BIN}" ]] && is_first_install=1
    install_base
    local arch=$(uname -m)
    local sb_arch=""
    case $arch in
        x86_64|amd64) sb_arch="amd64" ;;
        aarch64|arm64) sb_arch="arm64" ;;
        s390x) sb_arch="s390x" ;;
        riscv64) sb_arch="riscv64" ;;
        *) echo -e "${RED}不支持的架构: $arch${PLAIN}"; return ;;
    esac

    echo -e "${GREEN}>>> 正在获取 Sing-box 版本信息...${PLAIN}"
    local latest_ver=$(curl -m 10 -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    local beta_ver=$(curl -m 10 -s https://api.github.com/repos/SagerNet/sing-box/releases | grep '"tag_name":' | head -n 1 | sed -E 's/.*"([^"]+)".*/\1/')

    [[ -z "$latest_ver" ]] && latest_ver="获取失败"
    [[ -z "$beta_ver" ]] && beta_ver="获取失败"

    echo -e "===================================================="
    echo -e "           Sing-box 内核安装/切换 (完美版)"
    echo -e "===================================================="
    echo -e "  1. 最新稳定版 (${GREEN}${latest_ver}${PLAIN})"
    echo -e "  2. 最新测试版 (${YELLOW}${beta_ver}${PLAIN})"
    echo -e "  3. 指定版本   (例如 v1.10.7)"
    echo -e "  0. 返回上一级"
    echo -e "===================================================="
    read -p " 请输入数字 [0-3]: " choice

    local version=""
    case "$choice" in
        1) version="${latest_ver}" ;;
        2) version="${beta_ver}" ;;
        3) read -p "请输入版本号 (支持 1.10.7 或 v1.10.7): " input_ver
           if [[ "${input_ver:0:1}" != "v" ]]; then version="v${input_ver}"; else version="${input_ver}"; fi ;;
        0) return ;;
        *) echo -e "${RED}输入错误${PLAIN}"; return ;;
    esac

    if [[ "$version" == "获取失败" ]] || [[ -z "$version" ]]; then echo -e "${RED}无效版本信息${PLAIN}"; return; fi

    local ver_num="${version#v}"
    local download_url="https://github.com/SagerNet/sing-box/releases/download/${version}/sing-box-${ver_num}-linux-${sb_arch}.tar.gz"

    echo -e "${YELLOW}>>> 正在验证版本有效性: ${version} ...${PLAIN}"
    local check_status=$(curl -o /dev/null -s -w "%{http_code}" -I "$download_url")
    if [[ "$check_status" != "200" && "$check_status" != "302" ]]; then
        echo -e "${RED}错误: 版本 ${version} 不存在 (HTTP ${check_status})${PLAIN}"; sleep 3; return
    fi

    echo -e "${GREEN}>>> 版本有效，开始下载...${PLAIN}"
    systemctl stop sing-box 2>/dev/null
    rm -f /tmp/sing-box.tar.gz
    wget -O /tmp/sing-box.tar.gz "$download_url"
    if [[ $? -ne 0 ]]; then echo -e "${RED}下载中断。${PLAIN}"; rm -f /tmp/sing-box.tar.gz; return; fi

    cd /tmp
    if ! tar -xzf sing-box.tar.gz; then echo -e "${RED}解压失败。${PLAIN}"; rm -f sing-box.tar.gz; return; fi
    local sb_bin_path=$(find . -name "sing-box" -type f | grep "linux" | head -n 1)
    if [[ -z "$sb_bin_path" ]]; then echo -e "${RED}未找到二进制文件。${PLAIN}"; return; fi

    mv "$sb_bin_path" ${SB_BIN}
    chmod +x ${SB_BIN}
    rm -rf sing-box.tar.gz "sing-box-${ver_num}-linux-${sb_arch}" 2>/dev/null
    adapt_config_to_version "$version"

    cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target
[Service]
User=root
Group=root
ExecStart=${SB_BIN} run -C ${SB_SERVER}
WorkingDirectory=${SB_SERVER}
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sing-box

    if ! grep -q "net.core.rmem_max=33554432" /etc/sysctl.conf; then
        echo "net.core.rmem_max=33554432" >> /etc/sysctl.conf; echo "net.core.wmem_max=33554432" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_fastopen=3" >> /etc/sysctl.conf; sysctl -p >/dev/null 2>&1
    fi

    generate_base_config "$version"
    generate_outbounds_config "$version"
    update_route_rules "$version"

    systemctl restart sing-box
    echo -e "${GREEN}Sing-box ${version} 安装成功！${PLAIN}"

    if [[ "$is_first_install" == "1" ]]; then
        echo -e "${YELLOW}>>> 检测到首次安装，等待网络稳定 (5秒)...${PLAIN}"
        sleep 5
        menu_protocol
    else
        read -p "按回车返回..."
    fi
}

# --- 4. 配套组件 ---

menu_cert_nginx() {
    clear
    echo -e "===================================================="
    echo -e "           域名证书 & 伪装站点管理"
    echo -e "===================================================="
    echo -e "  1. 80 端口模式 (申请证书 + 部署 Nginx 伪装)"
    echo -e "  2. 卸载 Nginx & 清理证书"
    echo -e "  3. 更换 Nginx 伪装网站 (在线模板库)"  # <--- 新增选项
    echo -e "  0. 返回上一级"
    echo -e "===================================================="
    read -p "-> " opt
    case "$opt" in
        1) install_nginx_cert_standalone ;;
        2) systemctl stop nginx; apt-get purge -y nginx nginx-common; rm -rf /usr/share/nginx/html /etc/nginx ${SB_CERT_ACME}; echo -e "${GREEN}清理完成。${PLAIN}"; read -p "回车..." ;;
        3) switch_camouflage_site ;; # <--- 新增跳转逻辑
        0) return ;;
        *) echo -e "${RED}输入错误${PLAIN}"; sleep 1; menu_cert_nginx ;;
    esac
    # 执行完功能后重新显示菜单
    menu_cert_nginx
}

install_nginx_cert_standalone() {
    echo -e "${YELLOW}>>> 正在安装 ACME 依赖...${PLAIN}"
    if [[ "$RELEASE" == "centos" ]]; then yum install -y socat nginx; else apt-get install -y socat nginx; fi

    # 停止 Nginx 释放 80 端口
    systemctl stop nginx 2>/dev/null

    read -p "请输入域名: " domain
    [[ -z "$domain" ]] && return

    # ==============================================================
    # 1. 智能环境检测 (防止 CF 小黄云 & 自动识别 V4/V6)
    # ==============================================================
    echo -e "${YELLOW}>>> 正在进行 IP 匹配与环境检测...${PLAIN}"

    # 获取本机 IP
    local local_v4=$(curl -s4m5 https://api.ipify.org)
    local local_v6=$(curl -s6m5 https://api64.ipify.org)

    # 获取域名 IP (Google DNS API)
    local domain_v4=$(curl -sm5 "https://dns.google/resolve?name=${domain}&type=A" | jq -r '.Answer[]? | .data' | grep -E '^[0-9]+\.' | head -n 1)
    local domain_v6=$(curl -sm5 "https://dns.google/resolve?name=${domain}&type=AAAA" | jq -r '.Answer[]? | .data' | grep -E ':' | head -n 1)

    echo -e "${BLUE}    本机 IP: [V4] ${local_v4:-无}  [V6] ${local_v6:-无}${PLAIN}"
    echo -e "${BLUE}    域名 IP: [V4] ${domain_v4:-未解析}  [V6] ${domain_v6:-未解析}${PLAIN}"

    local acme_listen_arg=""
    local match_mode="none"

    # 比对逻辑
    if [[ -n "$local_v4" && "$local_v4" == "$domain_v4" ]]; then
        echo -e "${GREEN}>>> 检测到 IPv4 地址匹配，将使用标准模式。${PLAIN}"
        acme_listen_arg=""
        match_mode="v4"
    elif [[ -n "$local_v6" && "$local_v6" == "$domain_v6" ]]; then
        echo -e "${GREEN}>>> 检测到 IPv6 地址匹配，将启用 --listen-v6 模式。${PLAIN}"
        acme_listen_arg="--listen-v6"
        match_mode="v6"
    else
        echo -e "${RED}==========================================================${PLAIN}"
        echo -e "${RED} [错误] 域名解析 IP 与本机 IP 不一致！${PLAIN}"
        echo -e "${RED} 可能原因：1. 开启了 Cloudflare 小黄云 (CDN)；2. 解析填错。${PLAIN}"
        echo -e "${RED}==========================================================${PLAIN}"
        read -p "是否强制继续? (风险自担) [y/N]: " force_opt
        if [[ "$force_opt" == "y" || "$force_opt" == "Y" ]]; then
            echo -e "${YELLOW}>>> 已强制继续...${PLAIN}"
            # 如果本机没V4只有V6，强制给V6参数
            if [[ -z "$local_v4" && -n "$local_v6" ]]; then acme_listen_arg="--listen-v6"; fi
        else
            return 1
        fi
    fi

    # ==============================================================
    # 2. 执行 ACME 申请
    # ==============================================================
    curl https://get.acme.sh | sh
    ~/.acme.sh/acme.sh --register-account -m "admin@${domain}"

    local issue_success=false

    # 第一次尝试
    if ~/.acme.sh/acme.sh --issue -d "${domain}" --standalone $acme_listen_arg; then
        issue_success=true
    else
        echo -e "${RED}>>> 初次申请失败，正在检查是否可以重试...${PLAIN}"
        # 自动降级重试逻辑：如果原本是 V4 失败了，且机器有 V6，尝试 V6
        if [[ "$match_mode" == "v4" && -n "$local_v6" && "$local_v6" == "$domain_v6" ]]; then
            echo -e "${YELLOW}>>> 尝试切换到 IPv6 模式重试...${PLAIN}"
            if ~/.acme.sh/acme.sh --issue -d "${domain}" --standalone --listen-v6; then
                echo -e "${GREEN}>>> IPv6 模式重试成功！${PLAIN}"
                issue_success=true
            fi
        fi
    fi

    # 最终判断申请结果
    if [[ "$issue_success" == "false" ]]; then
        echo -e "${RED}>>> [错误] 证书申请彻底失败！请检查端口占用或防火墙。${PLAIN}"
        return 1
    fi

    # 安装证书
    ~/.acme.sh/acme.sh --installcert -d "${domain}" \
        --key-file "${SB_CERT_ACME}/private.key" \
        --fullchain-file "${SB_CERT_ACME}/cert.crt" \
        --reloadcmd "systemctl force-reload nginx"

    # 物理检查证书文件
    if [[ ! -s "${SB_CERT_ACME}/cert.crt" ]]; then
        echo -e "${RED}>>> [致命错误] 流程结束但未发现证书文件，申请失败。${PLAIN}"; return 1
    fi

    chmod 755 ${SB_CERT_ACME} && chmod 644 ${SB_CERT_ACME}/*
    echo "$domain" > "${SB_CERT_ACME}/domain_info.txt"

    # ==============================================================
    # 3. Nginx 伪装网站部署 (带 404 容错)
    # ==============================================================
    echo -e "${YELLOW}>>> 正在部署 Nginx 伪装站点...${PLAIN}"
    rm -rf /usr/share/nginx/html/*

    local templates=(
        "经典2048游戏|https://github.com/gabrielecirulli/2048/archive/refs/heads/master.zip"
        "3D粒子特效页|https://github.com/JulianLaval/canvas-particle-network/archive/refs/heads/master.zip"
        "黑客帝国数字雨|https://github.com/mineshpatel/Digital-Rain/archive/refs/heads/master.zip"
        "简约个人主页|https://github.com/StartBootstrap/startbootstrap-resume/archive/refs/heads/master.zip"
        "高仿大厂404页|https://github.com/0x00-0x00/fake404/archive/refs/heads/master.zip"
    )

    local index=$(($RANDOM % ${#templates[@]}))
    local selected="${templates[$index]}"
    local name="${selected%%|*}"
    local url="${selected##*|}"

    echo -e "${GREEN}>>> 🎲 尝试下载模板: [ ${name} ]${PLAIN}"

    local site_deployed=false

    # 尝试下载
    if wget --no-check-certificate -O /tmp/template.zip "$url"; then
        rm -rf /tmp/template_unzip
        mkdir -p /tmp/template_unzip
        if unzip -o /tmp/template.zip -d /tmp/template_unzip >/dev/null; then
             # 智能寻找 index.html
            local site_root=$(find /tmp/template_unzip -name "index.html" | head -n 1 | xargs dirname)
            if [[ -n "$site_root" ]]; then
                mv "$site_root"/* /usr/share/nginx/html/
                site_deployed=true
            fi
        fi
    fi

    # 如果下载失败/解压失败/找不到index，则写入保底页面
    if [[ "$site_deployed" == "false" ]]; then
        echo -e "${RED}>>> 模板下载或解压失败 (可能源已失效)，使用默认保底页面。${PLAIN}"
        cat > /usr/share/nginx/html/index.html <<EOF
<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body><h1>Site Under Construction</h1><p>Running on Nginx.</p></body>
</html>
EOF
    fi

    # 清理垃圾
    rm -rf /tmp/template.zip /tmp/template_unzip

    # ==============================================================
    # 4. 配置并启动 Nginx
    # ==============================================================
    cat > /etc/nginx/conf.d/singbox.conf <<EOF
server { listen 80; server_name ${domain}; return 301 https://\$host\$request_uri; }
server { listen 443 ssl http2; server_name ${domain}; root /usr/share/nginx/html; index index.html; ssl_certificate ${SB_CERT_ACME}/cert.crt; ssl_certificate_key ${SB_CERT_ACME}/private.key; ssl_protocols TLSv1.2 TLSv1.3; ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:!aNULL'; }
EOF
    rm -f /etc/nginx/sites-enabled/default

    echo -e "${YELLOW}>>> 正在启动 Nginx...${PLAIN}"
    systemctl restart nginx

    # 最终存活检查
    if systemctl is-active --quiet nginx; then
        echo -e "${GREEN}>>> ✅ 证书申请及 Nginx 部署成功！${PLAIN}"
        return 0
    else
        echo -e "${RED}>>> [错误] Nginx 启动失败！${PLAIN}"
        echo -e "${YELLOW}请运行 systemctl status nginx 查看原因 (通常是证书无效或端口占用)。${PLAIN}"
        return 1
    fi
}

switch_camouflage_site() {
    # 1. 环境检查
    if [[ ! -d "/usr/share/nginx/html" ]]; then
        echo -e "${RED}错误: 未检测到 Nginx 目录。请先执行选项 [1] 安装 Nginx。${PLAIN}"
        read -p "按回车返回..."
        return
    fi

    echo -e "${YELLOW}正在获取在线模板列表...${PLAIN}"

    # 2. 定义模板库 (格式: 显示名称|GitHub下载链接)
    local templates=(
        "经典 2048 游戏|https://github.com/gabrielecirulli/2048/archive/refs/heads/master.zip"
        "3D 粒子特效页 (极客风)|https://github.com/JulianLaval/canvas-particle-network/archive/refs/heads/master.zip"
        "黑客帝国 数字雨特效|https://github.com/mineshpatel/Digital-Rain/archive/refs/heads/master.zip"
        "简约 个人简历/主页|https://github.com/StartBootstrap/startbootstrap-resume/archive/refs/heads/master.zip"
        "高仿 微软/谷歌 404页|https://github.com/0x00-0x00/fake404/archive/refs/heads/master.zip"
        "简易 网站建设中|https://github.com/tmKamal/under-construction-template/archive/refs/heads/master.zip"
    )

    echo -e "===================================================="
    echo -e "           选择新的伪装站点风格"
    echo -e "===================================================="

    local i=1
    for item in "${templates[@]}"; do
        local name="${item%%|*}"
        echo -e "  $i. $name"
        let i++
    done
    echo -e "  R. 🎲 随机抽取一个"
    echo -e "  0. 取消操作"
    echo -e "===================================================="
    read -p "请选择 [1-$((${#templates[@]}))/R]: " choice

    local url=""
    local selected_name=""

    if [[ "$choice" == "0" ]]; then return; fi

    if [[ "$choice" == "r" || "$choice" == "R" ]]; then
        local idx=$(($RANDOM % ${#templates[@]}))
        local selected="${templates[$idx]}"
        selected_name="${selected%%|*}"
        url="${selected##*|}"
        echo -e "${YELLOW}>>> 随机命中: ${GREEN}${selected_name}${PLAIN}"
    elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#templates[@]} ]; then
        local idx=$(($choice - 1))
        local selected="${templates[$idx]}"
        selected_name="${selected%%|*}"
        url="${selected##*|}"
        echo -e "${YELLOW}>>> 你选择了: ${GREEN}${selected_name}${PLAIN}"
    else
        echo -e "${RED}输入无效！${PLAIN}"; sleep 1; return
    fi

    # 3. 下载与部署
    echo -e "${YELLOW}>>> 正在清理旧文件...${PLAIN}"
    rm -rf /usr/share/nginx/html/*

    echo -e "${YELLOW}>>> 正在下载资源...${PLAIN}"
    # 增加 --no-check-certificate 增加下载成功率
    wget --no-check-certificate -O /tmp/template.zip "$url"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}下载失败！请检查网络。${PLAIN}"
        rm -f /tmp/template.zip
        read -p "按回车返回..."
        return
    fi

    echo -e "${YELLOW}>>> 正在解压部署...${PLAIN}"
    rm -rf /tmp/template_unzip
    mkdir -p /tmp/template_unzip
    unzip -o /tmp/template.zip -d /tmp/template_unzip >/dev/null

    # [核心修复] 智能寻找入口文件
    local entry_point=$(find /tmp/template_unzip -type f \( -name "index.html" -o -name "demo.html" -o -name "home.html" -o -name "main.html" \) | head -n 1)

    if [[ -n "$entry_point" ]]; then
        local site_root=$(dirname "$entry_point")
        local main_file=$(basename "$entry_point")

        # 移动文件到 Nginx 目录
        mv "$site_root"/* /usr/share/nginx/html/

        # [关键步骤] 如果主文件不叫 index.html，强制重命名为 index.html
        if [[ "$main_file" != "index.html" ]]; then
            echo -e "${YELLOW}>>> 检测到入口文件为 ${main_file}，正在重命名为 index.html...${PLAIN}"
            mv "/usr/share/nginx/html/$main_file" "/usr/share/nginx/html/index.html"
        fi

        # 权限修正
        chown -R www-data:www-data /usr/share/nginx/html 2>/dev/null
        chmod -R 755 /usr/share/nginx/html

        echo -e "${GREEN}✅ 伪装站点更换成功！立即生效。${PLAIN}"
        echo -e "${GREEN}你可以访问你的域名查看效果。${PLAIN}"
    else
        echo -e "${RED}错误: 压缩包中未找到网页文件(index/demo.html)，部署失败。${PLAIN}"
    fi

    # 清理缓存
    rm -rf /tmp/template.zip /tmp/template_unzip
    read -p "按回车返回..."
}

# --- 5. 协议配置核心逻辑 ---

check_brutal() { if lsmod | grep -q "brutal"; then echo "tcp_brutal" > /etc/modules-load.d/tcp_brutal.conf; return 0; else return 1; fi }

# [核心辅助] 智能获取 SNI (支持参数 "big" 强制优选)
get_smart_sni() {
    local force_mode=$1
    mkdir -p ${SB_CERT_SELF}
    local cache_file="${SB_CERT_SELF}/sni_cache.txt"
    local final_sni=""

    # 1. 缓存读取
    if [[ -f "$cache_file" ]]; then
        local cached_sni=$(cat "$cache_file")
        if [[ -n "$cached_sni" ]]; then
            echo -e "${YELLOW}>>> 检测到已保存的伪装域名 (SNI): ${GREEN}${cached_sni}${PLAIN}" >&2
            read -p "是否直接使用此域名? [Y/n] (默认: 是): " use_cache >&2
            if [[ -z "$use_cache" ]] || [[ "$use_cache" =~ ^[Yy]$ ]]; then echo "$cached_sni"; return; fi
            echo -e "${YELLOW}>>> 即将重新配置 SNI...${PLAIN}" >&2
        fi
    fi

    local sni_opt=""
    # 2. 模式判断: 如果传入 "big"，则强制锁定选项 1，不再询问
    if [[ "$force_mode" == "big" ]]; then
        sni_opt="1"
    else
        echo -e "${YELLOW}请选择 目标域名 (SNI) 来源:${PLAIN}" >&2
        echo -e "  1. 优选大厂域名 (Microsoft/Apple/AMD/Bing 或自定义等)" >&2
        echo -e "  2. 自己的域名" >&2
        read -p "请选择 [1-2]: " sni_opt >&2
    fi

    # 3. 执行选择
    if [[ "$sni_opt" == "1" ]]; then
        local domains=("www.microsoft.com" "www.apple.com" "www.amazon.com" "www.speedtest.net" "www.amd.com" "www.bing.com")
        local best_domain=""; local min_time=9999
        echo -e ">>> 正在优选大厂域名..." >&2
        for d in "${domains[@]}"; do
            local t=$(curl -o /dev/null -s -w "%{time_connect}" --connect-timeout 2 "https://$d")
            if [[ -n "$t" ]]; then
                local t_ms=$(awk "BEGIN {print int($t*1000)}"); echo -e "$d : ${t_ms}ms" >&2
                if (( t_ms < min_time )); then min_time=$t_ms; best_domain=$d; fi
            else echo -e "$d : 超时" >&2; fi
        done
        [[ -z "$best_domain" ]] && best_domain="www.microsoft.com"
        echo -e "${GREEN}优选结果: ${best_domain}${PLAIN}" >&2
        read -p "确认使用? [回车默认 / 输入其他]: " confirm_sni >&2
        [[ -n "$confirm_sni" ]] && final_sni="$confirm_sni" || final_sni=$best_domain
    else
        read -p "请输入域名 (例如 www.bing.com): " user_sni >&2
        [[ -z "$user_sni" ]] && user_sni="www.microsoft.com"; final_sni=$user_sni
    fi
    echo "$final_sni" > "$cache_file"
    echo "$final_sni"
}

# [核心辅助] 智能获取自签证书 (支持参数: "big" 强制优选)
get_smart_self_cert() {
    local force_mode=$1
    local crt="${SB_CERT_SELF}/self.crt"; local key="${SB_CERT_SELF}/self.key"

    # 1. 如果证书已存在，直接返回
    if [[ -f "$crt" && -f "$key" ]]; then return 0; fi

    echo -e "${YELLOW}>>> 未检测到自签证书，正在自动生成...${PLAIN}"
    mkdir -p ${SB_CERT_SELF}

    # [修改点] 将接收到的 force_mode (例如 "big") 传递给 get_smart_sni
    local sni=$(get_smart_sni "$force_mode")

    openssl req -x509 -newkey rsa:2048 -keyout "$key" -out "$crt" -days 3650 -nodes -subj "/CN=${sni}" >/dev/null 2>&1
    if [[ -f "$crt" ]]; then echo -e "${GREEN}>>> 自签证书生成完毕 (Common Name: ${sni})${PLAIN}"; else echo -e "${RED}自签证书生成失败！${PLAIN}"; return 1; fi
}

# [核心辅助] 智能获取 ACME 证书
get_smart_acme_cert() {
    local crt="${SB_CERT_ACME}/cert.crt"
    local key="${SB_CERT_ACME}/private.key"
    local info="${SB_CERT_ACME}/domain_info.txt"

    # 1. 严谨检查：文件是否存在？是否为空文件？
    # -s 表示文件存在且大小 > 0
    if [[ -s "$crt" && -s "$key" && -f "$info" ]]; then
        # 证书看起来是好的，直接返回成功
        return 0
    fi

    # 2. 如果文件缺失或为空，进入申请流程
    echo -e "${RED}>>> 未检测到有效的域名证书 (文件缺失或为空)！${PLAIN}"
    echo -e "${YELLOW}>>> 系统将自动跳转至 [证书申请] 模块...${PLAIN}"

    # 调用申请函数 (这里会使用之前修复过的 install_nginx_cert_standalone)
    install_nginx_cert_standalone
    local ret=$?

    # 3. 再次复查：申请完了，到底有没有文件？
    if [[ $ret -ne 0 ]] || [[ ! -s "$crt" ]]; then
        echo -e "${RED}[错误] 证书申请流程失败，无法满足 ACME 模式要求。${PLAIN}"
        return 1 # 返回 1 (失败)，这将触发 add_vless 等函数的自动降级
    fi

    echo -e "${GREEN}>>> 证书申请成功！正在返回协议配置...${PLAIN}"
    sleep 1
    return 0
}

menu_protocol() {
    clear
    local ver="0"; if [ -f ${SB_BIN} ]; then ver=$(${SB_BIN} version | head -n1 | awk '{print $3}'); fi
    echo -e "===================================================="
    echo -e "           Sing-box 协议配置向导 [Smart]"
    echo -e "===================================================="
    echo -e "  核心已安装。请选择要部署的主流协议："
    echo -e "----------------------------------------------------"
    echo -e "  1. VLESS (Vision / Brutal)"
    echo -e "  2. Hysteria 2"
    echo -e "  3. TUIC v5"
    if version_ge "${ver#v}" "1.12"; then echo -e "  4. AnyTLS"; else echo -e "  4. AnyTLS ${GRAY}(需 v1.12+)${PLAIN}"; fi
    echo -e "  5. Shadowsocks-2022"
    echo -e "  6. 自定义 JSON 配置"
    echo -e "  0. 返回上一级"
    echo -e "===================================================="
    read -p " 请输入数字 [0-6]: " p_opt

    case "$p_opt" in
        1)
            add_vless
            menu_protocol # <--- 添加完 VLESS 后，回到协议菜单
            ;;
        2)
            add_hysteria2
            menu_protocol # <--- 添加完 Hy2 后，回到协议菜单
            ;;
        3)
            add_tuic
            menu_protocol # <--- 添加完 TUIC 后，回到协议菜单
            ;;
        4)
            if version_ge "${ver#v}" "1.12"; then
                echo -e "1. TLS 模式  2. Reality 模式"
                read -p "-> " m
                [[ "$m" == "1" ]] && add_anytls "tls"
                [[ "$m" == "2" ]] && add_anytls "reality"
            else
                echo "版本不足"; sleep 1
            fi
            menu_protocol # <--- 回到协议菜单
            ;;
        5)
            add_ss2022
            menu_protocol # <--- 回到协议菜单
            ;;
        6)
            nano_custom_json
            menu_protocol # <--- 回到协议菜单
            ;;
        0) return ;; # <--- 只有这里回主菜单
        *) echo -e "${RED}输入错误${PLAIN}"; sleep 1; menu_protocol ;;
    esac
}

add_vless() {
    # 1. 选择流控模式
    echo -e "${YELLOW}请选择 VLESS 流控模式:${PLAIN}"
    echo -e "  1. Vision (抗封锁能力强，推荐)"
    echo -e "  2. Brutal (TCP 暴力发包，速度快)"
    read -p "-> " flow_opt

    local flow_type="vision"
    local is_brutal=0
    if [[ "$flow_opt" == "2" ]]; then
        if check_brutal; then
            echo -e "${GREEN}[检测] Brutal 模块可用。${PLAIN}"
            flow_type="brutal"
            is_brutal=1
        else
            echo -e "${RED}无 Brutal 模块，强制降级为 Vision。${PLAIN}"
        fi
    fi

    # 2. 选择 Reality 伪装目标 (SNI)
    echo -e "${YELLOW}请选择 Reality 伪装域名 (SNI):${PLAIN}"
    echo -e "  1. 偷大厂域名 (Microsoft/Apple 等，无需本地环境)"
    echo -e "  2. 使用自己的域名 (Reality 协议 + 本地 Nginx/证书伪装)"
    read -p "-> " cert_opt

    # 强制标记为 self (确保最终生成的是 Reality 结构)
    local cert_mode="self"
    local sni=""

    if [[ "$cert_opt" == "2" ]]; then
        # === 核心逻辑：Reality + 自建域名 (带环境检查) ===
        local info_file="${SB_CERT_ACME}/domain_info.txt"
        local cert_file="${SB_CERT_ACME}/cert.crt"
        local key_file="${SB_CERT_ACME}/private.key"

        # 检查逻辑：域名文件存在 且 证书文件大小大于0
        if [[ -s "$info_file" && -s "$cert_file" && -s "$key_file" ]]; then
            # --- 环境齐全 ---
            sni=$(cat "$info_file")
            echo -e "${GREEN}>>> [环境检查] 检测到 Nginx/证书 环境正常。${PLAIN}"
            echo -e "${GREEN}>>> [Reality] 将使用现有域名作为伪装: ${sni}${PLAIN}"
        else
            # --- 环境缺失 ---
            echo -e "${YELLOW}>>> [环境检查] 未检测到有效的域名证书/Nginx 环境。${PLAIN}"
            echo -e "${YELLOW}>>> 根据要求，正在跳转至 [证书申请 & Nginx部署] 流程...${PLAIN}"
            sleep 2

            # 调用申请函数 (申请证书 + 装 Nginx)
            install_nginx_cert_standalone

            # 申请完再次检查
            if [[ -s "$info_file" && -s "$cert_file" ]]; then
                sni=$(cat "$info_file")
                echo -e "${GREEN}>>> [环境部署] 成功！${PLAIN}"
                echo -e "${GREEN}>>> [Reality] 将使用新申请的域名作为伪装: ${sni}${PLAIN}"
            else
                echo -e "${RED}>>> [错误] 证书申请失败或中断，无法继续配置 Reality。${PLAIN}"
                read -p "按回车返回..."
                return
            fi
        fi
    else
        # === 选项1：自动大厂 SNI ===
        sni=$(get_smart_sni "big")
    fi

    local final_tag="vless-${flow_type}-reality"
    local filename="10_vless_${flow_type}_reality.json"
    rm -f "${SB_SERVER}/${filename}" "${SB_CLIENT}/${filename}"

    echo -e "${YELLOW}>>> 正在配置: ${GREEN}${final_tag}${PLAIN} ..."

    # 端口选择
    local port=$(get_safe_port "VLESS端口" $(shuf -i 20000-50000 -n 1))

    local uuid=$(/usr/bin/sing-box generate uuid)
    local flow="xtls-rprx-vision"
    if [[ "$is_brutal" == "1" ]]; then flow=""; fi

    # [Brutal 参数补全]
    local mux='{"enabled": false}'
    local cmux
    if [[ "$is_brutal" == "1" ]]; then
        read -p "VPS上传(Mbps): " vu; [[ -z "$vu" ]] && vu=1000; read -p "VPS下载(Mbps): " vd; [[ -z "$vd" ]] && vd=1000
        read -p "本地上传(Mbps): " lu; [[ -z "$lu" ]] && lu=100; read -p "本地下载(Mbps): " ld; [[ -z "$ld" ]] && ld=500

        # 服务端
        mux='{"enabled": true, "padding": true, "brutal": {"enabled": true, "up_mbps": '$vu', "down_mbps": '$vd'}}'

        # 客户端 (补全 max_connections, min_streams)
        cmux='{"enabled": true, "protocol": "smux", "max_connections": 1, "min_streams": 4, "padding": true, "brutal": {"enabled": true, "up_mbps": '$lu', "down_mbps": '$ld'}}'
    fi

    # === 生成 Reality 密钥对 (关键步骤) ===
    # 即使本地有 cert.crt，Reality 也不用它，而是用生成的 Key
    local keys=$(/usr/bin/sing-box generate reality-keypair)
    local pk=$(echo "$keys" | grep "Public" | awk -F ": " '{print $2}')
    local sk=$(echo "$keys" | grep "Private" | awk -F ": " '{print $2}')
    local short_id=$(/usr/bin/sing-box generate rand --hex 8)

    # 构建 Reality JSON
    # 注意：这里 server_name 填的是你的 ACME 域名，但协议是 reality (private_key)
    local tls_server_json='"tls": { "enabled": true, "server_name": "'$sni'", "reality": { "enabled": true, "handshake": {"server": "'$sni'", "server_port": 443}, "private_key": "'$sk'", "short_id": ["'$short_id'"] } }'

    local tls_client_json='"tls": { "enabled": true, "server_name": "'$sni'", "utls": {"enabled": true, "fingerprint": "chrome"}, "reality": {"enabled": true, "public_key": "'$pk'", "short_id": "'$short_id'"} }'

    # 写入服务端配置
    cat > ${SB_SERVER}/${filename} <<EOF
{ "inbounds": [{ "type": "vless", "tag": "${final_tag}", "listen": "::", "listen_port": ${port}, "users": [{"uuid": "${uuid}", "flow": "${flow}"}], ${tls_server_json}, "multiplex": ${mux} }] }
EOF

    # 获取真实 IP
    local server_ip=$(get_final_server_ip)
    echo -e "${GREEN}>>> 锁定客户端连接 IP: ${server_ip}${PLAIN}"

    # 写入客户端配置
    local client_tpl="{ \"type\": \"vless\", \"tag\": \"${final_tag}\", \"server\": \"${server_ip}\", \"server_port\": ${port}, \"uuid\": \"${uuid}\", \"flow\": \"${flow}\", \"packet_encoding\": \"xudp\", ${tls_client_json}"
    if [[ "$is_brutal" == "1" ]]; then client_tpl="${client_tpl}, \"multiplex\": ${cmux} }"; else client_tpl="${client_tpl} }"; fi
    echo "$client_tpl" > ${SB_CLIENT}/${filename}

    format_json ${SB_SERVER}/${filename}; format_json ${SB_CLIENT}/${filename}; update_route_rules; apply_changes
}

add_hysteria2() {
    echo -e "${YELLOW}请选择证书类型:${PLAIN}"
    echo -e "  1. 自签证书 (自动生成 / 偷大厂 SNI)"
    echo -e "  2. 域名证书 (申请证书 + Nginx)"
    read -p "-> " cert_opt

    local cert_mode="self"; if [[ "$cert_opt" == "2" ]]; then cert_mode="acme"; fi

    if [[ "$cert_mode" == "acme" ]]; then
        if ! get_smart_acme_cert; then
            echo -e "${RED}>>> ⚠️ 域名证书申请失败，自动降级为自签证书模式${PLAIN}"; sleep 2; cert_mode="self"
        fi
    fi

    local sni cpath kpath insecure
    if [[ "$cert_mode" == "acme" ]]; then
        cpath="${SB_CERT_ACME}/cert.crt"; kpath="${SB_CERT_ACME}/private.key"; insecure="false"; sni=$(cat "${SB_CERT_ACME}/domain_info.txt")
    else
        get_smart_self_cert "big"; cpath="${SB_CERT_SELF}/self.crt"; kpath="${SB_CERT_SELF}/self.key"; insecure="true"; sni=$(cat "${SB_CERT_SELF}/sni_cache.txt")
    fi

    local filename="20_hysteria2_${cert_mode}.json"
    if [[ -f "${SB_SERVER}/${filename}" ]]; then echo -e "${YELLOW}[警告] 覆盖配置。${PLAIN}"; read -p "继续..."; fi

    local port=$(get_safe_port "Hy2主端口 (监听)" $(shuf -i 30000-40000 -n 1))
    echo -e "请输入端口跳跃范围 (例如 20000:50000) [回车不开启]:"; read hop_range
    local password=$(openssl rand -base64 16)

    if [[ -n "$hop_range" ]]; then
        echo -e "${YELLOW}>>> 正在配置系统级端口转发 (iptables)...${PLAIN}"
        local clean_range=$(echo $hop_range | tr '-' ':'); local start_port=$(echo $clean_range | cut -d':' -f1); local end_port=$(echo $clean_range | cut -d':' -f2)
        if command -v iptables >/dev/null; then
            iptables -t nat -D PREROUTING -p udp --dport $start_port:$end_port -j REDIRECT --to-ports $port 2>/dev/null
            iptables -t nat -A PREROUTING -p udp --dport $start_port:$end_port -j REDIRECT --to-ports $port
            if [[ -f /etc/redhat-release ]]; then service iptables save 2>/dev/null; fi
            if command -v netfilter-persistent >/dev/null; then netfilter-persistent save 2>/dev/null; fi
            echo -e "${GREEN}✅ 服务端 iptables 转发已生效: $clean_range -> $port${PLAIN}"
        fi
    fi

    cat > ${SB_SERVER}/${filename} <<EOF
{ "inbounds": [{ "type": "hysteria2", "tag": "hy2-${cert_mode}", "listen": "::", "listen_port": ${port}, "users": [{"password": "${password}", "name": "user"}], "tls": { "enabled": true, "certificate_path": "${cpath}", "key_path": "${kpath}", "alpn": ["h3"] }, "ignore_client_bandwidth": true }] }
EOF

    # [核心修改] 获取真实 IP
    local server_ip=$(get_final_server_ip)

    cat > ${SB_CLIENT}/${filename} <<EOF
{ "type": "hysteria2", "tag": "hy2-${cert_mode}", "server": "${server_ip}", "server_port": ${port}, "password": "${password}", "tls": { "enabled": true, "server_name": "${sni}", "insecure": ${insecure}, "alpn": ["h3"] } }
EOF

    format_json ${SB_SERVER}/${filename}; format_json ${SB_CLIENT}/${filename}; update_route_rules; apply_changes
}

add_tuic() {
    echo -e "${YELLOW}请选择证书类型:${PLAIN}"
    echo -e "  1. 自签证书 (自动生成)"; echo -e "  2. 域名证书 (申请证书+Nginx)"
    read -p "-> " cert_opt

    local cert_mode="self"; if [[ "$cert_opt" == "2" ]]; then cert_mode="acme"; fi

    if [[ "$cert_mode" == "acme" ]]; then
        if ! get_smart_acme_cert; then
            echo -e "${RED}>>> ⚠️ 域名证书申请失败，自动降级为自签证书模式${PLAIN}"; sleep 2; cert_mode="self"
        fi
    fi

    local sni cpath kpath insecure
    if [[ "$cert_mode" == "acme" ]]; then
        cpath="${SB_CERT_ACME}/cert.crt"; kpath="${SB_CERT_ACME}/private.key"; insecure="false"; sni=$(cat "${SB_CERT_ACME}/domain_info.txt")
    else
        get_smart_self_cert "big"; cpath="${SB_CERT_SELF}/self.crt"; kpath="${SB_CERT_SELF}/self.key"; insecure="true"; sni=$(cat "${SB_CERT_SELF}/sni_cache.txt")
    fi

    local filename="30_tuic_${cert_mode}.json"
    if [[ -f "${SB_SERVER}/${filename}" ]]; then echo -e "${YELLOW}[警告] 覆盖配置。${PLAIN}"; read -p "继续..."; fi

    local port=$(get_safe_port "TUIC主端口 (实际监听)" $(shuf -i 30000-40000 -n 1))
    echo -e "请输入端口跳跃范围 (例如 20000-50000) [回车不开启]:"; read hop_range
    local password=$(openssl rand -base64 16); local t_uuid=$(/usr/bin/sing-box generate uuid)

    if [[ -n "$hop_range" ]]; then
        local start_port=$(echo $hop_range | cut -d'-' -f1); local end_port=$(echo $hop_range | cut -d'-' -f2)
        if command -v iptables >/dev/null; then
            iptables -t nat -D PREROUTING -p udp --dport $start_port:$end_port -j REDIRECT --to-ports $port 2>/dev/null
            iptables -t nat -A PREROUTING -p udp --dport $start_port:$end_port -j REDIRECT --to-ports $port
            echo -e "${GREEN}✅ 端口跳跃已生效: $hop_range -> $port${PLAIN}"
        fi
    fi

    cat > ${SB_SERVER}/${filename} <<EOF
{ "inbounds": [{ "type": "tuic", "tag": "tuic-${cert_mode}", "listen": "::", "listen_port": ${port}, "users": [{"uuid": "${t_uuid}", "password": "${password}", "name": "user"}], "tls": { "enabled": true, "certificate_path": "${cpath}", "key_path": "${kpath}", "alpn": ["h3"] }, "congestion_control": "bbr", "zero_rtt_handshake": true }] }
EOF

    # [核心修改] 获取真实 IP
    local server_ip=$(get_final_server_ip)

    cat > ${SB_CLIENT}/${filename} <<EOF
{ "type": "tuic", "tag": "tuic-${cert_mode}", "server": "${server_ip}", "server_port": ${port}, "uuid": "${t_uuid}", "password": "${password}", "congestion_control": "bbr", "zero_rtt_handshake": true, "udp_over_stream": false, "tls": { "enabled": true, "server_name": "${sni}", "insecure": ${insecure}, "alpn": ["h3"] } }
EOF

    format_json ${SB_SERVER}/${filename}; format_json ${SB_CLIENT}/${filename}; update_route_rules; apply_changes
}

add_anytls() {
    local slot_type=$1; local filename="40_anytls_${slot_type}.json"
    if [[ -f "${SB_SERVER}/${filename}" ]]; then echo -e "${YELLOW}[提示] 将覆盖现有的 ${slot_type} 配置...${PLAIN}"; fi
    local port=$(get_safe_port "AnyTLS端口" $(shuf -i 20000-50000 -n 1)); local pwd=$(openssl rand -base64 16)
    local sni cpath kpath insecure

    if [[ "$slot_type" == "tls" ]]; then
        echo -e "${YELLOW}请选择证书类型:${PLAIN}"; echo -e "  1. 自签证书"; echo -e "  2. 域名证书"; read -p "-> " cert_opt
        local use_acme=false; if [[ "$cert_opt" == "2" ]]; then use_acme=true; fi
        if [[ "$use_acme" == "true" ]]; then
            if ! get_smart_acme_cert; then
                echo -e "${RED}>>> ⚠️ 域名证书申请失败，自动降级为自签证书${PLAIN}"; sleep 2; use_acme=false
            fi
        fi
        if [[ "$use_acme" == "true" ]]; then
             cpath="${SB_CERT_ACME}/cert.crt"; kpath="${SB_CERT_ACME}/private.key"; insecure="false"; sni=$(cat "${SB_CERT_ACME}/domain_info.txt")
        else
             get_smart_self_cert "big"; cpath="${SB_CERT_SELF}/self.crt"; kpath="${SB_CERT_SELF}/self.key"; insecure="true"; sni=$(cat "${SB_CERT_SELF}/sni_cache.txt")
        fi
        local tls_server='"tls": { "enabled": true, "certificate_path": "'$cpath'", "key_path": "'$kpath'" }'
        local tls_client='"tls": { "enabled": true, "server_name": "'$sni'", "insecure": '$insecure', "utls": { "enabled": true, "fingerprint": "chrome" } }'

    else
        echo -e "${YELLOW}请选择 Reality 伪装目标:${PLAIN}"; echo -e "  1. 偷大厂域名"; echo -e "  2. 自己的域名"; read -p "-> " reality_opt
        local use_real_cert=false; if [[ "$reality_opt" == "2" ]]; then use_real_cert=true; fi
        if [[ "$use_real_cert" == "true" ]]; then
             if ! get_smart_acme_cert; then
                echo -e "${RED}>>> ⚠️ 域名证书申请失败，自动降级为偷大厂域名${PLAIN}"; sleep 2; use_real_cert=false
             fi
        fi
        if [[ "$use_real_cert" == "true" ]]; then
             sni=$(cat "${SB_CERT_ACME}/domain_info.txt"); echo "$sni" > "${SB_CERT_SELF}/sni_cache.txt"
        else
             sni=$(get_smart_sni "big")
        fi
        local keys=$(/usr/bin/sing-box generate reality-keypair)
        local sk=$(echo "$keys" | grep "Private" | awk -F ": " '{print $2}')
        local pk=$(echo "$keys" | grep "Public" | awk -F ": " '{print $2}')
        local sid=$(/usr/bin/sing-box generate rand --hex 8)
        local tls_server='"tls": { "enabled": true, "server_name": "'$sni'", "reality": { "enabled": true, "handshake": {"server": "'$sni'", "server_port": 443}, "private_key": "'$sk'", "short_id": ["'$sid'"] } }'
        local tls_client='"tls": { "enabled": true, "server_name": "'$sni'", "utls": {"enabled": true, "fingerprint": "chrome"}, "reality": {"enabled": true, "public_key": "'$pk'", "short_id": "'$sid'"} }'
    fi

    cat > ${SB_SERVER}/${filename} <<EOF
{ "inbounds": [ { "type": "anytls", "tag": "anytls-${slot_type}", "listen": "::", "listen_port": ${port}, "users": [ { "name": "user", "password": "${pwd}" } ], "padding_scheme": [ "stop=8", "0=30-30", "1=100-400" ], ${tls_server} } ] }
EOF

    # [核心修改] 获取真实 IP
    local server_ip=$(get_final_server_ip)

    cat > ${SB_CLIENT}/${filename} <<EOF
{ "type": "anytls", "tag": "anytls-${slot_type}", "server": "${server_ip}", "server_port": ${port}, "password": "${pwd}", "idle_session_check_interval": "30s", "idle_session_timeout": "30s", "min_idle_session": 5, ${tls_client} }
EOF

    format_json ${SB_SERVER}/${filename}; format_json ${SB_CLIENT}/${filename}; update_route_rules; apply_changes
}

add_ss2022() {
    local filename="50_shadowsocks.json"
    if [[ -f "${SB_SERVER}/${filename}" ]]; then echo -e "${YELLOW}[警告] 覆盖 SS 配置。${PLAIN}"; read -p "继续..."; fi
    local port=$(get_safe_port "SS端口" $(shuf -i 20000-50000 -n 1)); local password=$(openssl rand -base64 16)

    cat > ${SB_SERVER}/${filename} <<EOF
{ "inbounds": [{ "type": "shadowsocks", "tag": "ss-in", "listen": "::", "listen_port": ${port}, "method": "2022-blake3-aes-128-gcm", "password": "${password}", "multiplex": {"enabled": false} }] }
EOF

    # [核心修改] 获取真实 IP
    local server_ip=$(get_final_server_ip)
    echo -e "${GREEN}>>> 锁定客户端连接 IP: ${server_ip}${PLAIN}"

    cat > ${SB_CLIENT}/${filename} <<EOF
{ "type": "shadowsocks", "tag": "ss-out", "server": "${server_ip}", "server_port": ${port}, "method": "2022-blake3-aes-128-gcm", "password": "${password}", }
EOF
    format_json ${SB_SERVER}/${filename}; format_json ${SB_CLIENT}/${filename}; update_route_rules; apply_changes
}

# ==============================================================================
# Realm 模块修复版 (Fix by Gemini)
# ==============================================================================

menu_realm() {
    clear
    # --- 1. 安装/检查逻辑 (保持不变) ---
    if [[ ! -f "/usr/local/bin/realm" ]]; then
        echo -e "${YELLOW}检测到未安装 Realm，正在自动安装...${PLAIN}"

        local arch=$(uname -m)
        local realm_filename=""
        case "$arch" in
            x86_64|amd64) realm_filename="realm-x86_64-unknown-linux-gnu.tar.gz" ;;
            aarch64|arm64) realm_filename="realm-aarch64-unknown-linux-gnu.tar.gz" ;;
            *) echo -e "${RED}致命错误: 不支持的架构 $arch${PLAIN}"; read -p "按回车返回..."; return ;;
        esac

        local download_url="https://github.com/zhboner/realm/releases/latest/download/${realm_filename}"
        wget -O /tmp/realm.tar.gz "$download_url"
        if [[ $? -ne 0 ]]; then echo -e "${RED}下载失败，请检查网络。${PLAIN}"; rm -f /tmp/realm.tar.gz; read -p "回车..."; return; fi

        cd /tmp && tar -xvf realm.tar.gz
        mv realm /usr/local/bin/realm
        chmod +x /usr/local/bin/realm
        rm -f realm.tar.gz

        cat > /etc/systemd/system/realm.service <<EOF
[Unit]
Description=realm
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/realm -c ${REALM_ROOT}/config.toml

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        mkdir -p ${REALM_ROOT}
        echo -e "${GREEN}Realm 安装完成！${PLAIN}"
        sleep 2
    fi

    # --- 2. 菜单逻辑 ---
    echo -e "===================================================="
    echo -e "           Realm 端口转发 (双栈修复版)"
    echo -e "===================================================="
    if systemctl is-active --quiet realm; then
        echo -e "    状态: ${GREEN}运行中${PLAIN}"
    else
        echo -e "    状态: ${RED}未运行${PLAIN}"
    fi
    echo -e "----------------------------------------------------"
    echo -e "  1. 添加 转发规则"
    echo -e "  2. 删除 转发规则 (指定/全部)"
    echo -e "  3. 查看 当前规则"
    echo -e "  4. 重启 Realm 服务"
    echo -e "  5. 卸载 Realm"
    echo -e "  0. 返回上一级"
    echo -e "===================================================="
    read -p " 请输入数字 [0-5]: " r_opt

    case "$r_opt" in
        1)
            echo -e "${YELLOW}提示: 本地监听将使用 [::]，同时支持 IPv4 和 IPv6 连入${PLAIN}"
            read -p "请输入本地监听端口: " lp
            read -p "请输入目标地址 (IP或域名): " ra
            read -p "请输入目标端口: " rp

            [[ -z "$lp" || -z "$ra" || -z "$rp" ]] && echo -e "${RED}输入不能为空${PLAIN}" && return

            if [[ "$ra" == *":"* && "$ra" != *"["* && "$ra" != *".com"* && "$ra" != *".net"* ]]; then
                ra="[${ra}]"
                echo -e "${YELLOW}检测到 IPv6 地址，已自动添加括号修正为: ${ra}${PLAIN}"
            fi

            echo "${lp}|${ra}|${rp}" >> ${REALM_ROOT}/rules.db
            update_realm
            echo -e "${GREEN}规则添加成功并已生效！${PLAIN}"
            read -p "按回车继续..."
            ;;
        2)
            # --- 删除逻辑升级版 ---
            if [[ ! -s "${REALM_ROOT}/rules.db" ]]; then
                echo -e "${RED}当前没有规则可删除。${PLAIN}"
                read -p "按回车返回..."
                menu_realm
                return
            fi

            echo -e "${YELLOW}当前规则列表:${PLAIN}"
            echo -e "---------------------------------------------------------"
            printf "%-4s %-10s %-30s %-10s\n" "ID" "本地端口" "目标地址" "目标端口"
            echo -e "---------------------------------------------------------"

            # 使用 awk 打印带行号的列表
            local i=1
            while IFS='|' read -r lp ra rp; do
                printf "%-4s %-10s %-30s %-10s\n" "$i" "$lp" "$ra" "$rp"
                let i++
            done < ${REALM_ROOT}/rules.db

            echo -e "---------------------------------------------------------"
            echo -e "提示: 输入 ${GREEN}数字ID${PLAIN} 删除单条，输入 ${RED}all${PLAIN} 删除全部，输入 ${GREEN}0${PLAIN} 取消"
            read -p "请输入操作: " del_opt

            if [[ "$del_opt" == "0" ]]; then
                menu_realm
                return
            elif [[ "$del_opt" == "all" ]]; then
                read -p "确认清空所有规则? [y/N]: " confirm
                if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                    rm -f ${REALM_ROOT}/rules.db
                    update_realm
                    echo -e "${GREEN}已清空所有规则。${PLAIN}"
                else
                    echo "已取消。"
                fi
            elif [[ "$del_opt" =~ ^[0-9]+$ ]]; then
                # 检查输入的数字是否超出范围
                local total_lines=$(wc -l < ${REALM_ROOT}/rules.db)
                if [[ "$del_opt" -gt "$total_lines" || "$del_opt" -lt 1 ]]; then
                    echo -e "${RED}无效的 ID。${PLAIN}"
                else
                    # 使用 sed 删除指定行
                    sed -i "${del_opt}d" ${REALM_ROOT}/rules.db
                    update_realm
                    echo -e "${GREEN}规则 ID: ${del_opt} 已删除。${PLAIN}"
                fi
            else
                echo -e "${RED}输入无效。${PLAIN}"
            fi
            read -p "按回车继续..."
            ;;
        3)
            echo -e "${YELLOW}--- 当前转发列表 ---${PLAIN}"
            if [[ -s "${REALM_ROOT}/rules.db" ]]; then
                printf "%-10s %-30s %-10s\n" "本地端口" "目标地址" "目标端口"
                echo "------------------------------------------------------"
                while IFS='|' read -r lp ra rp; do
                    printf "%-10s %-30s %-10s\n" "$lp" "$ra" "$rp"
                done < ${REALM_ROOT}/rules.db
            else
                echo "暂无规则"
            fi
            echo -e "------------------------------------"
            read -p "按回车返回..."
            ;;
        4)
            systemctl restart realm
            echo -e "${GREEN}服务已重启${PLAIN}"
            sleep 1
            ;;
        5)
            systemctl stop realm
            systemctl disable realm
            rm -f /etc/systemd/system/realm.service /usr/local/bin/realm
            systemctl daemon-reload
            echo -e "${GREEN}Realm 已卸载${PLAIN}"
            sleep 1
            ;;
        0) return ;;
        *) echo -e "${RED}输入错误${PLAIN}" ;;
    esac
    menu_realm
}

update_realm() {
    # 写入基础配置
    # 注意：这里强制使用 minimal 配置以保证稳定性
    cat > ${REALM_ROOT}/config.toml <<EOF
[log]
level = "warn"
output = "stdout"

[network]
no_tcp = false
use_udp = true

EOF

    # 循环写入规则
    if [[ -f "${REALM_ROOT}/rules.db" ]]; then
        while IFS='|' read -r lp ra rp; do
            cat >> ${REALM_ROOT}/config.toml <<EOF
[[endpoints]]
listen = "[::]:${lp}"
remote = "${ra}:${rp}"

EOF
        done
    fi

    systemctl restart realm
}

# --- [新增] 赛风/Warp 服务管理 ---
manage_sbwpph_service() {
    install_sbwpph_tool || return

    echo -e "${YELLOW}请选择模式:${PLAIN}"
    echo -e "  1. 启用 WARP 本地代理 (无限制，IP 纯净度一般)"
    echo -e "  2. 启用 Psiphon 多国代理 (可指定国家，救急/解锁强)"
    echo -e "  3. 停止并卸载该服务"
    read -p "-> " type_opt

    if [[ "$type_opt" == "3" ]]; then
        systemctl stop sbwpph 2>/dev/null
        systemctl disable sbwpph 2>/dev/null
        rm -f /etc/systemd/system/sbwpph.service
        systemctl daemon-reload
        echo -e "${GREEN}服务已停止并移除。${PLAIN}"
        return
    fi

    # 端口设置
    local port=$(get_safe_port "本地Socks端口" "40000")

    # IP 协议检测 (移植自 yg.sh)
    local sw46="-4"
    if [[ -z $(curl -s4m2 https://api.ipify.org) ]]; then sw46="-6"; fi

    local cmd_args="-b 127.0.0.1:${port} --endpoint 162.159.192.1:2408 ${sw46}"
    local mode_msg=""

    if [[ "$type_opt" == "1" ]]; then
        # Warp 模式
        cmd_args="${cmd_args} --gool"
        mode_msg="WARP 本地代理"
    elif [[ "$type_opt" == "2" ]]; then
        # Psiphon 模式 - 国家列表移植
        echo -e "${YELLOW}支持的国家代码:${PLAIN}"
        echo -e "  奥地利(AT) 澳大利亚(AU) 比利时(BE) 加拿大(CA) 瑞士(CH) 德国(DE)"
        echo -e "  西班牙(ES) 芬兰(FI) 法国(FR) 英国(GB) 爱尔兰(IE) 印度(IN)"
        echo -e "  意大利(IT) 日本(JP) 荷兰(NL) 挪威(NO) 波兰(PL) 新加坡(SG) 美国(US)"
        read -p "请输入国家代码 (默认 US): " country
        [[ -z "$country" ]] && country="US"
        cmd_args="${cmd_args} --cfon --country ${country}"
        mode_msg="Psiphon 代理 (国家: ${country})"
    else
        return
    fi

    # 生成 Systemd 服务
    cat > /etc/systemd/system/sbwpph.service <<EOF
[Unit]
Description=Sing-box-yg Warp/Psiphon Helper
After=network.target

[Service]
Type=simple
User=root
ExecStart=${SB_WPPH_BIN} ${cmd_args}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable sbwpph >/dev/null 2>&1
    systemctl restart sbwpph

    echo -e "${YELLOW}>>> 正在启动 ${mode_msg}...${PLAIN}"
    sleep 5
    if systemctl is-active --quiet sbwpph; then
        echo -e "${GREEN}✅ 启动成功！本地端口: ${port}${PLAIN}"
        echo -e "${YELLOW}提示: 现在你可以在 [分流规则管理] 中添加规则，将流量指向此端口。${PLAIN}"
    else
        echo -e "${RED}启动失败，请检查日志: journalctl -u sbwpph -e${PLAIN}"
    fi
    read -p "按回车继续..."
}

# --- [新增] 添加赛风/Warp 分流规则 (修复引号版) ---
add_wpph_rule() {
    # 检查服务是否运行
    if ! systemctl is-active --quiet sbwpph; then
        echo -e "${RED}错误: 赛风/Warp 服务未启动。${PLAIN}"
        echo -e "请先在上一级菜单选择 [5. 管理 服务进程] 进行启动。"
        read -p "按回车返回..."
        return
    fi

    # 自动抓取端口
    local cmd_line=$(ps -ef | grep sbwpph | grep -v grep)
    local port=$(echo "$cmd_line" | grep -oP '(?<=-b 127.0.0.1:)\d+')

    if [[ -z "$port" ]]; then
        echo -e "${RED}无法自动获取端口，请手动输入。${PLAIN}"
        read -p "本地端口: " port
    fi

    echo -e "${YELLOW}--- 添加 Warp/Psiphon 分流规则 ---${PLAIN}"
    echo -e "${GREEN}检测到本地服务端口: ${port}${PLAIN}"

    read -p "给规则起个名 (Tag，例: warp-netflix): " tag
    [[ -z "$tag" ]] && return

    echo -e "请选择分流目标:"
    echo -e "1. AI 智能全家桶 (OpenAI/Claude/Gemini)"
    echo -e "2. Netflix"
    echo -e "3. Disney+"
    echo -e "4. TikTok"
    echo -e "5. 自定义 geosite (例如: bilibili)"
    echo -e "6. 自定义 域名后缀 (例如: .uk)"
    read -p "-> " r_opt

    local rules=""
    local rule_name=""
    case "$r_opt" in
        1) rules="\"geosite-openai\", \"geosite-anthropic\", \"geosite-google-gemini\", \"geosite-category-ai-chat-!cn\""; rule_name="AI-Services" ;;
        2) rules="\"geosite-netflix\""; rule_name="Netflix" ;;
        3) rules="\"geosite-disney\""; rule_name="Disney+" ;;
        4) rules="\"geosite-tiktok\""; rule_name="TikTok" ;;
        5)
            read -p "输入 geosite 代码 (逗号分隔): " c
            rules=$(echo "$c" | sed 's/,/","/g' | sed 's/^/"geosite-/g' | sed 's/$/"/g')
            rule_name="Custom-Geo"
            ;;
        6)
            read -p "输入域名后缀 (逗号分隔): " c
            rules=$(echo "$c" | sed 's/,/","/g' | sed 's/^/"./g' | sed 's/$/"/g')
            rule_name="Custom-Domain"
            ;;
        *) return ;;
    esac

    # 写入配置 (注意 TYPE=socks, IP=127.0.0.1)
    echo "TAG=$tag" > ${SB_NODES}/${tag}.conf
    echo "TYPE=socks" >> ${SB_NODES}/${tag}.conf
    echo "IP=127.0.0.1" >> ${SB_NODES}/${tag}.conf
    echo "PORT=$port" >> ${SB_NODES}/${tag}.conf
    echo "PASS=none" >> ${SB_NODES}/${tag}.conf
    echo "METHOD=none" >> ${SB_NODES}/${tag}.conf
    # [关键修复] 强制单引号
    echo "RULES='$rules'" >> ${SB_NODES}/${tag}.conf
    echo "RULE_TYPE=$r_opt" >> ${SB_NODES}/${tag}.conf
    echo "RULE_NAME='$rule_name'" >> ${SB_NODES}/${tag}.conf

    echo -e "${GREEN}规则 [$tag] 已添加！流量将转发至本地 Warp/Psiphon。${PLAIN}"
    update_route_rules; apply_changes
}

# ==============================================================================
# [重构] 分流规则 & 路由策略管理模块 (优雅分层版)
# ==============================================================================

# --- 1. 创建 SS 节点 (修复引号版) ---
add_ss_node() {
    echo -e "${YELLOW}--- 添加 Shadowsocks 分流节点 ---${PLAIN}"
    read -p "给节点起个名 (Tag，仅限英文数字，例: ss-unlock): " tag
    [[ -z "$tag" ]] && return

    read -p "IP地址: " ip
    read -p "端口 (Port): " port
    read -p "密码 (Password): " pass
    read -p "加密方式 (Method, 例: aes-256-gcm): " method

    if [[ -z "$ip" || -z "$port" || -z "$pass" || -z "$method" ]]; then
        echo -e "${RED}错误：所有字段都必须填写！${PLAIN}"; return
    fi

    echo -e "----------------------------"
    echo -e "请选择该节点初始分流目标:"
    echo -e "1. AI 智能全家桶 (OpenAI/Claude/Gemini) [推荐]"
    echo -e "2. Netflix"
    echo -e "3. Disney+"
    echo -e "4. TikTok"
    echo -e "5. 自定义 geosite (例如: bilibili)"
    echo -e "6. 自定义 域名后缀 (例如: .uk)"
    read -p "-> " r_opt

    local rules=""; local rule_name=""
    case "$r_opt" in
        1) rules="\"geosite-openai\", \"geosite-anthropic\", \"geosite-google-gemini\", \"geosite-category-ai-chat-!cn\""; rule_name="AI-Services" ;;
        2) rules="\"geosite-netflix\""; rule_name="Netflix" ;;
        3) rules="\"geosite-disney\""; rule_name="Disney+" ;;
        4) rules="\"geosite-tiktok\""; rule_name="TikTok" ;;
        5) read -p "输入 geosite 代码 (逗号分隔): " c; rules=$(echo "$c" | sed 's/,/","/g' | sed 's/^/"geosite-/g' | sed 's/$/"/g'); rule_name="Custom-Geo" ;;
        6) read -p "输入域名后缀 (逗号分隔): " c; rules=$(echo "$c" | sed 's/,/","/g' | sed 's/^/"./g' | sed 's/$/"/g'); rule_name="Custom-Domain" ;;
        *) echo "无效选择"; return ;;
    esac

    # 写入文件 (强制单引号)
    echo "TAG=$tag" > ${SB_NODES}/${tag}.conf
    echo "TYPE=shadowsocks" >> ${SB_NODES}/${tag}.conf
    echo "IP=$ip" >> ${SB_NODES}/${tag}.conf
    echo "PORT=$port" >> ${SB_NODES}/${tag}.conf
    echo "PASS=$pass" >> ${SB_NODES}/${tag}.conf
    echo "METHOD=$method" >> ${SB_NODES}/${tag}.conf
    echo "RULES='$rules'" >> ${SB_NODES}/${tag}.conf
    echo "RULE_NAME='$rule_name'" >> ${SB_NODES}/${tag}.conf

    echo -e "${GREEN}SS 节点 [$tag] 添加成功！${PLAIN}"
    update_route_rules; apply_changes
}

# --- 2. 通用函数：给节点追加规则 (支持类型过滤 & 修复引号) ---
append_rule_to_node() {
    local type_filter=$1 # 接收参数: "shadowsocks" 或 "socks"
    local title_str="SS"
    [[ "$type_filter" == "socks" ]] && title_str="Warp/Psiphon"

    echo -e "${YELLOW}--- 扩展 ${title_str} 规则 (追加目标) ---${PLAIN}"
    local conf_files=("${SB_NODES}"/*.conf)
    if [[ ! -e "${conf_files[0]}" ]]; then echo -e "${RED}没有可用的配置。${PLAIN}"; read -p "回车..."; return; fi

    echo -e "请选择要扩展的项:"
    local i=1; local tags=()
    for f in "${SB_NODES}"/*.conf; do
        # 过滤逻辑
        if grep -q "TYPE=${type_filter}" "$f"; then
            local tag_name=$(basename "$f" .conf)
            local current_rule_name=$(grep "RULE_NAME=" "$f" | cut -d= -f2 | sed "s/'//g")
            echo -e "  ${i}. ${GREEN}${tag_name}${PLAIN} (当前: ${current_rule_name})"
            tags+=("$tag_name");
        else
            tags+=("SKIP") # 占位，保持序号一致性
        fi
        let i++
    done
    echo -e "  0. 取消"
    read -p "-> " idx

    if [[ "$idx" == "0" || -z "$tags[$((idx-1))]" || "${tags[$((idx-1))]}" == "SKIP" ]]; then return; fi

    local target_tag="${tags[$((idx-1))]}"
    local target_file="${SB_NODES}/${target_tag}.conf"

    echo -e "----------------------------"
    echo -e "请选择要 **追加** 的新规则:"
    echo -e "1. AI 智能全家桶"
    echo -e "2. Netflix"
    echo -e "3. Disney+"
    echo -e "4. TikTok"
    echo -e "5. 自定义 geosite"
    echo -e "6. 自定义 域名后缀"
    read -p "-> " r_opt

    local new_rules=""; local new_rule_name=""
    case "$r_opt" in
        1) new_rules="\"geosite-openai\", \"geosite-anthropic\", \"geosite-google-gemini\", \"geosite-category-ai-chat-!cn\""; new_rule_name="AI" ;;
        2) new_rules="\"geosite-netflix\""; new_rule_name="Netflix" ;;
        3) new_rules="\"geosite-disney\""; new_rule_name="Disney+" ;;
        4) new_rules="\"geosite-tiktok\""; new_rule_name="TikTok" ;;
        5) read -p "输入 geosite: " c; new_rules=$(echo "$c" | sed 's/,/","/g' | sed 's/^/"geosite-/g' | sed 's/$/"/g'); new_rule_name="CustomGeo" ;;
        6) read -p "输入域名后缀: " c; new_rules=$(echo "$c" | sed 's/,/","/g' | sed 's/^/"./g' | sed 's/$/"/g'); new_rule_name="CustomDomain" ;;
        *) return ;;
    esac

    local old_rules=$(grep "^RULES=" "$target_file" | cut -d= -f2 | sed "s/^'//;s/'$//")
    local old_name=$(grep "^RULE_NAME=" "$target_file" | cut -d= -f2 | sed "s/'//g")

    local final_rules="${old_rules}, ${new_rules}"
    local final_name="${old_name} + ${new_rule_name}"

    sed -i '/^RULES=/d' "$target_file"
    sed -i '/^RULE_NAME=/d' "$target_file"
    echo "RULES='${final_rules}'" >> "$target_file"
    echo "RULE_NAME='${final_name}'" >> "$target_file"

    echo -e "${GREEN}✅ 追加成功！${PLAIN}"
    update_route_rules; apply_changes
}

# --- 3. 通用函数：从节点移除规则 (支持类型过滤 & 修复引号) ---
remove_rule_from_node() {
    local type_filter=$1
    local title_str="SS"
    [[ "$type_filter" == "socks" ]] && title_str="Warp/Psiphon"

    echo -e "${YELLOW}--- 缩减 ${title_str} 规则 (移除目标) ---${PLAIN}"
    local conf_files=("${SB_NODES}"/*.conf)
    if [[ ! -e "${conf_files[0]}" ]]; then echo -e "${RED}没有可用的配置。${PLAIN}"; read -p "回车..."; return; fi

    echo -e "请选择操作对象:"
    local i=1; local tags=()
    for f in "${SB_NODES}"/*.conf; do
        if grep -q "TYPE=${type_filter}" "$f"; then
            local tag_name=$(basename "$f" .conf)
            local rule_name=$(grep "RULE_NAME=" "$f" | cut -d= -f2 | sed "s/'//g")
            echo -e "  ${i}. ${GREEN}${tag_name}${PLAIN} [包含: ${rule_name}]"
            tags+=("$tag_name")
        else
            tags+=("SKIP")
        fi
        let i++
    done
    echo -e "  0. 取消"
    read -p "-> " idx

    if [[ "$idx" == "0" || -z "$tags[$((idx-1))]" || "${tags[$((idx-1))]}" == "SKIP" ]]; then return; fi

    local target_tag="${tags[$((idx-1))]}"
    local target_file="${SB_NODES}/${target_tag}.conf"

    # 解析逻辑
    local raw_rules_str=$(grep "^RULES=" "$target_file" | cut -d= -f2 | sed "s/^'//;s/'$//")
    local raw_names_str=$(grep "^RULE_NAME=" "$target_file" | cut -d= -f2 | sed "s/^'//;s/'$//")
    IFS=',' read -r -a rules_array <<< "$raw_rules_str"
    IFS='+' read -r -a names_array <<< "$raw_names_str"

    echo -e "当前挂载的规则:"
    local r_count=${#rules_array[@]}
    if [[ "$r_count" -eq 0 ]]; then echo -e "${RED}无规则。${PLAIN}"; return; fi

    for ((k=0; k<r_count; k++)); do
        local show_name=$(echo "${names_array[$k]}" | xargs)
        echo -e "  $((k+1)). ${YELLOW}${show_name}${PLAIN}"
    done
    echo -e "  0. 取消"

    read -p "删除序号 [1-$r_count]: " del_idx
    if [[ "$del_idx" == "0" || ! "$del_idx" =~ ^[0-9]+$ || "$del_idx" -gt "$r_count" ]]; then return; fi

    local new_rules_str=""; local new_names_str=""; local first=1
    for ((k=0; k<r_count; k++)); do
        if [[ $((k+1)) -eq "$del_idx" ]]; then continue; fi
        local clean_rule=$(echo "${rules_array[$k]}" | xargs)
        local clean_name=$(echo "${names_array[$k]}" | xargs)
        if [[ $first -eq 1 ]]; then
            new_rules_str="${clean_rule}"; new_names_str="${clean_name}"; first=0
        else
            new_rules_str="${new_rules_str}, ${clean_rule}"; new_names_str="${new_names_str} + ${clean_name}"
        fi
    done

    sed -i '/^RULES=/d' "$target_file"
    sed -i '/^RULE_NAME=/d' "$target_file"
    echo "RULES='${new_rules_str}'" >> "$target_file"
    echo "RULE_NAME='${new_names_str}'" >> "$target_file"

    echo -e "${GREEN}✅ 规则已移除！${PLAIN}"
    update_route_rules; apply_changes
}

# --- 4. 通用函数：删除节点/配置文件 (支持类型过滤) ---
delete_route_interactive() {
    local type_filter=$1
    local title_str="SS 节点"
    [[ "$type_filter" == "socks" ]] && title_str="Warp 规则配置"

    echo -e "${YELLOW}请输入要删除的 ${title_str} Tag (文件名):${PLAIN}"
    # 只列出符合类型的节点
    grep -l "TYPE=${type_filter}" ${SB_NODES}/*.conf 2>/dev/null | xargs -n 1 basename | sed 's/.conf//'
    echo -e "----------------------------"
    read -p "-> " del_tag
    if [[ -f "${SB_NODES}/${del_tag}.conf" ]]; then
        # 二次确认类型，防止误删
        if ! grep -q "TYPE=${type_filter}" "${SB_NODES}/${del_tag}.conf"; then
            echo -e "${RED}错误：该 Tag 不属于当前类别，无法删除。${PLAIN}"; return
        fi
        rm -f "${SB_NODES}/${del_tag}.conf"
        echo -e "${GREEN}删除成功。${PLAIN}"
        update_route_rules; apply_changes
    else
        echo -e "${RED}未找到该节点。${PLAIN}"; sleep 1
    fi
}

# --- 5. 查看函数 (查看所有) ---
view_routes_interactive() {
    echo -e "${YELLOW}>>> 当前已配置的分流规则:${PLAIN}"
    if ls ${SB_NODES}/*.conf >/dev/null 2>&1; then
        for f in ${SB_NODES}/*.conf; do
            (
                source "$f"
                local type_info="SS"
                local color="${GREEN}"
                if [[ "$TYPE" == "socks" ]]; then type_info="Warp"; color="${BLUE}"; fi
                echo -e "  📄 [${type_info}] Tag: ${color}${TAG}${PLAIN}"
                echo -e "      └-> 目标: ${YELLOW}${RULE_NAME}${PLAIN}"
            )
        done
    else
        echo "  (暂无配置)"
    fi
    read -p "按回车返回..."
}

# --- 6. 子菜单：SS 管理 ---
menu_routing_ss() {
    clear
    echo -e "===================================================="
    echo -e "           SS 外部分流节点管理 (高级)"
    echo -e "===================================================="
    echo -e "  1. 新增 SS 分流节点 (创建新地基)"
    echo -e "  2. 扩展 SS 分流规则 (给节点**追加**新目标)"
    echo -e "  3. 缩减 SS 分流规则 (从节点**移除**某目标)"
    echo -e "  --------------------------------------------------"
    echo -e "  4. 删除 整个 SS 节点 (炸掉地基)"
    echo -e "  0. 返回上一级"
    echo -e "===================================================="
    read -p "-> " opt
    case "$opt" in
        1) add_ss_node; menu_routing_ss ;;
        2) append_rule_to_node "shadowsocks"; menu_routing_ss ;; # 传入 shadowsocks 过滤
        3) remove_rule_from_node "shadowsocks"; menu_routing_ss ;;
        4) delete_route_interactive "shadowsocks"; menu_routing_ss ;;
        0) menu_routing ;;
        *) menu_routing_ss ;;
    esac
}

# --- 7. 子菜单：Warp 管理 ---
menu_routing_warp() {
    clear
    local status="${RED}未启动${PLAIN}"
    if systemctl is-active --quiet sbwpph; then status="${GREEN}运行中${PLAIN}"; fi

    echo -e "===================================================="
    echo -e "           赛风/Warp 本地分流管理 (高级)"
    echo -e "===================================================="
    echo -e "  服务状态: ${status}"
    echo -e "----------------------------------------------------"
    echo -e "  1. 新增 Warp/Psiphon 规则 (创建本地映射)"
    echo -e "  2. 扩展 Warp 规则 (给配置**追加**新目标)"
    echo -e "  3. 缩减 Warp 规则 (从配置**移除**某目标)"
    echo -e "  --------------------------------------------------"
    echo -e "  4. 删除 整个 Warp 规则配置"
    echo -e "  5. 管理 服务进程 (启动/停止/国家切换)"
    echo -e "  0. 返回上一级"
    echo -e "===================================================="
    read -p "-> " opt
    case "$opt" in
        1) add_wpph_rule; menu_routing_warp ;;
        2) append_rule_to_node "socks"; menu_routing_warp ;; # 传入 socks 过滤
        3) remove_rule_from_node "socks"; menu_routing_warp ;;
        4) delete_route_interactive "socks"; menu_routing_warp ;;
        5) manage_sbwpph_service; menu_routing_warp ;;
        0) menu_routing ;;
        *) menu_routing_warp ;;
    esac
}

# --- 8. 主分流菜单 (入口) ---
menu_routing() {
    clear
    echo -e "===================================================="
    echo -e "           分流规则 & 路由策略管理 (分层版)"
    echo -e "===================================================="
    echo -e "  1. >> SS 外部分流管理 (增删改查)"
    echo -e "  2. >> 赛风/Warp 本地分流管理 (增删改查)"
    echo -e "----------------------------------------------------"
    echo -e "  3. 查看 当前配置总览"
    echo -e "  4. 清空 所有分流配置 (重置)"
    echo -e "  0. 返回上一级"
    echo -e "===================================================="
    read -p "-> " opt
    case "$opt" in
        1) menu_routing_ss ;;
        2) menu_routing_warp ;;
        3) view_routes_interactive; menu_routing ;;
        4) rm -f ${SB_NODES}/*.conf; update_route_rules; apply_changes; menu_routing ;;
        0) return ;;
        *) menu_routing ;;
    esac
}

apply_changes() {
    local ver=$(${SB_BIN} version | head -n 1 | awk '{print $3}')
    generate_base_config "$ver"
    generate_outbounds_config "$ver"
    update_route_rules "$ver"
    echo -e "${YELLOW}>>> 正在重启 Sing-box 服务...${PLAIN}"
    if systemctl restart sing-box; then echo -e "${GREEN}✅ 配置已应用，服务重启成功！${PLAIN}"; else echo -e "${RED}❌ 服务重启失败！请检查日志 (Menu 11) 排查错误。${PLAIN}"; fi
    read -p "按回车继续..."
}

menu_view_config() {
    clear
    echo -e "===================================================="
    echo -e "           Sing-box 配置信息查看"
    echo -e "===================================================="
    echo -e "  1. 查看 URL 链接 (暂未开发)"
    echo -e "  2. 查看 二维码 (暂未开发)"
    echo -e "  3. 查看 客户端 JSON"
    echo -e "  4. 查看 服务端 JSON"
    echo -e "  0. 返回上一级"
    echo -e "===================================================="
    read -p " 请输入数字 [0-4]: " v_opt
    if [[ "$v_opt" == "0" ]]; then return; fi

    echo -e "${GREEN}>>> 现有配置列表:${PLAIN}"
    local files=($(ls ${SB_CLIENT}/*.json 2>/dev/null)); local i=1
    for f in "${files[@]}"; do echo "$i. $(basename $f)"; let i++; done
    if [ ${#files[@]} -eq 0 ]; then echo "暂无配置"; read; return; fi

    echo "0. 返回上一级"
    echo -e "------------------------------------"
    read -p "请输入序号 [回车=查看全部]: " f_idx
    if [[ "$f_idx" == "0" ]]; then return; fi

    print_content() {
        local f=$1
        if [[ "$v_opt" == "3" ]]; then
            if [[ -n "$f_idx" ]]; then echo -e "${YELLOW}========== [文件: $(basename "$f")] ==========${PLAIN}"; cat "$f"; echo -e "\n"; fi
        elif [[ "$v_opt" == "4" ]]; then
            local s_target="${f/client/server}"; s_target="${s_target/out_/in_}"
            if [[ -f "$s_target" ]]; then echo -e "${YELLOW}========== [文件: $(basename "$s_target")] ==========${PLAIN}"; cat "$s_target"; else echo -e "${RED}服务端对应文件未找到: $s_target${PLAIN}"; fi
            echo -e "\n"
        fi
    }

    if [[ -z "$f_idx" ]]; then
        if [[ "$v_opt" == "3" ]]; then echo -e "${YELLOW}>>> 以下内容可直接复制到客户端 outbounds: [ ... ] 中:${PLAIN}"; jq -s '.' ${SB_CLIENT}/*.json | sed '1d;$d'
        else for f in "${files[@]}"; do print_content "$f"; done; fi
    else
        local target="${files[$((f_idx-1))]}"; if [[ -f "$target" ]]; then print_content "$target"; else echo -e "${RED}无效序号${PLAIN}"; fi
    fi
    read -p "按回车返回..."
}

menu_uninstall() {
    clear
    echo -e "===================================================="
    echo -e "           卸载 Sing-box & 清理环境"
    echo -e "===================================================="
    echo -e "  1. 仅卸载 Sing-box (保留 Nginx/Realm)"
    echo -e "  2. 彻底卸载 (级联删除 Nginx/Realm/Crontab)"
    echo -e "  0. 返回上一级"
    echo -e "===================================================="
    read -p " 请输入数字 [0-2]: " u_opt
    if [[ "$u_opt" == "0" ]]; then return; fi
    echo -e "${YELLOW}正在停止服务...${PLAIN}"
    systemctl stop sing-box; systemctl disable sing-box; rm -rf ${SB_BIN} ${SB_ROOT}
    if [[ "$u_opt" == "2" ]]; then
        echo -e "${YELLOW}正在级联清理...${PLAIN}"
        apt-get purge -y nginx nginx-common; rm -rf /usr/share/nginx/html /etc/nginx; systemctl stop realm; rm -rf /usr/local/bin/realm ${REALM_ROOT} /etc/systemd/system/realm.service
        crontab -l | grep -v "singbox" | crontab -; rm -rf /root/.acme.sh
    fi
    echo -e "${GREEN}卸载完成。${PLAIN}"; read -p "按回车返回..."
}

show_menu() {
    while true; do
        clear; check_root
        local ver="未安装"; if [ -f ${SB_BIN} ]; then ver=$(${SB_BIN} version | head -n1 | awk '{print $3}'); fi
        local ver_color="${RED}未安装${PLAIN}"; if [[ "$ver" != "未安装" ]]; then ver_color="${GREEN}${ver}${PLAIN}"; fi
        local status="${RED}未运行${PLAIN}"; if systemctl is-active --quiet sing-box; then status="${GREEN}运行中${PLAIN}"; fi
        local auto="${RED}未开启${PLAIN}"; if systemctl is-enabled sing-box 2>/dev/null | grep -q "enabled"; then auto="${GREEN}已开启${PLAIN}"; fi

        echo -e "===================================================="
        echo -e "       Sing-box 终极管理脚本 [Ultimate v9.9.12]"
        echo -e "===================================================="
        echo -e "    系统状态:  ${status}"
        echo -e "    内核版本:  ${ver_color}"
        echo -e "    开机自启:  ${auto}"
        echo -e ""
        echo -e "———————————————— 核心管理 ————————————————"
        echo -e "  1. 安装 / 更新 / 切换 Sing-box (核心)"
        echo -e "  2. 卸载 Sing-box (级联清理)"
        echo -e "  3. 协议管理 (多协议共存)"
        echo -e ""
        echo -e "———————————————— 配套组件 (高级) ————————————————"
        echo -e "  4. 域名证书 & 伪装 (Nginx)"
        echo -e "  5. 端口转发 (Realm)"
        echo -e "  6. 分流与解锁 (Routing)"
        echo -e ""
        echo -e "———————————————— 服务管理 ————————————————"
        echo -e "  7. 启动服务"
        echo -e "  8. 停止服务"
        echo -e "  9. 重启服务"
        echo -e ""
        echo -e "———————————————— 信息查看 ————————————————"
        echo -e "  10. 查看配置信息"
        echo -e "  11. 查看运行日志"
        echo -e ""
        echo -e "  0. 退出脚本"
        echo -e "===================================================="
        read -p " 请输入数字选择 [0-11]: " num
        case "$num" in
            1) install_singbox ;; 2) menu_uninstall ;; 3) menu_protocol ;; 4) menu_cert_nginx ;; 5) menu_realm ;; 6) menu_routing ;;
            7) systemctl start sing-box && echo "已启动"; read -p "回车继续..." ;;
            8) systemctl stop sing-box && echo "已停止"; read -p "回车继续..." ;;
            9) systemctl restart sing-box && echo "已重启"; read -p "回车继续..." ;;
            10) menu_view_config ;; 11) journalctl -u sing-box -f ;; 0) exit 0 ;;
            *) echo "输入错误"; read -p "回车重试..." ;;
        esac
    done
}

install_base
show_menu
