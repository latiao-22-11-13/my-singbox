#!/bin/bash

# =========================================================
#  VPS 极致性能工具箱 - 统一管理脚本
#  集成: XanMod 内核 / TCP Brutal / Sing-box
# =========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
PLAIN='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "${RED}错误: 必须使用 root 用户运行此脚本！${PLAIN}" && exit 1

# =========================================================
#  公共函数
# =========================================================

function check_sys() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        release="$ID"
    else
        release="unknown"
    fi
}

function get_sys_info() {
    if [[ -f /etc/os-release ]]; then
        grep PRETTY_NAME /etc/os-release | cut -d '"' -f 2
    else
        uname -sr
    fi
}

function check_environment() {
    check_sys
    local os_id=$(echo "$release" | tr '[:upper:]' '[:lower:]')

    if [[ "$os_id" != "debian" && "$os_id" != "ubuntu" ]]; then
        echo -e "${RED}[拒绝] 不支持的操作系统: ${os_id}${PLAIN}"
        echo -e "${RED}XanMod 内核仅支持 Debian 和 Ubuntu。${PLAIN}"
        return 1
    fi

    local virt_type="unknown"
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        virt_type=$(systemd-detect-virt)
    elif [[ -f /proc/user_beancounters ]]; then
        virt_type="openvz"
    elif [[ -f /.dockerenv ]]; then
        virt_type="docker"
    fi

    case "$virt_type" in
        lxc|lxd|openvz*|docker|podman|container)
            echo -e "${RED}[拒绝] 容器环境 (${virt_type})，不支持更换内核。${PLAIN}"
            return 1
            ;;
    esac
    return 0
}

function sys_cleanup() {
    echo -e "${YELLOW}正在清理系统垃圾...${PLAIN}"
    apt-get autoremove -y > /dev/null 2>&1
    apt-get clean > /dev/null 2>&1
    rm -rf /var/cache/apt/archives/*
    echo -e "${GREEN}清理完成。${PLAIN}"
}

# =========================================================
#  模块 1: XanMod 内核管理
# =========================================================

function check_cpu_support() {
    local arch=$(uname -m)
    if [[ "$arch" != "x86_64" ]]; then
        echo -e "${RED}[失败] 架构 $arch 不支持。${PLAIN}"
        return 1
    fi

    local tmp_dir=$(mktemp -d)
    wget -q -O "${tmp_dir}/check_x86-64_psabi.sh" https://dl.xanmod.org/check_x86-64_psabi.sh
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[失败] 下载 CPU 检测脚本失败。${PLAIN}"
        rm -rf "$tmp_dir"
        return 1
    fi
    chmod +x "${tmp_dir}/check_x86-64_psabi.sh"

    local output
    output=$("${tmp_dir}/check_x86-64_psabi.sh")
    rm -rf "$tmp_dir"

    if [[ -z "$output" ]]; then
        echo -e "${RED}[失败] CPU 检测无输出。${PLAIN}"
        return 1
    fi

    if [[ "$output" == *"v4"* ]]; then
        XANMOD_VER="x64v4"
    elif [[ "$output" == *"v3"* ]]; then
        XANMOD_VER="x64v3"
    elif [[ "$output" == *"v2"* ]]; then
        XANMOD_VER="x64v2"
    elif [[ "$output" == *"v1"* ]]; then
        XANMOD_VER="x64v1"
    else
        echo -e "${RED}[失败] 无法识别 CPU 等级: $output ${PLAIN}"
        return 1
    fi

    echo -e "${GREEN}CPU 等级: ${XANMOD_VER}${PLAIN}"
    return 0
}

function install_xanmod() {
    check_environment || return

    echo -e "${YELLOW}正在安装依赖...${PLAIN}"
    apt-get update -y > /dev/null 2>&1
    apt-get install -y wget gpg gawk ca-certificates > /dev/null 2>&1

    check_cpu_support || return

    echo -e "${YELLOW}目标版本: linux-xanmod-${XANMOD_VER}${PLAIN}"

    echo -e "${YELLOW}配置源...${PLAIN}"
    source /etc/os-release
    wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /etc/apt/keyrings/xanmod-archive-keyring.gpg --yes
    echo "deb [signed-by=/etc/apt/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org ${VERSION_CODENAME} main" | tee /etc/apt/sources.list.d/xanmod-release.list

    echo -e "${YELLOW}检查更新...${PLAIN}"
    apt-get update -y > /dev/null 2>&1

    echo -e "${YELLOW}执行安装...${PLAIN}"
    apt-get install -y "linux-xanmod-${XANMOD_VER}"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[失败] 安装出错。${PLAIN}"
        return
    fi

    sys_cleanup

    echo -e "${YELLOW}是否删除旧内核? [Y/n]${PLAIN}"
    read -p "(默认回车确认): " del_old
    if [[ "$del_old" != "n" && "$del_old" != "N" ]]; then
        echo -e "${YELLOW}正在清理旧内核...${PLAIN}"
        current_kernel=$(uname -r)
        # 保留: 当前内核 + xanmod 内核 + 最新一个非xanmod非当前内核(保底)
        local all_images=($(dpkg --list | grep "^ii.*linux-image-[0-9]" | awk '{print $2}'))
        local xanmod_images=()
        local other_images=()
        for img in "${all_images[@]}"; do
            if [[ "$img" == *"$current_kernel"* ]]; then
                continue
            elif [[ "$img" == *"xanmod"* ]]; then
                xanmod_images+=("$img")
            else
                other_images+=("$img")
            fi
        done
        # other_images 按版本排序，保留最新一个作为保底
        local sorted_others=($(printf '%s\n' "${other_images[@]}" | sort -V))
        local keep_fallback=""
        if [[ ${#sorted_others[@]} -gt 1 ]]; then
            keep_fallback="${sorted_others[-1]}"
        fi
        local to_remove=()
        for img in "${sorted_others[@]}"; do
            [[ "$img" == "$keep_fallback" ]] && continue
            to_remove+=("$img")
        done
        if [[ ${#to_remove[@]} -gt 0 ]]; then
            echo -e "${SKYBLUE}保留: 当前($current_kernel) + XanMod + 保底($keep_fallback)${PLAIN}"
            echo -e "将移除: ${to_remove[*]}"
            apt-get purge -y "${to_remove[@]}"
            update-grub
            echo -e "${GREEN}旧内核已移除。${PLAIN}"
        else
            echo -e "${GREEN}无需清理。${PLAIN}"
        fi
    fi

    echo -e "${YELLOW}系统必须重启才能启用 XanMod 内核。${PLAIN}"
    read -p "是否立即重启? [Y/n] (默认重启): " confirm
    [[ "$confirm" != "n" && "$confirm" != "N" ]] && reboot
}

function remove_xanmod() {
    check_environment || return

    echo -e "${YELLOW}正在安装保底内核...${PLAIN}"
    apt-get install -y linux-image-amd64

    local xanmod_pkgs=$(dpkg --list | grep "xanmod" | awk '{print $2}')
    if [[ -z "$xanmod_pkgs" ]]; then
        echo -e "${RED}未找到 XanMod 包。${PLAIN}"
        return
    fi

    echo -e "${YELLOW}正在卸载 XanMod...${PLAIN}"
    apt-get purge -y $xanmod_pkgs
    rm -f /etc/apt/sources.list.d/xanmod-release.list
    rm -f /etc/apt/keyrings/xanmod-archive-keyring.gpg
    sys_cleanup
    update-grub
    echo -e "${GREEN}卸载完成！${PLAIN}"
    read -p "是否立即重启? [Y/n] (默认重启): " confirm
    [[ "$confirm" != "n" && "$confirm" != "N" ]] && reboot
}

function menu_xanmod() {
    while true; do
        clear
        echo -e "============================================"
        echo -e "         ${SKYBLUE}XanMod 内核管理${PLAIN}"
        echo -e "============================================"
        echo -e "当前内核: ${YELLOW}$(uname -r)${PLAIN}"
        echo -e "--------------------------------------------"
        echo -e "${GREEN}1.${PLAIN} 安装/更新 XanMod"
        echo -e "${GREEN}2.${PLAIN} 卸载 XanMod"
        echo -e "${GREEN}0.${PLAIN} 返回主菜单"
        echo -e "============================================"
        read -p "请选择 [0-2]: " sub
        case $sub in
            1) install_xanmod ;;
            2) remove_xanmod ;;
            0) return ;;
            *) echo -e "${RED}输入错误${PLAIN}"; sleep 1 ;;
        esac
    done
}

# =========================================================
#  模块 2: TCP Brutal
# =========================================================

function check_brutal_status() {
    lsmod | grep -q "brutal"
}

function get_brutal_str() {
    check_brutal_status && echo -e "${GREEN}运行中${PLAIN}" || echo -e "${RED}未运行${PLAIN}"
}

function install_brutal() {
    clear
    check_sys
    local kernel_version=$(uname -r)
    echo -e "系统: ${SKYBLUE}${release}${PLAIN}  内核: ${SKYBLUE}${kernel_version}${PLAIN}"

    # 检测编译器
    echo -e "${YELLOW}检测编译器...${PLAIN}"
    local COMPILER="gcc"
    if cat /proc/version | grep -i -q "clang"; then
        COMPILER="clang"
        echo -e "编译器: ${GREEN}Clang/LLVM${PLAIN}"
    else
        echo -e "编译器: ${GREEN}GCC${PLAIN}"
    fi

    # 安装依赖
    echo -e "${YELLOW}安装编译依赖...${PLAIN}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y > /dev/null 2>&1
    apt-get install -y build-essential "linux-headers-${kernel_version}" git > /dev/null 2>&1
    if [[ "$COMPILER" == "clang" ]]; then
        apt-get install -y clang llvm lld > /dev/null 2>&1
    fi
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[失败] 依赖安装出错。${PLAIN}"
        return
    fi

    # 拉取源码
    echo -e "${YELLOW}拉取源码...${PLAIN}"
    rm -rf /usr/src/tcp-brutal
    git clone --depth=1 https://github.com/apernet/tcp-brutal.git /usr/src/tcp-brutal
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[失败] 源码下载失败。${PLAIN}"
        return
    fi

    # 编译
    echo -e "${YELLOW}编译中...${PLAIN}"
    cd /usr/src/tcp-brutal
    if [[ "$COMPILER" == "clang" ]]; then
        make LLVM=1
    else
        make
    fi

    if [[ ! -f "brutal.ko" ]]; then
        echo -e "${RED}[失败] 编译失败。${PLAIN}"
        return
    fi

    # 安装
    echo -e "${YELLOW}安装模块...${PLAIN}"
    local MODULE_DIR="/lib/modules/${kernel_version}/extra"
    mkdir -p "$MODULE_DIR"
    cp brutal.ko "$MODULE_DIR/"
    depmod -a
    modprobe brutal

    if check_brutal_status; then
        echo -e "${GREEN}TCP Brutal 安装成功！${PLAIN}"
        echo "brutal" > /etc/modules-load.d/brutal.conf
        sys_cleanup
    else
        echo -e "${RED}[失败] 加载失败，请检查 dmesg。${PLAIN}"
    fi
}

function remove_brutal() {
    check_sys
    local kver=$(uname -r)

    echo -e "${YELLOW}卸载模块...${PLAIN}"
    rm -f /etc/modules-load.d/brutal.conf /etc/modules-load.d/tcp_brutal.conf
    check_brutal_status && { rmmod brutal 2>/dev/null; rmmod tcp_brutal 2>/dev/null; }
    rm -rf /usr/src/tcp-brutal
    find /lib/modules/"${kver}" -name "brutal.ko" -delete 2>/dev/null
    find /lib/modules/"${kver}" -name "tcp_brutal.ko" -delete 2>/dev/null
    depmod -a

    read -p "是否清理编译依赖 (headers/clang)? [Y/n] (默认Y): " clean_deps
    if [[ "$clean_deps" != "n" && "$clean_deps" != "N" ]]; then
        local pkgs="linux-headers-${kver}"
        cat /proc/version | grep -i -q "clang" && pkgs="$pkgs clang llvm lld"
        apt-get purge -y $pkgs > /dev/null 2>&1
        echo -e "${GREEN}编译依赖已清理。${PLAIN}"
    fi

    sys_cleanup
    echo -e "${GREEN}卸载完成。${PLAIN}"
}

function menu_brutal() {
    while true; do
        clear
        echo -e "============================================"
        echo -e "        ${SKYBLUE}TCP Brutal 管理${PLAIN}"
        echo -e "============================================"
        echo -e "当前内核: ${YELLOW}$(uname -r)${PLAIN}"
        echo -e "运行状态: $(get_brutal_str)"
        echo -e "--------------------------------------------"
        echo -e "${GREEN}1.${PLAIN} 安装/更新 TCP Brutal"
        echo -e "${GREEN}2.${PLAIN} 卸载 TCP Brutal"
        echo -e "${GREEN}0.${PLAIN} 返回主菜单"
        echo -e "============================================"
        read -p "请选择 [0-2]: " sub
        case $sub in
            1) install_brutal ;;
            2) remove_brutal ;;
            0) return ;;
            *) echo -e "${RED}输入错误${PLAIN}"; sleep 1 ;;
        esac
    done
}

# =========================================================
#  模块 3: Sing-box
# =========================================================

function install_singbox() {
    bash <(curl -sL https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/sb.sh)
}

function menu_singbox() {
    install_singbox
}

# =========================================================
#  主菜单
# =========================================================

function main_menu() {
    while true; do
        clear
        echo -e "============================================"
        echo -e "  ${SKYBLUE}VPS 极致性能工具箱${PLAIN}"
        echo -e "============================================"
        echo -e "系统: ${YELLOW}$(get_sys_info)${PLAIN}"
        echo -e "内核: ${YELLOW}$(uname -r)${PLAIN}"
        echo -e "============================================"
        echo -e "${GREEN}1.${PLAIN} XanMod 内核管理"
        echo -e "${GREEN}2.${PLAIN} TCP Brutal 管理"
        echo -e "${GREEN}3.${PLAIN} Sing-box 部署"
        echo -e "${GREEN}0.${PLAIN} 退出"
        echo -e "============================================"
        read -p "请选择 [0-3]: " choice
        case $choice in
            1) menu_xanmod ;;
            2) menu_brutal ;;
            3) menu_singbox ;;
            0) exit 0 ;;
            *) echo -e "${RED}输入错误${PLAIN}"; sleep 1 ;;
        esac
    done
}

main_menu
