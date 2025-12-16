#!/bin/bash

# =========================================================
#  VPS 极致性能工具箱 - Part 1: XanMod 内核管理 (Fix版)
# =========================================================

# 定义颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
PLAIN='\033[0m'

# 检查是否为 Root 用户
[[ $EUID -ne 0 ]] && echo -e "${RED}错误: 必须使用 root 用户运行此脚本！${PLAIN}" && exit 1

# =========================================================
#  系统检测与基础函数
# =========================================================

# 0. 环境兼容性检测 (OS + 虚拟化)
function check_environment() {
    # --- 1. 系统白名单检测 ---
    local os_id=""
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        os_id="${ID}"
    fi
    
    # 转换为小写兼容
    os_id=$(echo "$os_id" | tr '[:upper:]' '[:lower:]')
    
    if [[ "$os_id" != "debian" && "$os_id" != "ubuntu" ]]; then
        echo -e "${RED}==========================================================${PLAIN}"
        echo -e "${RED} [拒绝] 不支持的操作系统: ${os_id} ${PLAIN}"
        echo -e "${RED} XanMod 内核官方仅支持 Debian 和 Ubuntu 系统。 ${PLAIN}"
        echo -e "${RED}==========================================================${PLAIN}"
        exit 1
    fi

    # --- 2. 虚拟化架构检测 (拦截容器) ---
    local virt_type="unknown"
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        virt_type=$(systemd-detect-virt)
    elif [[ -f /proc/user_beancounters ]]; then
        virt_type="openvz"
    elif [[ -f /.dockerenv ]]; then
        virt_type="docker"
    fi

    case "$virt_type" in
        lxc|lxd|openvz*|docker|podman)
            echo -e "${RED}==========================================================${PLAIN}"
            echo -e "${RED} [拒绝] 检测到容器虚拟化环境: ${virt_type} ${PLAIN}"
            echo -e "${RED} 此类环境共享宿主机内核，不支持更换内核。 ${PLAIN}"
            echo -e "${RED}==========================================================${PLAIN}"
            exit 1
            ;;
        *)
            # KVM, VMWare, Microsoft, None (物理机) 等均放行
            ;;
    esac
}

# 1. 检查系统版本 (并导出变量)
function check_sys() {
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif cat /etc/issue | grep -q -E -i "debian"; then
        release="debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    elif cat /proc/version | grep -q -E -i "debian"; then
        release="debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    else
        if [[ -f /etc/os-release ]]; then
            source /etc/os-release
            release=$ID
        else
            release="unknown"
        fi
    fi
}

# 2. 获取并显示系统详细信息
function get_sys_info() {
    check_sys
    # 获取详细版本号
    if [[ -f /etc/os-release ]]; then
        pretty_name=$(grep PRETTY_NAME /etc/os-release | cut -d '"' -f 2)
    else
        pretty_name="${release}"
    fi
    echo "${pretty_name}"
}

# 3. 智能安装依赖工具
function install_base_dependencies() {
    check_sys
    # export LC_ALL=C
    
    if [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
        apt-get update -y
        apt-get install -y wget gpg gawk ca-certificates grep
    elif [[ "${release}" == "centos" || "${release}" == "almalinux" || "${release}" == "rocky" ]]; then
        yum update -y
        yum install -y wget gnupg2 gawk ca-certificates grep
    else
        echo -e "${RED}[警告] 无法识别的系统: ${release}${PLAIN}"
        read -p "按回车键尝试强制继续..."
    fi
}

# 4. 系统垃圾清理
function sys_cleanup() {
    echo -e "${YELLOW}正在执行系统垃圾清理 (autoremove & clean)...${PLAIN}"
    if [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
        apt-get autoremove -y > /dev/null 2>&1
        apt-get clean > /dev/null 2>&1
        rm -rf /var/cache/apt/archives/*
    elif [[ "${release}" == "centos" ]]; then
        yum autoremove -y > /dev/null 2>&1
        yum clean all > /dev/null 2>&1
    fi
    echo -e "${GREEN}系统清理完成！${PLAIN}"
}

# 5. CPU 详细检查逻辑
function check_cpu_support() {
    local arch=$(uname -m)
    if [[ "$arch" != "x86_64" ]]; then
        echo -e "${RED}[失败] 架构 $arch 不支持。${PLAIN}"
        return 1
    fi

    if [ -f "check_x86-64_psabi.sh" ]; then rm "check_x86-64_psabi.sh"; fi
    wget -q https://dl.xanmod.org/check_x86-64_psabi.sh
    if [ $? -ne 0 ]; then
        echo -e "${RED}[失败] 下载检测脚本失败。${PLAIN}"
        return 1
    fi
    chmod +x check_x86-64_psabi.sh

    local output
    output=$(./check_x86-64_psabi.sh)
    rm "check_x86-64_psabi.sh"

    if [[ -z "$output" ]]; then
        echo -e "${RED}[失败] 检测无输出。${PLAIN}"
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
        echo -e "${RED}[失败] 无法识别等级: $output ${PLAIN}"
        return 1
    fi
    return 0
}

# =========================================================
#  核心逻辑：XanMod 管理
# =========================================================

# 安装/更新 XanMod 内核
function install_xanmod() {
    check_environment

    check_sys
    if [[ "${release}" != "debian" && "${release}" != "ubuntu" ]]; then
        echo -e "${RED}错误：系统 ${release} 不支持自动安装 XanMod。${PLAIN}"
        read -p "按回车键返回..."
        return
    fi

    install_base_dependencies
    check_cpu_support
    if [ $? -ne 0 ]; then return; fi

    echo -e "${YELLOW}目标版本: linux-xanmod-${XANMOD_VER}${PLAIN}"
    
    echo -e "${YELLOW}配置源...${PLAIN}"
    wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
    echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list

    echo -e "${YELLOW}检查更新...${PLAIN}"
    apt-get update -y > /dev/null 2>&1
    
    echo -e "${YELLOW}执行安装...${PLAIN}"
    
    TEMP_LOG=$(mktemp)
    apt-get install -y "linux-xanmod-${XANMOD_VER}" 2>&1 | tee "$TEMP_LOG"
    INSTALL_STATUS=${PIPESTATUS[0]}
    install_log=$(cat "$TEMP_LOG")
    rm -f "$TEMP_LOG"

    if [ $INSTALL_STATUS -ne 0 ]; then
        echo -e "${RED}==============================================${PLAIN}"
        echo -e "${RED}  [失败] 安装过程中 apt 返回错误。${PLAIN}"
        echo -e "${RED}==============================================${PLAIN}"
        echo -e "请检查上方的错误信息 (可能是网络问题或依赖冲突)。"
        read -p "按回车键返回..."
        return
    fi

    if echo "$install_log" | grep -q "0 upgraded, 0 newly installed"; then
        echo -e "${GREEN}>>> 当前已是最新版本，无需更新。${PLAIN}"
        if [[ $(uname -r) != *"xanmod"* ]]; then
            echo -e "${RED}提示：内核包已在系统中，但当前运行的是旧内核。${PLAIN}"
        else
            sys_cleanup
            read -p "按回车键返回..."
            return
        fi
    else
        echo -e "${GREEN}>>> XanMod 内核安装/更新成功！${PLAIN}"
    fi

    sys_cleanup

    # 询问是否删除旧内核 (修改点：默认为 Y)
    echo -e "${YELLOW}===================================================${PLAIN}"
    echo -e "${YELLOW}  为了节省空间，是否删除系统自带的旧内核?${PLAIN}"
    echo -e "${YELLOW}  (仅保留刚才安装的 XanMod 内核)${PLAIN}"
    echo -e "${YELLOW}===================================================${PLAIN}"
    # 更改为默认 Y
    read -p "是否删除旧内核? [Y/n] (默认回车确认): " del_old
    
    # 逻辑添加 || -z "$del_old"
    if [[ "$del_old" == "y" || "$del_old" == "Y" || -z "$del_old" ]]; then
        echo -e "${YELLOW}正在识别并移除旧内核...${PLAIN}"
        
        current_kernel=$(uname -r)
        old_kernels=$(dpkg --list | grep "linux-image" | grep -v "xanmod" | grep -v "$current_kernel" | awk '{print $2}')
        
        if [[ -n "$old_kernels" ]]; then
            echo -e "${SKYBLUE}注意：当前运行的内核 ($current_kernel) 将被保留。${PLAIN}"
            echo -e "将移除: ${old_kernels}"
            apt-get purge -y $old_kernels
            update-grub
            echo -e "${GREEN}旧内核已移除。${PLAIN}"
        else
            echo -e "未发现可移除的旧内核 (或者只剩下当前正在运行的内核)。"
        fi
    fi

    echo -e "${YELLOW}系统必须重启才能启用 XanMod 内核。${PLAIN}"
    # 更改为默认 Y
    read -p "是否立即重启 VPS? [Y/n] (默认回车重启): " confirm
    # 逻辑添加 || -z "$confirm"
    [[ "${confirm}" == "y" || "${confirm}" == "Y" || -z "${confirm}" ]] && reboot
}

# 彻底卸载 XanMod 内核
function remove_xanmod() {
    check_environment

    check_sys
    if [[ "${release}" != "debian" && "${release}" != "ubuntu" ]]; then
        echo -e "${RED}不支持的系统。${PLAIN}"
        return
    fi

    echo -e "${YELLOW}准备卸载 XanMod... 正在检查保底内核...${PLAIN}"
    
    if [[ "${release}" == "debian" ]]; then
        echo -e "${YELLOW}正在安装/确认 Debian 官方内核 (linux-image-amd64)...${PLAIN}"
        apt-get install -y linux-image-amd64
    elif [[ "${release}" == "ubuntu" ]]; then
        echo -e "${YELLOW}正在安装/确认 Ubuntu 官方内核 (linux-image-generic)...${PLAIN}"
        apt-get install -y linux-image-generic
    fi

    echo -e "${YELLOW}正在搜索所有 XanMod 相关包...${PLAIN}"
    local xanmod_pkgs=$(dpkg --list | grep "xanmod" | awk '{print $2}')

    if [[ -z "$xanmod_pkgs" ]]; then
        echo -e "${RED}未找到 XanMod 包。${PLAIN}"
        read -p "按回车键返回..."
        return
    fi

    echo -e "${YELLOW}正在彻底卸载 XanMod...${PLAIN}"
    apt-get purge -y $xanmod_pkgs
    
    rm -f /etc/apt/sources.list.d/xanmod-release.list
    rm -f /usr/share/keyrings/xanmod-archive-keyring.gpg

    sys_cleanup
    echo -e "${YELLOW}正在更新 GRUB 引导...${PLAIN}"
    update-grub
    
    echo -e "${GREEN}>>> 卸载完成！${PLAIN}"
    # 更改为默认 Y
    read -p "是否立即重启? [Y/n] (默认回车重启): " confirm
    # 逻辑添加 || -z "$confirm"
    [[ "$confirm" == "y" || "$confirm" == "Y" || -z "$confirm" ]] && reboot
}

# XanMod 子菜单
function menu_xanmod() {
    while true; do
        clear
        echo -e "============================================"
        echo -e "         ${SKYBLUE}XanMod 内核管理模块${PLAIN}"
        echo -e "============================================"
        echo -e "当前系统内核: ${YELLOW}$(uname -r)${PLAIN}"
        echo -e "--------------------------------------------"
        echo -e "${GREEN}1.${PLAIN} 安装/更新 XanMod (自动清理+可选删旧内核)"
        echo -e "${GREEN}2.${PLAIN} 卸载 XanMod (自动装回官方内核+清理垃圾)"
        echo -e "${GREEN}0.${PLAIN} 返回主菜单"
        echo -e "============================================"
        
        read -p "请输入选项 [0-2]: " sub_choice
        case $sub_choice in
            1) install_xanmod; break ;; 
            2) remove_xanmod; break ;;
            0) return ;;
            *) echo -e "${RED}输入错误。${PLAIN}"; sleep 1 ;;
        esac
    done
}

# =========================================================
#  主菜单入口
# =========================================================
function main_menu() {
    while true; do
        clear
        echo -e "============================================"
        echo -e "    ${SKYBLUE}VPS 极致性能多功能脚本 (Dev版)${PLAIN}"
        echo -e "============================================"
        # 新增：显示系统信息
        echo -e "当前系统: ${YELLOW}$(get_sys_info)${PLAIN}"
        echo -e "============================================"
        echo -e "${GREEN}1.${PLAIN} XanMod 内核管理 (第一步)"
        echo -e "${GREEN}2.${PLAIN} TCP Brutal 安装 (需先重启)"
        echo -e "${GREEN}3.${PLAIN} Sing-box 部署"
        echo -e "${GREEN}0.${PLAIN} 退出脚本"
        echo -e "============================================"
        
        read -p "请输入选项 [0-3]: " choice
        case $choice in
            1) menu_xanmod ;;
            2) echo -e "${YELLOW}待开发。${PLAIN}"; sleep 1 ;;
            3) echo -e "${YELLOW}待开发。${PLAIN}"; sleep 1 ;;
            0) exit 0 ;;
            *) echo -e "${RED}输入错误。${PLAIN}"; sleep 1 ;;
        esac
    done
}

main_menu