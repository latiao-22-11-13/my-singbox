#!/bin/bash

# =========================================================
#  Part 2: TCP Brutal 独立管理脚本 (Final v3 - Auto Clean)
# =========================================================

# 定义颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
PLAIN='\033[0m'

# 检查 Root 权限
[[ $EUID -ne 0 ]] && echo -e "${RED}错误: 必须使用 root 用户运行此脚本！${PLAIN}" && exit 1

# =========================================================
#  [新增] 强制环境检查机制
# =========================================================
function check_strict_env() {
    # 1. 系统版本强制检查 (仅允许 Debian/Ubuntu)
    local is_valid_os=0
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "${ID}" == "debian" || "${ID}" == "ubuntu" ]]; then
            is_valid_os=1
        fi
    elif [[ -f /etc/issue ]]; then
        if grep -q -E -i "debian|ubuntu" /etc/issue; then
            is_valid_os=1
        fi
    fi

    if [[ ${is_valid_os} -eq 0 ]]; then
        echo -e "${RED}错误: 本脚本仅支持 Debian 或 Ubuntu 系统。${PLAIN}"
        echo -e "${YELLOW}检测到非受支持的系统，已停止运行。${PLAIN}"
        exit 1
    fi

    # 2. 虚拟化环境强制检查 (拦截 OpenVZ, LXC, Docker 等无独立内核环境)
    # 检查 A: systemd-detect-virt
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        local virt_type=$(systemd-detect-virt)
        if [[ "${virt_type}" == "lxc" || "${virt_type}" == "openvz" || "${virt_type}" == "docker" || "${virt_type}" == "container" ]]; then
            echo -e "${RED}错误: 检测到容器虚拟化环境 (${virt_type})。${PLAIN}"
            echo -e "${RED}TCP Brutal 需要独立内核权限 (KVM/Xen/VMware/实体机)，无法在容器中编译安装。${PLAIN}"
            exit 1
        fi
    fi

    # 检查 B: 传统 OpenVZ 特征
    if [[ -f /proc/user_beancounters ]] || [[ -d /proc/vz ]]; then
        echo -e "${RED}错误: 检测到 OpenVZ 环境，不支持内核模块安装。${PLAIN}"
        exit 1
    fi
    
    # 检查 C: 简单判断 /boot 是否为空 (防止极简容器系统)
    if [[ ! -f /boot/vmlinuz-$(uname -r) ]] && [[ ! -f /boot/config-$(uname -r) ]]; then
         # 仅做强警告，防止是某些特殊定制系统
         echo -e "${YELLOW}警告: 未检测到 /boot 下的内核文件，后续编译可能失败。${PLAIN}"
    fi
}

# 立即执行环境检查，不符合直接退出
check_strict_env

# =========================================================
#  基础检测与清理函数 (原脚本内容)
# =========================================================

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
        release="unknown"
    fi
}

function check_brutal_status() {
    if lsmod | grep -q "brutal"; then return 0; else return 1; fi
}

function get_status_str() {
    if check_brutal_status; then
        echo -e "${GREEN}运行中 (Active)${PLAIN}"
    else
        echo -e "${RED}未运行 (Inactive)${PLAIN}"
    fi
}

# 系统垃圾清理 (Autoremove & Clean)
function sys_cleanup() {
    echo -e "${YELLOW}正在执行系统垃圾清理 (autoremove & clean)...${PLAIN}"
    if [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
        apt-get autoremove -y > /dev/null 2>&1
        apt-get clean > /dev/null 2>&1
    elif [[ "${release}" == "centos" ]]; then
        yum autoremove -y > /dev/null 2>&1
        yum clean all > /dev/null 2>&1
    fi
    echo -e "${GREEN}清理完成。${PLAIN}"
}

# =========================================================
#  核心逻辑
# =========================================================

function install_brutal() {
    clear
    echo -e "==================================================="
    echo -e "       TCP Brutal 智能安装 (Clang/GCC 自适应)"
    echo -e "==================================================="
    
    check_sys
    kernel_version=$(uname -r)
    echo -e "当前系统: ${SKYBLUE}${release}${PLAIN}"
    echo -e "当前内核: ${SKYBLUE}${kernel_version}${PLAIN}"
    
    # 1. 编译器检测
    echo -e "${YELLOW}正在检测内核编译器类型...${PLAIN}"
    if cat /proc/version | grep -i -q "clang"; then
        COMPILER="clang"
        echo -e "检测结果: ${GREEN}Clang / LLVM${PLAIN} (XanMod 特性)"
    else
        COMPILER="gcc"
        echo -e "检测结果: ${GREEN}GCC${PLAIN} (通用)"
    fi

    # 2. 清理旧环境
    if lsmod | grep -q "brutal"; then
        rmmod brutal 2>/dev/null
        rmmod tcp_brutal 2>/dev/null
    fi
    rm -rf /usr/src/tcp-brutal

    # 3. 安装依赖
    echo -e "${YELLOW}正在安装编译依赖...${PLAIN}"
    if [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
        apt-get update -y > /dev/null 2>&1
        deps_list="git pkg-config linux-headers-${kernel_version}"
        if [[ "$COMPILER" == "clang" ]]; then
            deps_list="${deps_list} clang llvm lld build-essential"
        else
            deps_list="${deps_list} build-essential"
        fi
        echo -e "正在安装: ${deps_list} ..."
        apt-get install -y $deps_list
    elif [[ "${release}" == "centos" ]]; then
        yum groupinstall -y "Development Tools"
        yum install -y "kernel-headers-${kernel_version}" "kernel-devel-${kernel_version}" git
        if [[ "$COMPILER" == "clang" ]]; then
            yum install -y clang llvm
        fi
    fi

    if [ $? -ne 0 ]; then
        echo -e "${RED}[失败] 依赖安装出错。${PLAIN}"
        read -p "按回车键返回..."
        return
    fi

    # 4. 拉取源码
    echo -e "${YELLOW}正在从 GitHub 拉取最新源码...${PLAIN}"
    git clone --depth=1 https://github.com/apernet/tcp-brutal.git /usr/src/tcp-brutal
    if [ $? -ne 0 ]; then
        echo -e "${RED}[失败] 源码下载失败。${PLAIN}"
        return
    fi

    # 5. 编译
    echo -e "${YELLOW}正在编译...${PLAIN}"
    cd /usr/src/tcp-brutal
    if [[ "$COMPILER" == "clang" ]]; then
        make LLVM=1
    else
        make
    fi
    
    if [ ! -f "brutal.ko" ]; then
        echo -e "${RED}[失败] 编译错误，未生成 brutal.ko。${PLAIN}"
        read -p "按回车键返回..."
        return
    fi

    # 6. 手动安装
    echo -e "${YELLOW}正在安装模块...${PLAIN}"
    MODULE_DIR="/lib/modules/${kernel_version}/extra"
    mkdir -p "$MODULE_DIR"
    cp brutal.ko "$MODULE_DIR/"
    
    echo -e "${YELLOW}刷新依赖并加载...${PLAIN}"
    depmod -a
    modprobe brutal

    # 7. 验证
    if check_brutal_status; then
        echo -e "${GREEN}>>> TCP Brutal 安装成功！${PLAIN}"
        echo "brutal" > /etc/modules-load.d/brutal.conf
        echo -e "已添加开机自启配置。"
        
        # 安装完成后也顺手清理一下 apt 缓存
        sys_cleanup
        
        read -p "按回车键返回菜单..."
    else
        echo -e "${RED}[失败] 加载失败。请检查 dmesg。${PLAIN}"
        read -p "按回车键返回..."
    fi
}

function remove_brutal() {
    clear
    check_sys # 确保 release 变量存在，否则下面的 purge 会报错
    echo -e "============================================"
    echo -e "          卸载 TCP Brutal & 清理环境"
    echo -e "============================================"
    echo -e "${YELLOW}正在卸载模块...${PLAIN}"
    
    # 1. 移除配置和模块
    rm -f /etc/modules-load.d/brutal.conf
    rm -f /etc/modules-load.d/tcp_brutal.conf
    
    if check_brutal_status; then
        rmmod brutal 2>/dev/null
        rmmod tcp_brutal 2>/dev/null
    fi
    
    # 2. 删除文件
    rm -rf /usr/src/tcp-brutal
    local kver=$(uname -r)
    find /lib/modules/"${kver}" -name "brutal.ko" -delete
    find /lib/modules/"${kver}" -name "tcp_brutal.ko" -delete
    depmod -a
    echo -e "${GREEN}模块文件已删除。${PLAIN}"

    # 3. 询问是否深度清理 (默认 Y)
    echo -e "--------------------------------------------"
    echo -e "${YELLOW}为了编译 Brutal，之前安装了以下工具可能已不再需要：${PLAIN}"
    echo -e "  - linux-headers-${kver}"
    echo -e "  - clang, llvm, lld (如果是 Clang 内核)"
    echo -e "--------------------------------------------"
    
    # 修改点：默认 Y
    read -p "是否卸载这些编译工具以节省空间? [Y/n] (默认Y): " clean_deps
    clean_deps=${clean_deps:-y}
    
    if [[ "$clean_deps" == "y" || "$clean_deps" == "Y" ]]; then
        echo -e "${YELLOW}正在清理编译依赖...${PLAIN}"
        
        pkgs_to_remove="linux-headers-${kver}"
        
        if cat /proc/version | grep -i -q "clang"; then
            pkgs_to_remove="$pkgs_to_remove clang llvm lld"
        fi
        
        if [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
            apt-get purge -y $pkgs_to_remove
        elif [[ "${release}" == "centos" ]]; then
            yum remove -y $pkgs_to_remove
        fi
        echo -e "${GREEN}编译环境已清理。${PLAIN}"
    fi

    # 4. 最后执行全系统自动清理
    sys_cleanup
    
    echo -e "${GREEN}卸载及清理全部完成。${PLAIN}"
    read -p "按回车键返回..."
}

function show_menu() {
    while true; do
        clear
        echo -e "============================================"
        echo -e "    ${SKYBLUE}TCP Brutal 独立管理工具 (Part 2)${PLAIN}"
        echo -e "============================================"
        echo -e "当前内核: ${YELLOW}$(uname -r)${PLAIN}"
        echo -e "运行状态: $(get_status_str)"
        echo -e "============================================"
        echo -e "${GREEN}1.${PLAIN} 安装 / 更新 TCP Brutal (智能适配)"
        echo -e "${GREEN}2.${PLAIN} 卸载 TCP Brutal (含垃圾清理)"
        echo -e "${GREEN}0.${PLAIN} 退出"
        echo -e "============================================"
        
        read -p "请输入选项 [0-2]: " choice
        case $choice in
            1) install_brutal ;;
            2) remove_brutal ;;
            0) exit 0 ;;
            *) echo -e "${RED}输入错误。${PLAIN}"; sleep 1 ;;
        esac
    done
}

show_menu