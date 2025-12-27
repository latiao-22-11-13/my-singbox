#!/bin/bash

# =================================================================
#   Linux Network Optimizer (Mux/Reality/Brutal Edition)
#   适配: DMIT / XanMod / BBRv3
#   核心功能: 自动 RPS 均衡 + Mux 专用 TCP 调优
# =================================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SYSCTL_PATH="/etc/sysctl.d/99-sysctl.conf"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}错误: 请使用 root 运行此脚本。${NC}" 
   exit 1
fi

clear
echo -e "${BLUE}==========================================================${NC}"
echo -e "${YELLOW}   VPS 网络优化脚本 (Reality+Mux+Brutal 专用版)${NC}"
echo -e "${BLUE}==========================================================${NC}"

# --- 1. 环境探测与计算 ---
echo -e "${YELLOW}>> 步骤 1/4: 硬件与网络探测${NC}"

# 1.1 探测网卡
default_iface=$(ip route get 8.8.8.8 | sed -n 's/.*dev \([^ ]*\).*/\1/p')
if [[ -z "$default_iface" ]]; then
    echo -e "${RED}错误: 无法探测到主网卡，请手动检查。${NC}"
    exit 1
fi
echo -e "-> 主网卡: ${GREEN}${default_iface}${NC}"

# 1.2 探测 CPU 核心数
cpu_count=$(nproc)
echo -e "-> CPU 核心数: ${GREEN}${cpu_count}${NC}"

# 1.3 输入带宽延迟 (用于计算 TCP 窗口)
read -p "请输入 VPS 带宽 (Mbps, 默认 500): " bandwidth_mbps
bandwidth_mbps=${bandwidth_mbps:-500}
read -p "请输入 平均延迟 (ms, 默认 150): " latency_ms
latency_ms=${latency_ms:-150}

# 计算 BDP (对于 Mux，我们需要更大的窗口来容纳多路并发)
# Mux 模式下，单连接承载所有流量，窗口必须足够大
bdp_bytes=$(awk -v bw="$bandwidth_mbps" -v lat="$latency_ms" 'BEGIN { printf "%.0f", (bw * 1000000 / 8) * (lat / 1000) }')
target_window=$(awk -v bdp="$bdp_bytes" 'BEGIN { printf "%.0f", bdp * 2.5 }') # 系数 2.5，比普通节点更大

# 限制范围 (32MB - 512MB)
min_window=33554432
max_window=536870912
if (( target_window < min_window )); then target_window=$min_window; fi
if (( target_window > max_window )); then target_window=$max_window; fi

echo -e "-> 针对 Mux 优化的 TCP 窗口: ${GREEN}$((target_window / 1024 / 1024)) MB${NC}"
echo ""

# --- 2. 核心功能: 自动计算 RPS/RFS (解决核心数不同问题) ---
echo -e "${YELLOW}>> 步骤 2/4: 配置 CPU 软中断均衡 (RPS/RFS)${NC}"

# 计算 RPS 掩码 (16进制)
# 1核=1, 2核=3, 4核=f, 8核=ff
rps_mask=$(printf '%x' $(( (1 << cpu_count) - 1 )))

# 创建 RPS 启动脚本
mkdir -p /opt/network-tuning
cat <<EOF > /opt/network-tuning/enable_rps.sh
#!/bin/bash
# Auto-generated RPS script for ${default_iface}
# CPU Cores: ${cpu_count} | Mask: ${rps_mask}

# 1. 开启 RPS (让网卡中断分发给所有核心)
for rps_file in /sys/class/net/${default_iface}/queues/rx-*/rps_cpus; do
    echo ${rps_mask} > \$rps_file
done

# 2. 开启 RFS (提升缓存命中率)
# 全局表大小 (32768)
echo 32768 > /proc/sys/net/core/rps_sock_flow_entries
# 单队列流限制 (全局/队列数)
flow_limit=\$(( 32768 / \$(ls -1 /sys/class/net/${default_iface}/queues/rx-*/rps_flow_cnt | wc -l) ))
for rfs_file in /sys/class/net/${default_iface}/queues/rx-*/rps_flow_cnt; do
    echo \$flow_limit > \$rfs_file
done

# 3. 优化网卡物理队列 (Txqueuelen)
ip link set dev ${default_iface} txqueuelen 10000
EOF

chmod +x /opt/network-tuning/enable_rps.sh
echo -e "-> RPS 策略脚本已生成 (掩码: ${rps_mask})。"

# --- 3. 写入 Sysctl (Mux 专用版) ---
echo -e "${YELLOW}>> 步骤 3/4: 应用内核优化 (Mux 专用)${NC}"

# 备份
[ -f "$SYSCTL_PATH" ] && cp "$SYSCTL_PATH" "${SYSCTL_PATH}.bak"

cat <<EOF > "$SYSCTL_PATH"
# =================================================================
#   Mux + Reality + Brutal Optimized
#   Interface: ${default_iface} | Cores: ${cpu_count}
#   Target Window: ${target_window} Bytes
# =================================================================

# --- 1. 拥塞控制 ---
# 配合 XanMod BBRv3
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# --- 2. 内存策略 (适配 Brutal/Mux 高吞吐) ---
# Mux 连接一旦断流影响巨大，预留更多原子内存防止网卡饥饿
vm.min_free_kbytes = 131072
vm.swappiness = 1
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
vm.vfs_cache_pressure = 50

# --- 3. TCP 缓冲区 (超大窗口) ---
# Mux 聚合了多路流量，底层 TCP 必须像"高速公路"一样宽
net.core.rmem_max = ${target_window}
net.core.wmem_max = ${target_window}
net.core.rmem_default = 2621440
net.core.wmem_default = 2621440
net.ipv4.tcp_rmem = 4096 262144 ${target_window}
net.ipv4.tcp_wmem = 4096 262144 ${target_window}
net.core.optmem_max = 524288

# --- 4. UDP 优化 (辅助 Brutal) ---
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.udp_early_demux = 1

# --- 5. Mux 稳定性调优 (关键) ---
# 必须关闭 ECN，Mux 连接最怕被中间设备丢包
net.ipv4.tcp_ecn = 0
net.ipv4.tcp_ecn_fallback = 1

# Mux 连接是长连接，需要更频繁的保活探测，防止 NAT 超时断开
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3

# 降低发送延迟，让数据包更快发出，而不是在缓冲区堆积
# 这对于"Reality+Mux"的实时性非常重要
net.ipv4.tcp_notsent_lowat = 32768 

# 开启重用，方便 sing-box 快速重启
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 65536
net.ipv4.tcp_max_syn_backlog = 8192

# 开启 SACK/DSACK 提升抗丢包能力
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1

# --- 6. 连接追踪 ---
net.netfilter.nf_conntrack_max = 524288
net.netfilter.nf_conntrack_buckets = 65536
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_udp_timeout_stream = 60

# --- 7. 系统级 ---
net.core.netdev_max_backlog = 65535
net.core.somaxconn = 65535
fs.file-max = 1000000
fs.nr_open = 2000000
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF

sysctl --system > /dev/null
echo -e "-> 内核参数已应用。"

# --- 4. 持久化与服务 ---
echo -e "${YELLOW}>> 步骤 4/4: 创建 Systemd 持久化服务${NC}"

# 创建 Systemd 服务来在开机时执行 RPS 脚本
cat <<EOF > /etc/systemd/system/network-tuning.service
[Unit]
Description=Network RPS/RFS & Tuning Script
After=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/network-tuning/enable_rps.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# 启用服务
systemctl daemon-reload
systemctl enable network-tuning.service > /dev/null 2>&1
systemctl start network-tuning.service

# 优化 LimitNOFILE
if ! grep -q "soft nofile 524288" /etc/security/limits.conf; then
    echo "* soft nofile 524288" >> /etc/security/limits.conf
    echo "* hard nofile 524288" >> /etc/security/limits.conf
    echo "root soft nofile 524288" >> /etc/security/limits.conf
    echo "root hard nofile 524288" >> /etc/security/limits.conf
fi

# 修正 sing-box 服务限制 (如果存在)
if systemctl list-units --full -all | grep -Fq "sing-box.service"; then
    mkdir -p /etc/systemd/system/sing-box.service.d
    echo -e "[Service]\nLimitNOFILE=524288" > /etc/systemd/system/sing-box.service.d/override.conf
    systemctl daemon-reload
    echo -e "-> 已修正 Sing-box 句柄限制。"
fi

echo ""
echo -e "${BLUE}==========================================================${NC}"
echo -e "${GREEN}  优化完成！${NC}"
echo -e "${YELLOW}  1. 已为 ${cpu_count} 核 CPU 开启 RPS 均衡 (掩码: ${rps_mask})${NC}"
echo -e "${YELLOW}  2. 已应用针对 Mux/Reality 的超大窗口优化${NC}"
echo -e "${YELLOW}  3. 建议重启 VPS 或 sing-box 服务以确保所有生效${NC}"
echo -e "${BLUE}==========================================================${NC}"