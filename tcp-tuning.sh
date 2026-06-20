#!/bin/bash

# =========================================================
#  TCP 内核调优脚本 (Mux/Reality/Brutal 专用)
#  合并自 auto-tcp.sh + net-optimization.sh 精华参数
# =========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
PLAIN='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "${RED}错误: 必须使用 root 用户运行此脚本！${PLAIN}" && exit 1

SYSCTL_CONF="/etc/sysctl.d/99-sysctl.conf"
LIMITS_CONF="/etc/security/limits.d/99-limits.conf"
SYSTEMD_CONF="/etc/systemd/system.conf.d/99-system.conf"
RPS_SCRIPT="/opt/network-tuning/enable_rps.sh"
NIC_SERVICE="/etc/systemd/system/nic-tuning.service"

# =========================================================
#  步骤 1: 硬件探测 + BDP 计算
# =========================================================
echo -e "${SKYBLUE}==========================================================${PLAIN}"
echo -e "${YELLOW}  TCP 内核调优 (Mux/Reality/Brutal 专用)${PLAIN}"
echo -e "${SKYBLUE}==========================================================${PLAIN}"

# 探测网卡
default_iface=$(ip route get 8.8.8.8 2>/dev/null | sed -n 's/.*dev \([^ ]*\).*/\1/p')
[[ -z "$default_iface" ]] && default_iface="eth0"
echo -e "-> 主网卡: ${GREEN}${default_iface}${PLAIN}"

# 探测 CPU
cpu_count=$(nproc)
echo -e "-> CPU 核心: ${GREEN}${cpu_count}${PLAIN}"

# 输入带宽延迟
read -p "请输入 VPS 带宽 (Mbps, 默认 1000): " bandwidth_mbps
bandwidth_mbps=${bandwidth_mbps:-1000}
read -p "请输入平均延迟 (ms, 默认 72): " latency_ms
latency_ms=${latency_ms:-72}

# BDP × 2.5 (Mux 单连接聚合流量)
bdp_bytes=$(( bandwidth_mbps * 125 * latency_ms ))
target_window=$(( bdp_bytes * 5 / 2 ))

# 限制范围 32MB - 512MB
min_win=33554432
max_win=536870912
(( target_window < min_win )) && target_window=$min_win
(( target_window > max_win )) && target_window=$max_win

echo -e "-> BDP: ${GREEN}$((bdp_bytes/1024/1024)) MB${PLAIN}  TCP窗口: ${GREEN}$((target_window/1024/1024)) MB${PLAIN}"
echo ""

# =========================================================
#  步骤 2: RPS/RFS (CPU 软中断均衡)
# =========================================================
echo -e "${YELLOW}>> 配置 RPS/RFS...${PLAIN}"

rps_mask=$(printf '%x' $(( (1 << cpu_count) - 1 )))

mkdir -p /opt/network-tuning
cat > "$RPS_SCRIPT" << RPS_EOF
#!/bin/bash
# RPS/RFS for ${default_iface} | CPU: ${cpu_count} | Mask: ${rps_mask}
for rps_file in /sys/class/net/${default_iface}/queues/rx-*/rps_cpus; do
    echo ${rps_mask} > \$rps_file
done
echo 32768 > /proc/sys/net/core/rps_sock_flow_entries
flow_limit=\$(( 32768 / \$(ls -1 /sys/class/net/${default_iface}/queues/rx-*/rps_flow_cnt 2>/dev/null | wc -l) ))
(( flow_limit < 1 )) && flow_limit=1
for rfs_file in /sys/class/net/${default_iface}/queues/rx-*/rps_flow_cnt; do
    echo \$flow_limit > \$rfs_file
done
ip link set dev ${default_iface} txqueuelen 10000
RPS_EOF
chmod +x "$RPS_SCRIPT"

# 创建 systemd 服务持久化
cat > /etc/systemd/system/network-tuning.service << SVC_EOF
[Unit]
Description=Network RPS/RFS Tuning
After=network-online.target

[Service]
Type=oneshot
ExecStart=${RPS_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVC_EOF
systemctl daemon-reload
systemctl enable network-tuning.service > /dev/null 2>&1
bash "$RPS_SCRIPT"
echo -e "${GREEN}RPS/RFS 已配置。${PLAIN}"

# =========================================================
#  步骤 3: 网卡 Offload
# =========================================================
echo -e "${YELLOW}>> 配置网卡 Offload...${PLAIN}"

command -v ethtool > /dev/null 2>&1 || apt-get install -y ethtool > /dev/null 2>&1

cat > "$NIC_SERVICE" << NIC_EOF
[Unit]
Description=NIC Offload Tuning
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ethtool -K ${default_iface} tso on gso on gro on rx-gro-hw off lro off
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
NIC_EOF
systemctl daemon-reload
systemctl enable nic-tuning.service > /dev/null 2>&1
ethtool -K "$default_iface" tso on gso on gro on rx-gro-hw off lro off 2>/dev/null
echo -e "${GREEN}网卡 Offload 已配置。${PLAIN}"

# =========================================================
#  步骤 4: 写入 Sysctl
# =========================================================
echo -e "${YELLOW}>> 写入内核参数...${PLAIN}"

# 备份旧配置
[[ -f "$SYSCTL_CONF" ]] && cp "$SYSCTL_CONF" "${SYSCTL_CONF}.bak.$(date +%Y%m%d%H%M%S)"
[[ -f /etc/sysctl.conf ]] && { cp /etc/sysctl.conf "/etc/sysctl.conf.bak.$(date +%Y%m%d%H%M%S)"; rm -f /etc/sysctl.conf; }

cat > "$SYSCTL_CONF" << EOF
# =========================================================
#  TCP 内核调优 (Mux/Reality/Brutal 专用)
#  BDP: ${bdp_bytes} bytes | Window: ${target_window} bytes
#  合并自 auto-tcp.sh + net-optimization.sh
# =========================================================

# --- 拥塞控制 ---
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# --- TCP 缓冲区 (BDP × 2.5, Mux 专用大窗口) ---
net.core.rmem_max = ${target_window}
net.core.wmem_max = ${target_window}
net.core.rmem_default = 2621440
net.core.wmem_default = 2621440
net.ipv4.tcp_rmem = 4096 262144 ${target_window}
net.ipv4.tcp_wmem = 4096 262144 ${target_window}
net.core.optmem_max = 524288

# --- UDP ---
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.udp_early_demux = 1

# --- Mux 稳定性 ---
net.ipv4.tcp_ecn = 0
net.ipv4.tcp_ecn_fallback = 1
net.ipv4.tcp_notsent_lowat = 32768
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_autocorking = 0
net.ipv4.tcp_limit_output_bytes = 3145728

# --- 连接管理 ---
net.ipv4.tcp_tw_reuse = 2
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_max_tw_buckets = 65536
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_orphans = 32768
net.ipv4.tcp_abort_on_overflow = 0
net.ipv4.ip_local_port_range = 1024 65535

# --- 重传优化 (快速失败) ---
net.ipv4.tcp_retries1 = 3
net.ipv4.tcp_retries2 = 5
net.ipv4.tcp_orphan_retries = 3
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 3

# --- Keepalive ---
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3

# --- TCP 基础 ---
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_frto = 2
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = -1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_no_metrics_save = 0
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_mtu_probing = 0
net.ipv4.tcp_low_latency = 0
net.ipv4.tcp_stdurg = 0
net.ipv4.tcp_rfc1337 = 0
net.ipv4.ip_no_pmtu_disc = 0

# --- Conntrack ---
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_buckets = 32768
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 30
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 120

# --- 转发 ---
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1

# --- 安全 ---
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.default.arp_ignore = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- 网卡队列 ---
net.core.netdev_max_backlog = 32768
net.core.netdev_budget_usecs = 8000
net.core.netdev_budget = 800
net.core.dev_weight = 96
net.core.dev_weight_rx_bias = 1
net.core.dev_weight_tx_bias = 1
net.core.somaxconn = 65535
net.ipv4.route.gc_timeout = 300
net.core.rps_sock_flow_entries = 32768

# --- VM ---
vm.dirty_background_ratio = 3
vm.dirty_ratio = 20
vm.dirty_expire_centisecs = 1500
vm.dirty_writeback_centisecs = 200
vm.swappiness = 0
vm.page-cluster = 0
vm.compaction_proactiveness = 0
vm.vfs_cache_pressure = 50
vm.watermark_boost_factor = 0
vm.watermark_scale_factor = 200
vm.min_free_kbytes = 131072

# --- 文件系统 ---
fs.file-max = 1000000
fs.nr_open = 2000000
fs.inotify.max_user_instances = 4096
fs.inotify.max_user_watches = 524288
fs.aio-max-nr = 1048576

# --- 内核 ---
kernel.pid_max = 65535
kernel.panic = 5
kernel.sysrq = 1
kernel.sched_autogroup_enabled = 0
kernel.timer_migration = 0
EOF

sysctl --system > /dev/null 2>&1
echo -e "${GREEN}内核参数已应用。${PLAIN}"

# =========================================================
#  步骤 5: Limits + 禁用休眠
# =========================================================
echo -e "${YELLOW}>> 配置 limits + 系统优化...${PLAIN}"

mkdir -p /etc/security/limits.d
cat > "$LIMITS_CONF" << EOF
* soft     nproc    524288
* hard     nproc    524288
* soft     nofile   524288
* hard     nofile   524288
root soft  nproc    524288
root hard  nproc    524288
root soft  nofile   524288
root hard  nofile   524288
EOF

# systemd limits
mkdir -p /etc/systemd/system.conf.d
cat > "$SYSTEMD_CONF" << EOF
[Manager]
DefaultLimitNOFILE=524288
DefaultLimitNPROC=524288
EOF

# sing-box service limits
if systemctl list-units --full -all | grep -Fq "sing-box.service"; then
    mkdir -p /etc/systemd/system/sing-box.service.d
    echo -e "[Service]\nLimitNOFILE=524288" > /etc/systemd/system/sing-box.service.d/override.conf
fi

# PAM limits
for f in /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
    if [ -f "$f" ] && ! grep -qE 'session.*pam_limits\.so' "$f" 2>/dev/null; then
        echo "session required pam_limits.so" >> "$f"
    fi
done

# 禁用休眠
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target > /dev/null 2>&1

# 加载模块
modprobe tcp_bbr 2>/dev/null
modprobe sch_fq 2>/dev/null
echo -e "tcp_bbr\nsch_fq" > /etc/modules-load.d/bbr-fq.conf

# GRUB 超时
if [[ -f /etc/default/grub ]]; then
    sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=0/' /etc/default/grub
    command -v update-grub > /dev/null 2>&1 && update-grub > /dev/null 2>&1
fi

# 时间同步
if command -v timedatectl > /dev/null 2>&1; then
    timedatectl set-ntp true > /dev/null 2>&1
    timedatectl set-timezone Asia/Shanghai > /dev/null 2>&1
fi

# 文件描述符
if ! grep -q "soft nofile 524288" /etc/security/limits.conf 2>/dev/null; then
    echo "* soft nofile 524288" >> /etc/security/limits.conf
    echo "* hard nofile 524288" >> /etc/security/limits.conf
fi

systemctl daemon-reexec > /dev/null 2>&1
echo -e "${GREEN}系统优化完成。${PLAIN}"

# =========================================================
#  完成
# =========================================================
echo ""
echo -e "${SKYBLUE}==========================================================${PLAIN}"
echo -e "${GREEN}  调优完成！${PLAIN}"
echo -e "  网卡: ${default_iface} | CPU: ${cpu_count}核 | RPS掩码: ${rps_mask}"
echo -e "  TCP窗口: $((target_window/1024/1024))MB (BDP×2.5)"
echo -e "  拥塞: bbr + fq | ECN: 关闭"
echo -e ""
echo -e "  ${YELLOW}建议重启 VPS 以确保所有参数生效${PLAIN}"
echo -e "${SKYBLUE}==========================================================${PLAIN}"
