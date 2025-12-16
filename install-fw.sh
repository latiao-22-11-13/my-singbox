#!/usr/bin/env bash
set -euo pipefail

clear_screen() {
    if command -v tput >/dev/null 2>&1; then
        tput clear
    else
        printf "\033c"
    fi
}

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "[ERR] 请用 root 执行：sudo $0"
  exit 1
fi

if [[ -t 0 ]]; then
  stty sane 2>/dev/null || true
  stty erase '^?' 2>/dev/null || stty erase '^H' 2>/dev/null || true
fi

NFT_CONF="/etc/nftables.conf"
NFT_CONF_BAK="/etc/nftables.conf.fw-manager.bak"

SB_SCRIPT="/usr/local/sbin/singbox-ports.sh"
DEFAULTS_FILE="/etc/default/nftables-port-sync"
SVC_FILE="/etc/systemd/system/nftables-port-sync.service"

trim() { awk '{$1=$1};1' <<<"${1:-}"; }

pause() {
  echo
  read -r -e -p "按回车继续..." _ || true
}

normalize_ports() {
  local raw
  raw="$(trim "${1:-}")"
  raw="${raw//,/ }"
  raw="$(echo "$raw" | tr -s ' ' ' ')"
  [[ -z "$raw" ]] && return 0

  local out=() p
  for p in $raw; do
    [[ "$p" =~ ^[0-9]+$ ]] || { echo "[ERR] 端口必须是数字：$p" >&2; return 1; }
    (( p>=1 && p<=65535 )) || { echo "[ERR] 端口范围必须 1-65535：$p" >&2; return 1; }
    out+=("$p")
  done

  printf "%s\n" "${out[@]}" | sort -n -u | paste -sd, -
}

guess_ssh_ports() {
  local ports=""
  ports="$(ss -lntpH 2>/dev/null | awk '/sshd/ {n=split($4,a,":"); p=a[n]; if(p~/^[0-9]+$/) print p}' | sort -u | paste -sd, - || true)"
  if [[ -z "$ports" && -f /etc/ssh/sshd_config ]]; then
    ports="$(awk 'BEGIN{IGNORECASE=1} $1=="port"{print $2}' /etc/ssh/sshd_config 2>/dev/null | sort -u | paste -sd, - || true)"
  fi
  [[ -z "$ports" ]] && ports="22"
  echo "$ports"
}

guess_sb_ports() {
  local ports=""
  ports="$(ss -lntpH 2>/dev/null | awk '/sing-box/ { addr=$4; n=split(addr,a,":"); p=a[n]; if (p ~ /^[0-9]+$/) print p }' | sort -u | paste -sd, - || true)"
  echo "$ports"
}

backup_nft_conf_once() {
  if [[ -f "$NFT_CONF" && ! -f "$NFT_CONF_BAK" ]]; then
    cp -a "$NFT_CONF" "$NFT_CONF_BAK"
    echo "[OK] 已备份原 $NFT_CONF -> $NFT_CONF_BAK"
  fi
}

restore_or_remove_nft_conf() {
  if [[ -f "$NFT_CONF_BAK" ]]; then
    cp -a "$NFT_CONF_BAK" "$NFT_CONF"
    rm -f "$NFT_CONF_BAK"
    echo "[OK] 已恢复原始 $NFT_CONF（并删除备份）"
  else
    rm -f "$NFT_CONF" 2>/dev/null || true
    echo "[OK] 未发现备份，已删除 $NFT_CONF"
  fi
}

write_files_install() {
  local ssh_ports="$1"
  local sb_ports="$2"

  cat >"$NFT_CONF" <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {

  set ssh_tcp_ports {
    type inet_service
    elements = { ${ssh_ports} }
  }

  set sb_tcp_ports {
  type inet_service
  elements = { ${sb_ports} }
  }

  chain input {
    type filter hook input priority 0;
    policy drop;

    iif lo accept
    ip6 nexthdr icmpv6 accept
    ct state established,related accept

    tcp dport @ssh_tcp_ports ct state new limit rate 10/minute accept

    tcp dport @sb_tcp_ports ct count over 80 drop
    tcp dport @sb_tcp_ports ct state new limit rate over 30/second drop
    tcp dport @sb_tcp_ports ct state new accept
  }

  chain forward {
    type filter hook forward priority 0;
    policy drop;
  }

  chain output {
    type filter hook output priority 0;
    policy accept;
  }
}
EOF

  cat >"$SB_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

FAMILY="inet"
TABLE="filter"
SB_SET="sb_tcp_ports"
MGMT_SET="ssh_tcp_ports"

DEFAULTS_FILE="/etc/default/nftables-port-sync"

SSH_PORTS_OVERRIDE=""
SB_PORTS_OVERRIDE=""
if [[ -f "$DEFAULTS_FILE" ]]; then
  source "$DEFAULTS_FILE" || true
fi

normalize_ports() {
  local raw="${1:-}"
  raw="${raw//,/ }"
  raw="$(echo "$raw" | tr -s ' ' ' ' | awk '{$1=$1};1')"
  [[ -z "$raw" ]] && return 0
  local out=() p
  for p in $raw; do
    [[ "$p" =~ ^[0-9]+$ ]] || return 1
    (( p>=1 && p<=65535 )) || return 1
    out+=("$p")
  done
  printf "%s\n" "${out[@]}" | sort -n -u | paste -sd, -
}

SB_LIST=""
if [[ -n "${SB_PORTS_OVERRIDE:-}" ]]; then
  SB_LIST="$(normalize_ports "$SB_PORTS_OVERRIDE" || true)"
else
  mapfile -t SB_PORTS < <(
    ss -lntpH | awk '
      /sing-box/ {
        addr=$4
        n=split(addr, a, ":")
        port=a[n]
        if (port ~ /^[0-9]+$/) print port
      }
    ' | sort -u
  )
  if [[ ${#SB_PORTS[@]} -gt 0 ]]; then
    SB_LIST="$(printf "%s\n" "${SB_PORTS[@]}" | paste -sd, -)"
  fi
fi

MGMT_LIST=""
if [[ -n "${SSH_PORTS_OVERRIDE:-}" ]]; then
  MGMT_LIST="$(normalize_ports "$SSH_PORTS_OVERRIDE" || true)"
fi

if [[ -z "$MGMT_LIST" ]]; then
  mapfile -t MGMT_PORTS < <(
    ss -lntpH | awk '
      /sshd/ {
        addr=$4
        n=split(addr, a, ":")
        port=a[n]
        if (port ~ /^[0-9]+$/) print port
      }
    ' | sort -u
  )

  if [[ ${#MGMT_PORTS[@]} -eq 0 ]]; then
    mapfile -t MGMT_PORTS < <(
      awk 'BEGIN{IGNORECASE=1} $1=="port"{print $2}' /etc/ssh/sshd_config 2>/dev/null | sort -u
    )
  fi

  if [[ ${#MGMT_PORTS[@]} -eq 0 ]]; then
    MGMT_PORTS=(22)
  fi
  MGMT_LIST="$(printf "%s\n" "${MGMT_PORTS[@]}" | paste -sd, -)"
fi

nft list table "$FAMILY" "$TABLE" >/dev/null 2>&1 || nft add table "$FAMILY" "$TABLE"
nft list set "$FAMILY" "$TABLE" "$MGMT_SET" >/dev/null 2>&1 || \
  nft add set "$FAMILY" "$TABLE" "$MGMT_SET" '{ type inet_service; }'
nft list set "$FAMILY" "$TABLE" "$SB_SET" >/dev/null 2>&1 || \
  nft add set "$FAMILY" "$TABLE" "$SB_SET" '{ type inet_service; }'

nft -f - <<EOF_IN
flush set $FAMILY $TABLE $MGMT_SET
add element $FAMILY $TABLE $MGMT_SET { $MGMT_LIST }
EOF_IN

if [[ -n "$SB_LIST" ]]; then
  nft -f - <<EOF_SB
flush set $FAMILY $TABLE $SB_SET
add element $FAMILY $TABLE $SB_SET { $SB_LIST }
EOF_SB
else
  echo "[INFO] sb_tcp_ports 未更新（当前无 sing-box 监听端口且未设置 SB_PORTS_OVERRIDE）"
fi

echo "[OK] ssh_tcp_ports => $MGMT_LIST"
[[ -n "$SB_LIST" ]] && echo "[OK] sb_tcp_ports  => $SB_LIST"
EOF
  chmod 0755 "$SB_SCRIPT"

  cat >"$DEFAULTS_FILE" <<EOF
SSH_PORTS_OVERRIDE="${ssh_ports}"
SB_PORTS_OVERRIDE="${sb_ports}"
EOF
  chmod 0644 "$DEFAULTS_FILE"

  cat >"$SVC_FILE" <<'EOF'
[Unit]
Description=Sync nftables port sets (ssh_tcp_ports / sb_tcp_ports)
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 5
ExecStart=/usr/local/sbin/singbox-ports.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
}

install_fw() {
  echo "========== 安装 =========="

  local default_ssh in_ssh in_sb ssh_ports sb_ports

  default_ssh="$(guess_ssh_ports)"
  echo "检测到 SSH 端口：${default_ssh}"
  read -r -e -p "请输入要放行的 SSH 端口（可多端口，用空格/逗号分隔）[默认: ${default_ssh}] : " in_ssh || true
  in_ssh="$(trim "${in_ssh:-}")"
  [[ -z "$in_ssh" ]] && in_ssh="$default_ssh"
  ssh_ports="$(normalize_ports "$in_ssh")"

  default_sb="$(guess_sb_ports)"
  if [[ -n "$default_sb" ]]; then
    echo "检测到 sing-box 正在监听的 TCP 端口：${default_sb}"
    read -r -e -p "请输入需要放行的 sing-box TCP 端口（可多端口，空格/逗号分隔）[默认: ${default_sb}] : " in_sb || true
    in_sb="$(trim "${in_sb:-}")"
    [[ -z "$in_sb" ]] && in_sb="$default_sb"
    sb_ports="$(normalize_ports "$in_sb")"
  else
    echo
    echo "[ERR] 未检测到 sing-box 正在监听的 TCP 端口，本次安装将中止。"
    echo "      请先启动 sing-box（确保进程名包含 sing-box 且有 TCP 监听），然后再运行安装。"
    echo
    return 1
  fi

  echo
  echo "[INFO] 你输入的端口："
  echo "  SSH 放行端口：${ssh_ports}"
  echo "  sing-box 放行端口(兜底)：${sb_ports}"
  echo

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y nftables iproute2

  backup_nft_conf_once

  write_files_install "$ssh_ports" "$sb_ports"

  systemctl daemon-reload

  systemctl enable --now nftables
  nft -f "$NFT_CONF"

  systemctl enable nftables-port-sync.service
  systemctl start nftables-port-sync.service || true

  echo
  echo "[DONE] 安装完成。检查命令："
  echo "  nft list ruleset"
  echo "  nft list set inet filter ssh_tcp_ports"
  echo "  nft list set inet filter sb_tcp_ports"
  echo "  systemctl status nftables --no-pager"
  echo "  systemctl status nftables-port-sync.service --no-pager"
  echo
  echo "[INFO] 若要卸载回滚 nftables.conf：卸载会自动使用 $NFT_CONF_BAK 恢复。"
}

uninstall_fw() {
  echo "========== 卸载 =========="
  echo "[INFO] 卸载将："
  echo "  - 删除本脚本安装的 service / defaults / 脚本文件"
  echo "  - 恢复或删除 nftables.conf"
  echo "  - 关闭 nftables 服务并取消自启（不卸载 nftables 包）"
  echo

  read -r -e -p "确认卸载？输入 YES 继续：" confirm || true
  confirm="$(trim "${confirm:-}")"
  if [[ "$confirm" != "YES" ]]; then
    echo "[INFO] 已取消卸载。"
    return 0
  fi

  systemctl stop nftables-port-sync.service 2>/dev/null || true
  systemctl disable nftables-port-sync.service 2>/dev/null || true

  rm -f "$SVC_FILE" 2>/dev/null || true
  rm -f "$DEFAULTS_FILE" 2>/dev/null || true
  rm -f "$SB_SCRIPT" 2>/dev/null || true

  restore_or_remove_nft_conf

  systemctl disable --now nftables 2>/dev/null || true

  systemctl daemon-reload || true

  echo
  echo "[DONE] 卸载完成。你可以检查："
  echo "  systemctl status nftables-port-sync.service --no-pager"
  echo "  systemctl status nftables --no-pager"
  echo "  ls -l $SVC_FILE $DEFAULTS_FILE $SB_SCRIPT $NFT_CONF $NFT_CONF_BAK"
}

show_menu() {
  clear_screen
  echo
  echo "=============================="
  echo "   NFTables 防火墙管理菜单"
  echo "=============================="
  echo "1) 安装"
  echo "2) 卸载"
  echo "0) 退出"
  echo "------------------------------"
}

main() {
  while true; do
    show_menu
    read -r -e -p "请选择 [0-2]：" choice || true
    choice="$(trim "${choice:-}")"
    case "$choice" in
      1) install_fw; pause ;;
      2) uninstall_fw; pause ;;
      0) echo "退出。"; exit 0 ;;
      *) echo "[ERR] 请输入 0/1/2"; pause ;;
    esac
  done
}

main