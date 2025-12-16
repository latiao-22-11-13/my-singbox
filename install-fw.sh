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

PORTSYNC_SCRIPT="/usr/local/sbin/nftables-port-sync.sh"
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
  [[ -z "$raw" ]] && { echo ""; return 0; }

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
  ports="$(ss -lntpH 2>/dev/null | awk '/sshd/ {n=split($4,a,":"); p=a[n]; if(p~/^[0-9]+$/) print p}' \
    | sort -u | paste -sd, - || true)"
  if [[ -z "$ports" && -f /etc/ssh/sshd_config ]]; then
    ports="$(awk 'BEGIN{IGNORECASE=1} $1=="port"{print $2}' /etc/ssh/sshd_config 2>/dev/null \
      | sort -u | paste -sd, - || true)"
  fi
  [[ -z "$ports" ]] && ports="22"
  echo "$ports"
}

guess_sb_ports() {
  local ports=""
  ports="$(ss -lntpH 2>/dev/null | awk '/sing-box/ { addr=$4; n=split(addr,a,":"); p=a[n]; if (p ~ /^[0-9]+$/) print p }' \
    | sort -u | paste -sd, - || true)"
  echo "$ports"
}

guess_sui_ports() {
  local ports=""
  ports="$(ss -lntpH 2>/dev/null | awk '/\("sui"/ { addr=$4; n=split(addr,a,":"); p=a[n]; if (p ~ /^[0-9]+$/) print p }' \
    | sort -u | paste -sd, - || true)"
  echo "$ports"
}

restore_or_remove_nft_conf() {
  cat >"$NFT_CONF" <<'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
  chain input {
    type filter hook input priority filter;
  }
  chain forward {
    type filter hook forward priority filter;
  }
  chain output {
    type filter hook output priority filter;
  }
}
EOF
  echo "[OK] 已写回默认 nftables.conf 模板：$NFT_CONF"
}

write_files_install() {
  local ssh_ports="$1"
  local sb_ports="$2"
  local sui_ports="$3"
  local tcp_ports="$4"
  local allow_ping="${5:-yes}" 

  local sb_trim="${sb_ports//[[:space:]]/}"
  local sui_trim="${sui_ports//[[:space:]]/}"
  local extra_trim="${tcp_ports//[[:space:]]/}"

  cat >"$NFT_CONF" <<EOF
table inet filter {
  set ssh_tcp_ports { type inet_service; elements = { $ssh_ports } }
EOF

  if [[ -n "$sb_trim" ]]; then
    cat >>"$NFT_CONF" <<EOF
  set sb_tcp_ports { type inet_service; elements = { $sb_ports } }
EOF
  fi

  if [[ -n "$sui_trim" ]]; then
    cat >>"$NFT_CONF" <<EOF
  set sui_tcp_ports { type inet_service; elements = { $sui_ports } }
EOF
  fi

  if [[ -n "$extra_trim" ]]; then
    cat >>"$NFT_CONF" <<EOF
  set other_tcp_ports { type inet_service; elements = { $tcp_ports } }
EOF
  fi

  cat >>"$NFT_CONF" <<'EOF'

  chain input {
    type filter hook input priority 0;
    policy drop;

    iif lo accept
    ct state established,related accept

    ip6 nexthdr icmpv6 icmpv6 type {
      nd-router-solicit, nd-router-advert,
      nd-neighbor-solicit, nd-neighbor-advert,
      nd-redirect,
      packet-too-big, time-exceeded, parameter-problem,
      destination-unreachable
    } accept
EOF

  if [[ "$allow_ping" == "yes" ]]; then
    cat >>"$NFT_CONF" <<'EOF'

    icmp type echo-request accept
    icmpv6 type echo-request accept
EOF
  else
    cat >>"$NFT_CONF" <<'EOF'

    icmp type echo-request drop
    icmpv6 type echo-request drop
EOF
  fi

  cat >>"$NFT_CONF" <<'EOF'

    tcp dport @ssh_tcp_ports ct state new limit rate 10/minute accept
EOF

  if [[ -n "$sb_trim" ]]; then
    cat >>"$NFT_CONF" <<'EOF'
    tcp dport @sb_tcp_ports ct count over 200 drop
    tcp dport @sb_tcp_ports ct state new limit rate over 60/second drop
    tcp dport @sb_tcp_ports ct state new accept
EOF
  fi

  if [[ -n "$sui_trim" ]]; then
    cat >>"$NFT_CONF" <<'EOF'
    tcp dport @sui_tcp_ports ct count over 200 drop
    tcp dport @sui_tcp_ports ct state new limit rate over 60/second drop
    tcp dport @sui_tcp_ports ct state new accept
EOF
  fi

  if [[ -n "$extra_trim" ]]; then
    cat >>"$NFT_CONF" <<'EOF'
    tcp dport @other_tcp_ports ct count over 200 drop
    tcp dport @other_tcp_ports ct state new limit rate over 60/second drop
    tcp dport @other_tcp_ports ct state new accept
EOF
  fi

  cat >>"$NFT_CONF" <<'EOF'
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

  cat >"$PORTSYNC_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

FAMILY="inet"
TABLE="filter"

MGMT_SET="ssh_tcp_ports"
SB_SET="sb_tcp_ports"
SUI_SET="sui_tcp_ports"
EXTRA_SET="other_tcp_ports"

DEFAULTS_FILE="/etc/default/nftables-port-sync"

SSH_PORTS_OVERRIDE=""
SB_PORTS_OVERRIDE=""
SUI_PORTS_OVERRIDE=""
EXTRA_PORTS_OVERRIDE=""

if [[ -f "$DEFAULTS_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$DEFAULTS_FILE" || true
fi

normalize_ports() {
  local raw="${1:-}"
  raw="${raw//,/ }"
  raw="$(echo "$raw" | tr -s ' ' ' ' | awk '{$1=$1};1')"
  [[ -z "$raw" ]] && { echo ""; return 0; }
  local out=() p
  for p in $raw; do
    [[ "$p" =~ ^[0-9]+$ ]] || return 1
    (( p>=1 && p<=65535 )) || return 1
    out+=("$p")
  done
  printf "%s\n" "${out[@]}" | sort -n -u | paste -sd, -
}

has_set() {
  nft list set "$FAMILY" "$TABLE" "$1" >/dev/null 2>&1
}

MGMT_LIST=""
if [[ -n "${SSH_PORTS_OVERRIDE:-}" ]]; then
  MGMT_LIST="$(normalize_ports "$SSH_PORTS_OVERRIDE" || true)"
fi

if [[ -z "$MGMT_LIST" ]]; then
  mapfile -t MGMT_PORTS < <(
    ss -lntpH 2>/dev/null | awk '
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

SB_LIST=""
if [[ -n "${SB_PORTS_OVERRIDE:-}" ]]; then
  SB_LIST="$(normalize_ports "$SB_PORTS_OVERRIDE" || true)"
else
  mapfile -t SB_PORTS < <(
    ss -lntpH 2>/dev/null | awk '
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

SUI_LIST=""
if [[ -n "${SUI_PORTS_OVERRIDE:-}" ]]; then
  SUI_LIST="$(normalize_ports "$SUI_PORTS_OVERRIDE" || true)"
else
  mapfile -t SUI_PORTS < <(
    ss -lntpH 2>/dev/null | awk '
      /\("sui"/ {
        addr=$4
        n=split(addr, a, ":")
        port=a[n]
        if (port ~ /^[0-9]+$/) print port
      }
    ' | sort -u
  )
  if [[ ${#SUI_PORTS[@]} -gt 0 ]]; then
    SUI_LIST="$(printf "%s\n" "${SUI_PORTS[@]}" | paste -sd, -)"
  fi
fi

EXTRA_LIST=""
if [[ -n "${EXTRA_PORTS_OVERRIDE:-}" ]]; then
  EXTRA_LIST="$(normalize_ports "$EXTRA_PORTS_OVERRIDE" || true)"
fi

if has_set "$MGMT_SET"; then
  nft -f - <<EOF_IN
flush set $FAMILY $TABLE $MGMT_SET
add element $FAMILY $TABLE $MGMT_SET { $MGMT_LIST }
EOF_IN
  echo "[OK] ssh_tcp_ports => $MGMT_LIST"
else
  echo "[WARN] 未找到 set $MGMT_SET（可能 nftables.conf 未加载）"
fi

if [[ -n "$SB_LIST" ]] && has_set "$SB_SET"; then
  nft -f - <<EOF_SB
flush set $FAMILY $TABLE $SB_SET
add element $FAMILY $TABLE $SB_SET { $SB_LIST }
EOF_SB
  echo "[OK] sb_tcp_ports  => $SB_LIST"
fi

if [[ -n "$SUI_LIST" ]] && has_set "$SUI_SET"; then
  nft -f - <<EOF_SUI
flush set $FAMILY $TABLE $SUI_SET
add element $FAMILY $TABLE $SUI_SET { $SUI_LIST }
EOF_SUI
  echo "[OK] sui_tcp_ports => $SUI_LIST"
fi

if [[ -n "$EXTRA_LIST" ]] && has_set "$EXTRA_SET"; then
  nft -f - <<EOF_EX
flush set $FAMILY $TABLE $EXTRA_SET
add element $FAMILY $TABLE $EXTRA_SET { $EXTRA_LIST }
EOF_EX
  echo "[OK] other_tcp_ports => $EXTRA_LIST"
fi
EOF
  chmod 0755 "$PORTSYNC_SCRIPT"

  cat >"$DEFAULTS_FILE" <<EOF
SSH_PORTS_OVERRIDE="${ssh_ports}"
SB_PORTS_OVERRIDE="${sb_ports}"
SUI_PORTS_OVERRIDE="${sui_ports}"
EXTRA_PORTS_OVERRIDE="${tcp_ports}"
EOF
  chmod 0644 "$DEFAULTS_FILE"

  cat >"$SVC_FILE" <<'EOF'
[Unit]
Description=Sync nftables port sets (ssh/sing-box/sui/extra)
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 5
ExecStart=/usr/local/sbin/nftables-port-sync.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
}

install_fw() {
  echo "========== 安装 =========="

  local default_ssh default_sb default_sui
  local in_ssh in_sb in_sui in_extra
  local ssh_ports sb_ports sui_ports
  local tcp_ports=""  

  local allow_ping="yes"
  default_ssh="$(guess_ssh_ports)"
  echo "检测到 SSH 端口：${default_ssh}"
  read -r -e -p "请输入要放行的 SSH 端口 [默认: ${default_ssh}] : " in_ssh || true
  in_ssh="$(trim "${in_ssh:-}")"
  [[ -z "$in_ssh" ]] && in_ssh="$default_ssh"
  ssh_ports="$(normalize_ports "$in_ssh")"

  sb_ports=""
  default_sb="$(guess_sb_ports)"
  if [[ -n "$default_sb" ]]; then
    echo "检测到 sing-box 正在监听的 TCP 端口：${default_sb}"
    read -r -e -p "请输入需要放行的 sing-box TCP 端口（可多端口，逗号分隔）[默认: ${default_sb}] : " in_sb || true
    in_sb="$(trim "${in_sb:-}")"
    [[ -z "$in_sb" ]] && in_sb="$default_sb"
    sb_ports="$(normalize_ports "$in_sb")"
  else
    echo "[WARN] 未检测到 sing-box 正在监听的 TCP 端口。"
    read -r -e -p "如需手动放行 sing-box TCP 端口（可多端口；留空跳过）: " in_sb || true
    in_sb="$(trim "${in_sb:-}")"
    [[ -n "$in_sb" ]] && sb_ports="$(normalize_ports "$in_sb")"
  fi

  sui_ports=""
  default_sui="$(guess_sui_ports)"
  if [[ -n "$default_sui" ]]; then
    echo "检测到 SUI 正在监听的 TCP 端口：${default_sui}"
    read -r -e -p "请输入需要放行的 SUI TCP 端口（可多端口，空格/逗号分隔）[默认: ${default_sui}] : " in_sui || true
    in_sui="$(trim "${in_sui:-}")"
    [[ -z "$in_sui" ]] && in_sui="$default_sui"
    sui_ports="$(normalize_ports "$in_sui")"
  else
    echo "[WARN] 未检测到 SUI 正在监听的 TCP 端口。"
    read -r -e -p "如需手动放行 SUI TCP 端口（可多端口；留空跳过）: " in_sui || true
    in_sui="$(trim "${in_sui:-}")"
    [[ -n "$in_sui" ]] && sui_ports="$(normalize_ports "$in_sui")"
  fi

  if [[ -z "${sb_ports//[[:space:]]/}" && -z "${sui_ports//[[:space:]]/}" ]]; then
    echo
    echo "[INFO] 未检测/配置 sing-box 与 SUI 端口。你可以在这里输入其它需要放行的 TCP 端口（可留空跳过）。"
  fi
  read -r -e -p "请输入额外需要放行的 TCP 端口 tcp_ports（可多端口；留空跳过）: " in_extra || true
  in_extra="$(trim "${in_extra:-}")"
  [[ -n "$in_extra" ]] && tcp_ports="$(normalize_ports "$in_extra")"


  echo
  read -r -e -p "是否允许 Ping（ICMP echo-request）？[Y/n] : " in_ping || true
  in_ping="$(trim "${in_ping:-}")"
  case "${in_ping,,}" in
    ""|"y"|"yes") allow_ping="yes" ;;
    "n"|"no")     allow_ping="no" ;;
    *) echo "[WARN] 输入无效，默认允许 Ping"; allow_ping="yes" ;;
  esac

  echo
  echo "[INFO] 端口配置汇总："
  echo "  SSH 放行端口：${ssh_ports}"
  echo "  sing-box 放行端口：${sb_ports:-(未配置)}"
  echo "  SUI 放行端口：${sui_ports:-(未配置)}"
  echo "  EXTRA 放行端口：${tcp_ports:-(未配置)}"
  echo "  Ping：$([[ "$allow_ping" == "yes" ]] && echo "允许" || echo "禁止")"
  echo

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y nftables iproute2

  write_files_install "$ssh_ports" "$sb_ports" "$sui_ports" "$tcp_ports" "$allow_ping"

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
  echo "  nft list set inet filter sui_tcp_ports"
  echo "  nft list set inet filter other_tcp_ports"
  echo "  systemctl status nftables --no-pager"
  echo "  systemctl status nftables-port-sync.service --no-pager"
  echo
}

uninstall_fw() {
  echo "========== 卸载 =========="
  echo "[INFO] 卸载将："
  echo "  - 删除本脚本安装的 service / defaults / portsync 脚本"
  echo "  - 写回默认 nftables.conf 模板"
  echo "  - 关闭 nftables 服务并取消自启"
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
  rm -f "$PORTSYNC_SCRIPT" 2>/dev/null || true

  restore_or_remove_nft_conf

  nft -f "$NFT_CONF" 2>/dev/null || true
  systemctl disable --now nftables 2>/dev/null || true
  systemctl daemon-reload || true

  echo
  echo "[DONE] 卸载完成。你可以检查："
  echo "  systemctl status nftables-port-sync.service --no-pager"
  echo "  systemctl status nftables --no-pager"
  echo "  ls -l $SVC_FILE $DEFAULTS_FILE $PORTSYNC_SCRIPT $NFT_CONF"
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
