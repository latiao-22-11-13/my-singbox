#!/bin/bash

clear_screen() {
    if command -v tput >/dev/null 2>&1; then
        tput clear
    else
        printf "\033c"
    fi
}

WORKER="/usr/local/bin/tcp_bdp_worker.sh"
SERVICE="/etc/systemd/system/tcp-bdp.service"

read_line() {
  local prompt="$1"
  local default="$2"
  local char

  REPLY="$default"

  printf "%s%s" "$prompt" "$REPLY"

  while IFS= read -r -s -n1 char; do

    if [[ "$char" == "" ]]; then
      printf '\n'
      break
    fi

    if [[ "$char" == $'\x7f' || "$char" == $'\b' ]]; then
      if [ -n "$REPLY" ]; then
        REPLY=${REPLY%?}
        printf '\b \b'
      fi
      continue
    fi

    printf '%s' "$char"
    REPLY+="$char"
  done
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "必须使用 root 执行本脚本"
    exit 1
  fi
}

check_sysctl_conf() {
  if [ ! -f /etc/sysctl.d/99-sysctl.conf ]; then
    echo "请先运行你的net-optimization脚本，然后再启用 TCP BDP 自动调优。"
    return 1
  fi
  return 0
}

create_worker_script() {
  local bw="$1"
  local target="$2"
  local mode="$3"  
  local start="$4"
  local end="$5"
  local interval="$6"

  cat > "$WORKER" <<EOF_HEADER
#!/bin/bash

TARGET_IP="$target" 
BANDWIDTH_MBIT="$bw" 
MODE="$mode" 
START_HOUR="$start" 
END_HOUR="$end" 
INTERVAL_SEC="$interval" 

EOF_HEADER

  cat >> "$WORKER" <<'EOF_BODY'

DEFAULT_INTERVAL=300
SAFETY_FACTOR=1.5
MIN_WIN_BYTES=$((8 * 1024 * 1024))
MAX_WIN_BYTES=$((128 * 1024 * 1024))
ALIGN=4096

msg() {
  echo "[TCP-BDP] $(date '+%F %T') $*"
}

resolve_target() {
  local input="$1"

  if echo "$input" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    RESOLVED_IP="$input"
    return 0
  fi

  if echo "$input" | grep -Eq '^[0-9a-fA-F:]+$'; then
    RESOLVED_IP="$input"
    return 0
  fi

  RESOLVED_IP=$(getent hosts "$input" | awk '/:/{print $1; exit}')
  if [ -n "$RESOLVED_IP" ]; then
    return 0
  fi

  RESOLVED_IP=$(getent hosts "$input" | awk '/\./{print $1; exit}')
  if [ -n "$RESOLVED_IP" ]; then
    return 0
  fi

  return 1
}


run_one_cycle() {
  if [ -z "$TARGET_IP" ] || [ -z "$BANDWIDTH_MBIT" ]; then
    msg "配置不完整（TARGET_IP / BANDWIDTH_MBIT 为空），跳过"
    return
  fi

  if [ "$MODE" = "window" ]; then
    local hour
    hour=$(date +%H)
    hour=$((10#$hour))
    if [ "$hour" -lt "$START_HOUR" ] || [ "$hour" -ge "$END_HOUR" ]; then
      msg "当前时间 ${hour} 点不在调优时间段 ${START_HOUR}-${END_HOUR}，跳过"
      return
    fi
  fi

  if ! resolve_target "$TARGET_IP"; then
    msg "无法解析目标：$TARGET_IP"
    return
  fi

  msg "开始检测链路 → $TARGET_IP ($RESOLVED_IP)"

  PING_OUT=$(ping -c 20 -i 0.2 -n "$RESOLVED_IP" 2>&1)
  if [ $? -ne 0 ]; then
    msg "Ping 不通，保持原有 TCP 设置不变"
    return
  fi

  PACKET_LOSS=$(echo "$PING_OUT" | awk -F',' '/packet loss/ {gsub(/ /,"",$3); sub(/%packetloss/,"",$3); print $3}')
  [ -z "$PACKET_LOSS" ] && PACKET_LOSS=0
  RTT_LINE=$(echo "$PING_OUT" | awk -F'=' '/rtt/ {print $2}')
  RTT_MIN=$(echo "$RTT_LINE" | awk -F'/' '{printf "%.0f",$1}')
  RTT_AVG=$(echo "$RTT_LINE" | awk -F'/' '{printf "%.0f",$2}')
  RTT_MAX=$(echo "$RTT_LINE" | awk -F'/' '{printf "%.0f",$3}')
  JITTER=$((RTT_MAX - RTT_MIN))

  msg "丢包=${PACKET_LOSS}%  rtt_min=${RTT_MIN}ms rtt_avg=${RTT_AVG}ms rtt_max=${RTT_MAX}ms 抖动=${JITTER}ms"

  RTT_AVG_RAW="$RTT_AVG"
    [ "$RTT_AVG_RAW" -le 0 ] && RTT_AVG_RAW=1  

  JITTER_PCT=$(( JITTER * 100 / RTT_AVG_RAW ))  

  if [ "$PACKET_LOSS" -eq 0 ] && [ "$JITTER_PCT" -le 2 ]; then
    ADV="1"
    msg "线路极稳定（丢包=0 且抖动≤2%%）→ 使用激进模式"

  elif [ "$JITTER_PCT" -le 10 ] && [ "$PACKET_LOSS" -le 5 ]; then
    ADV="-1"
    msg "线路较稳定（抖动≤10%% 且丢包≤5%%）→ 使用平衡模式"

  else
    ADV="-2"
    msg "线路波动较大或丢包严重（抖动>${JITTER_PCT}%% 丢包=${PACKET_LOSS}%%）→ 使用保守模式"
  fi

  [ "$RTT_AVG" -lt 20 ] && RTT_AVG=20
  [ "$RTT_AVG" -gt 250 ] && RTT_AVG=250

  BPS=$((BANDWIDTH_MBIT * 1000000))

  TARGET_WIN=$(awk -v bps="$BPS" -v r="$RTT_AVG" -v k="$SAFETY_FACTOR" 'BEGIN{
    # BDP = 带宽 * RTT(s) / 8  → 字节
    bdp = bps * (r/1000.0) / 8.0;
    win = bdp * k;
    if (win < 1) win = 1;
    printf "%.0f", win;
  }')

  [ "$TARGET_WIN" -lt "$MIN_WIN_BYTES" ] && TARGET_WIN=$MIN_WIN_BYTES
  [ "$TARGET_WIN" -gt "$MAX_WIN_BYTES" ] && TARGET_WIN=$MAX_WIN_BYTES

  TARGET_WIN=$(( (TARGET_WIN / ALIGN) * ALIGN ))

  msg "目标窗口：$((TARGET_WIN/1048576)) MB"

  sysctl -w net.core.rmem_max="$TARGET_WIN" >/dev/null
  sysctl -w net.core.wmem_max="$TARGET_WIN" >/dev/null
  sysctl -w net.ipv4.tcp_rmem="4096 262144 $TARGET_WIN" >/dev/null
  sysctl -w net.ipv4.tcp_wmem="4096 262144 $TARGET_WIN" >/dev/null
  sysctl -w net.ipv4.tcp_adv_win_scale="$ADV" >/dev/null

  msg "调优完成"
}

while true; do
  run_one_cycle
  sleep "${INTERVAL_SEC:-$DEFAULT_INTERVAL}"
done
EOF_BODY

  chmod +x "$WORKER"
  echo "已生成 worker 脚本：$WORKER"
}

create_service() {
  cat > "$SERVICE" <<EOF
[Unit]
Description=TCP BDP Auto Optimizer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$WORKER
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
  echo "已生成 systemd 服务文件：$SERVICE"
}

enable_service() {
  systemctl daemon-reload
  systemctl enable --now tcp-bdp.service
}

disable_and_clean() {
  echo "正在关闭 TCP BDP 自动调优..."
  systemctl disable --now tcp-bdp.service 2>/dev/null || true
  rm -f "$SERVICE" "$WORKER"
  systemctl daemon-reload
  echo "已关闭。"
}

main_menu() {
  require_root

  while true; do
    clear_screen
    echo "========================================"
    echo "选择 TCP BDP 自动调优选项:"
    echo "1) 启用 TCP BDP 自动调优"
    echo "2) 关闭 TCP BDP 自动调优"
    echo "0) 退出"
    echo "========================================"
    read_line "请输入选项 [0-2]: " ""
    choice="$REPLY"

    case "$choice" in
      1)
        check_sysctl_conf || continue

        read_line "请输入带宽 (单位: Mbit/s)： " ""
        bw="$REPLY"
        if ! echo "$bw" | grep -Eq '^[0-9]+$'; then
          echo "带宽必须是正整数"
          continue
        fi

        read_line "请输入目标 IP 或 域名： " ""
        target="$REPLY"
        [ -z "$target" ] && { echo "目标不能为空"; continue; }

        echo "测试连通性，请稍候..."
        if ! ping -c 4 "$target" &>/dev/null; then
          echo "无法 ping 通目标 $target，请检查 IP / 域名 或 防火墙设置。"
          continue 
        fi
        echo "目标 $target 通信正常。"

        echo "请选择运行模式:"
        echo "1) 全天候运行"
        echo "2) 指定时间段运行（例如 8-24）"
        read_line "请输入选项 [1-2]: " ""
        mode_choice="$REPLY"

        mode="full"
        start="0"
        end="24"
        case "$mode_choice" in
          1)
            mode="full"
            ;;
          2)
            mode="window"
            read_line "请输入开始小时 (0-23，例如 8): " ""
            start="$REPLY"
            read_line "请输入结束小时 (1-24，例如 24): " ""
            end="$REPLY"
            if ! echo "$start" | grep -Eq '^[0-9]+$' || ! echo "$end" | grep -Eq '^[0-9]+$'; then
              echo "时间必须是整数小时"
              continue
            fi
            if [ "$start" -lt 0 ] || [ "$start" -gt 23 ] || [ "$end" -lt 1 ] || [ "$end" -gt 24 ] || [ "$start" -ge "$end" ]; then
              echo "时间段不合法，必须满足 0<=start<end<=24"
              continue
            fi
            ;;
          *)
            echo "无效选项"
            continue
            ;;
        esac

        read_line "检测间隔（秒，默认300）： " "300"
        interval="$REPLY"
        [ -z "$interval" ] && interval=300
        if ! echo "$interval" | grep -Eq '^[0-9]+$'; then
          echo "间隔必须是正整数"
          continue
        fi

        create_worker_script "$bw" "$target" "$mode" "$start" "$end" "$interval"
        create_service
        enable_service
        echo "TCP BDP 自动调优已启用，并已设置为开机自启。"
        echo "如需查看运行情况：journalctl -u tcp-bdp.service -f"
        ;;

      2)
        disable_and_clean
        ;;

      0)
        exit 0
        ;;

      *)
        echo "无效选项"
        ;;
    esac
  done
}

main_menu