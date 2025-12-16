# My Sing-box Script 工具箱

这里是我的自用 VPS 脚本合集。

## 1. 🚀 Sing-box 安装脚本
安装 Sing-box 核心服务。

```bash
bash <(curl -Ls [https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/sb.sh](https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/sb.sh))
2. ⚡ XanMod 内核安装脚本
安装 XanMod 内核以支持 TCP Brutal 等特性。
bash <(curl -Ls [https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/xanmod.sh](https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/xanmod.sh))
3. 🌊 TCP Brutal 开启脚本
在安装好 XanMod 内核后，开启 Brutal 拥塞控制
bash <(curl -Ls [https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/brutal.sh](https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/brutal.sh))
4. 🛡️ 防火墙/转发配置 (install-fw)
配置防火墙或端口转发规则
bash <(curl -Ls [https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/install-fw.sh](https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/install-fw.sh))
