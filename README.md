# My Sing-box Script 工具箱

VPS 一站式性能部署工具集，覆盖内核、网络加速、代理部署全流程。

## 快速开始（推荐）

统一管理脚本，集成 XanMod + TCP Brutal + Sing-box：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/setup.sh)
```

## 独立脚本

**XanMod 内核安装/卸载**
```bash
bash <(curl -Ls https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/xanmod.sh)
```

**TCP Brutal 模块编译安装**
```bash
bash <(curl -Ls https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/brutal.sh)
```

**Sing-box 部署管理（含快捷键 `sb`）**
```bash
bash <(curl -Ls https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/sb.sh)
```

**防火墙配置**
```bash
bash <(curl -Ls https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/fw.sh)
```

**网络优化（Reality/Mux/Brutal 专用）**
```bash
bash <(curl -Ls https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/auto-tcp.sh)
```

**TCP 系统参数调优**
```bash
bash <(curl -Ls https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/net-optimization.sh)
```

**TCP BDP 自动调优**
```bash
bash <(curl -Ls https://raw.githubusercontent.com/latiao-22-11-13/my-singbox/main/tcp_bdp.sh)
```

## 推荐部署顺序

1. **XanMod 内核** → 安装后重启
2. **TCP Brutal** → 编译内核模块
3. **Sing-box** → 部署代理服务
4. **网络优化** → 按需选择 auto-tcp / net-optimization / tcp_bdp
5. **防火墙** → 按需配置 fw.sh

## 系统要求

- Debian 12+ / Ubuntu 22.04+
- KVM / VMware / 物理机（不支持 OpenVZ/LXC/Docker）
- root 权限
