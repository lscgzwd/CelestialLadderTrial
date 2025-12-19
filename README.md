# CelestialLadderTrial 加密代理项目

## ⚠️ 重要声明（仅供学习与研究）

- 本项目**仅用于网络协议学习、加密代理实现原理研究及教学演示**。
- 严禁将本项目及其衍生作品用于任何形式的**违法、违规、绕过监管、攻击、商业牟利**等用途。
- 使用本项目产生的一切后果由**使用者自行承担**，作者不对任何直接或间接损失负责。
- 如您不同意以上任一条款，请**立即停止使用并删除本项目代码**。

---

## 📖 项目简介

`CelestialLadderTrial` 是一个用 Go 实现的加密代理通道示例项目，核心目标是**从零实现一个可工作的加密代理系统**，用于讲解和演示以下技术点：

- 将代理流量伪装为 **WSS/TLS** 流量，降低被识别风险
- 基于 **SOCKS5 / HTTP / HTTPS / WSS** 的本地代理入口
- 使用 **TUN 虚拟网卡 + tun2socks** 实现透明代理和系统级流量拦截
- 基于 **DoH（DNS over HTTPS）+ 特定区域 IP 数据 + GFWList** 的智能分流（直连 / 走代理）
- 使用 **Golang** 实现双向数据转发、网络接口绑定、路由表管理和系统代理自动配置

项目定位是一个**教学/研究用的“手搓加密代理”样例工程**，而不是即插即用的成品代理工具。

---

## 🚀 快速使用说明（实验环境）

> 以下步骤仅作为本地或测试环境中的技术学习、调试和验证示例。

### 1. 编译

```bash
go build -o proxy .
```

在 Windows 下：

```powershell
go build -o proxy.exe .
```

### 2. 配置文件

项目根目录提供了示例配置：

- `config.example.json`：示例配置
- `config.json`：实际运行时读取的配置

典型配置字段（节选）：

```json
{
  "debug": true,
  "user": "32-bytes-chacha20-key-here-123456",
  "ecs_subnet": "110.242.68.0/24",
  "in": {
    "type": 4,
    "port": 443,
    "server_name": "your.domain.com",
    "email": "admin@example.com"
  },
  "out": {
    "type": 2,
    "remote_addr": "your.domain.com"
  },
  "white_list": [],
  "black_list": [],
  "china_ip_file": "china_ip.txt",
  "gfw_list_file": "gfwlist.txt",
  "tun": {
    "enable": true,
    "name": "clt0",
    "address": "",
    "netmask": "",
    "mtu": 1500,
    "dns": []
  },
  "system_proxy": {
    "enable": true
  },
  "log": {
    "path": "./",
    "level": "info",
    "file_name": "client.log"
  }
}
```

> 说明：
> - `in.type`：入口类型（1: SOCKS5, 2: HTTP, 3: TLS, 4: WSS）
> - `out.type`：出口类型（1: TLS, 2: WSS, 3: Direct）
> - `user`：用于 Chacha20 加密的 32 字节密钥（务必自行替换）
> - `tun.enable`：是否启用 TUN 透明代理模式
> - `system_proxy.enable`：是否自动配置系统代理（Win/macOS/Linux）

### 3. 启动（本地测试）

```bash
./proxy -c config.json
```

注意事项：
- 启用 TUN 时需要 **管理员/root 权限**
- Windows 下会自动尝试 UAC 提权
- Linux/macOS 需使用 `sudo` 运行以便创建 TUN、修改路由表

### 4. 浏览器与系统代理

- 如果开启了 `system_proxy.enable`，程序会尝试自动配置：
  - Windows：WinHTTP + WinINET（系统设置中的“使用代理服务器”）
  - macOS：`networksetup` 设置 Wi-Fi/Ethernet 的 HTTP/HTTPS 代理
  - Linux（GNOME）：使用 `gsettings` 设置系统代理
- 亦可手动将浏览器代理配置为 `127.0.0.1:<in.port>`。

---

## 🧩 源码结构说明

项目采用模块化目录结构，主要目录说明如下：

```text
.
├─ config/            # 配置读取与热重载
│  ├─ config.go       # 配置结构体定义
│  ├─ init.go         # 启动加载 config.json + TLS 证书
│  └─ reloader.go     # fsnotify 热重载，回调通知路由/规则引擎
│
├─ server/
│  ├─ init.go         # 程序入口初始化：系统代理、TUN 服务、本地监听
│  │
│  ├─ proxy/
│  │  ├─ server/      # 本地入口（SOCKS5 / HTTP / TLS / WSS）
│  │  │  ├─ socket.go # SOCKS5 + HTTP CONNECT + HTTP 直连智能识别
│  │  │  ├─ http.go   # HTTP 代理入口
│  │  │  ├─ tls.go    # TLS 入口（基于 certmagic 的自动证书）
│  │  │  └─ wss.go    # WSS 入口
│  │  └─ client/      # 出口（直连 / TLS / WSS）
│  │     ├─ direct.go # DirectRemote，直连出口（支持 UDP）
│  │     ├─ tls.go    # TLSRemote，TLS 加密出口
│  │     └─ wss.go    # WSSRemote，WebSocket Secure 加密出口
│  │
│  ├─ tun/            # TUN 虚拟网卡与 tun2socks 集成
│  │  ├─ service.go   # TUN 服务生命周期管理（权限检查、路由备份/恢复）
│  │  ├─ tun2socks.go # 使用 github.com/xjasonlyu/tun2socks 的集成封装
│  │  ├─ tun_*.go     # 各平台 TUN 设备创建（windows/linux/darwin）
│  │  ├─ ip_allocator.go # 自动选择未使用的私有网段
│  │  └─ dns.go       # TUN 侧 DNS 处理（DoH）
│  │
│  ├─ route/          # 路由决策与系统路由表管理
│  │  ├─ route.go         # GetRemote：白名单/黑名单/GFWList/中国IP + DoH 分流逻辑
│  │  ├─ rule_engine.go   # 通用规则引擎（CIDR/IP 段/域名通配）
│  │  └─ route_manager.go # 系统路由表：备份/修改/恢复 + 远程服务器直连路由
│  │
│  ├─ doh/            # DNS over HTTPS 客户端
│  │  ├─ aliyun.go    # 基于 AliDNS 的 DoH 实现（带 ECS 与缓存）
│  │  └─ cache.go     # 内存 DNS 缓存
│  │
│  ├─ systemproxy/    # 系统代理自动配置与恢复
│  │  └─ systemproxy.go
│  │
│  └─ common/         # 通用组件
│     ├─ common.go        # Chacha20Stream、TargetAddr 等基础类型
│     ├─ buffer.go        # 高效缓冲区池
│     ├─ io.go            # 协议嗅探、连接包装
│     └─ interface_binder.go # 全局 Dialer，绑定原始网络接口 IP
│
├─ utils/
│  ├─ context/        # 带 traceID 与耗时统计的上下文封装
│  ├─ logger/         # 基于 logrus 的 JSON 日志封装
│  └─ gfwlist/        # GFWList 解析与匹配
│
├─ main.go            # 信号处理 + 优雅退出（恢复路由/系统代理）
└─ README.md
```

---

## 📦 引用三方库与致谢

本项目大量受益于开源社区，特别是以下第三方库和项目（按模块归类）：

### 网络与协议相关

- `github.com/xjasonlyu/tun2socks`  
  用于 TUN → SOCKS5 的透明代理实现，内部基于 gVisor 用户态网络栈。  
  项目地址：`https://github.com/xjasonlyu/tun2socks`

- `golang.org/x/crypto/chacha20`  
  实现 Chacha20 流加密，用于对代理数据进行二次加密。

- `github.com/gorilla/websocket`  
  WebSocket 客户端/服务端实现，用于 WSS 通道。

### DNS / DoH 相关

- `github.com/miekg/dns`  
  DNS 协议相关解析支持。

- `github.com/likexian/gokit/xip`  
  IP 与子网处理工具，在 DoH ECS 子网处理等场景中使用。

### TLS 与证书

- `github.com/caddyserver/certmagic`  
  自动获取与管理 Let’s Encrypt 证书，用于 TLS/WSS 入口的 HTTPS 证书自动化。

### 日志与工具

- `github.com/sirupsen/logrus`  
  结构化日志库，配合自定义 JSONFormatter 用于输出统一格式的运行日志。

- `github.com/fsnotify/fsnotify`（间接依赖）  
  用于监听配置文件变化，实现热重载。

> 在此对上述以及所有间接依赖的开源项目作者表示**衷心感谢**。  
> 本项目仅作为学习与研究示例，强烈建议使用者直接参考这些上游项目的文档与源码，获得更全面、可靠的实现方案。

---

## 📚 学习建议

如果你希望通过本项目系统性地学习“加密代理通道”的实现，可以按以下顺序阅读源码：

1. **整体流程**：`main.go` → `server/init.go`
2. **入口协议**：`server/proxy/server/socket.go`（SOCKS5/HTTP）、`server/proxy/server/wss.go`
3. **出口协议**：`server/proxy/client/direct.go` / `tls.go` / `wss.go`
4. **路由决策**：`server/route/route.go` + `server/route/rule_engine.go`
5. **TUN 与透明代理**：`server/tun/service.go` + `server/tun/tun2socks.go`
6. **DoH 与 DNS 缓存**：`server/doh/aliyun.go` + `server/doh/cache.go`
7. **系统集成**：`server/route/route_manager.go` + `server/systemproxy/systemproxy.go`


---

## 🔚 最后再强调一次

- 本项目是一个**教学/研究性质**的示例工程，用于展示如何一步一步“手搓”一个加密代理通道。
- 请**严格遵守当地法律法规**，不要将其用于任何违法或不当用途。
- 如需在生产环境中使用代理软件，请优先选择经过安全审计、广泛使用的成熟开源项目（如各类主流代理客户端），并结合自身合规要求进行评估。

感谢所有参与和支持开源社区的开发者。  
也欢迎你在阅读代码过程中提出 Issue 或 PR，一起交流学习。
