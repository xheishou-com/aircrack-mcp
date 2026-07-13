# Aircrack-ng MCP Server

**开发者: Anil Parashar (TechChip)**  
**网站:** [X黑手网](https://xheishou.com)


Aircrack-MCP 是一个 Model Context Protocol (MCP) 服务端，让大语言模型能够与 Aircrack-ng 工具交互。
它使 AI 系统能够执行并自动化 WiFi 渗透测试任务。
该集成通过智能的、模型驱动的工作流简化了无线安全评估。

## 环境要求

| 要求 | 详情 |
|---|---|
| Python | 3.10+ |
| aircrack-ng | 必须已安装且在 `$PATH` 中 |
| 权限 | Root / Administrator（启用监听模式必需） |
| 操作系统 | 推荐 Kali Linux（aircrack-ng 支持最好） |

### 安装 aircrack-ng

```bash
# Debian / Ubuntu / Kali Linux
sudo apt install aircrack-ng

# Arch
sudo pacman -S aircrack-ng

# macOS (Homebrew)
brew install aircrack-ng
```

## 可用工具

| 工具 | 描述 |
|---|---|
| `start_monitor` | 在无线网卡上启用监听模式 |
| `stop_monitor` | 禁用监听模式 |
| `scan_wifi` | 扫描附近的 WiFi 网络（限时） |
| `capture_handshake` | 捕获目标 BSSID 的 WPA 握手包 |
| `deauth` | 发送解除认证帧以强制客户端重连 |
| `crack_wifi` | 使用字典破解 WPA/WEP 密钥 |
| `list_interfaces` | 列出所有可用的无线网卡 |
| `fake_auth` | 伪造认证攻击（WEP） |
| `arp_replay` | ARP 请求重放攻击，快速生成 WEP IVs |
| `decrypt_capture` | 使用已知密钥解密捕获的数据包 |
| `create_evil_twin` | 创建伪造 AP 用于中间人测试 |
| `auto_crack_wep` | 自动破解附近所有 WEP 网络 |
| `clean_capture` | 清理捕获文件以加速 WPA 破解 |

## Root 权限配置 (Linux)

由于 `aircrack-ng` 工具需要 root 权限，而 MCP 服务端在后台运行无法提示输入密码，你必须配置 `sudo` 以允许免密码运行服务端。

### 1. 配置免密码 Sudo
运行以下命令编辑 sudoers 文件：
```bash
sudo visudo
```
在文件末尾添加以下行（将 `your_username` 和 `/path/to/...` 替换为你的实际用户名和脚本的绝对路径）：
```text
your_username ALL=(ALL) NOPASSWD: /usr/bin/python3 /absolute/path/to/aircrack-mcp/aircrackmcp.py
```

## 使用方法

### 传输模式

服务端支持两种传输模式：

| 模式 | 描述 | 适用场景 |
|---|---|---|
| **stdio**（默认） | JSON-RPC 通过 stdin/stdout 通信 | 客户端和服务端在**同一台机器**上 |
| **sse** | JSON-RPC 通过 HTTP + Server-Sent Events 通信 | 客户端和服务端在**不同机器**上（远程访问） |

---

### 模式一：stdio（本地模式）

直接运行服务端 — 从 **stdin** 读取 JSON-RPC 2.0 消息，将响应写入 **stdout**。

```bash
sudo python3 aircrackmcp.py
```

MCP 客户端配置：

```json
{
  "mcpServers": {
    "aircrack": {
      "command": "sudo",
      "args": [
        "python3",
        "/absolute/path/to/aircrack-mcp/aircrackmcp.py"
      ]
    }
  }
}
```

---

### 模式二：SSE（远程访问）

在 Kali 机器上将服务端作为 HTTP 服务运行，然后从任意远程 MCP 客户端（如 Trae IDE、Claude Desktop）连接。

#### 第一步：在 Kali 上启动服务端

```bash
# 默认端口 8080，绑定所有网络接口
sudo python3 aircrackmcp.py --transport sse

# 自定义主机和端口
sudo python3 aircrackmcp.py --transport sse --host 0.0.0.0 --port 9090
```

输出示例：
```
[aircrack-mcp] INFO Aircrack-ng MCP server (SSE transport) listening on http://0.0.0.0:8080
[aircrack-mcp] INFO SSE endpoint: http://0.0.0.0:8080/sse
```

#### 第二步：配置远程 MCP 客户端

将以下配置添加到你的 MCP 客户端配置中（如 Trae IDE、`claude_desktop_config.json`）：

```json
{
  "mcpServers": {
    "aircrack": {
      "url": "http://<kali-ip>:8080/sse"
    }
  }
}
```

将 `<kali-ip>` 替换为你的 Kali 机器 IP 地址（如 `192.168.1.100`）。

#### 防火墙注意事项

确保 Kali 上对应端口已放行：
```bash
sudo ufw allow 8080/tcp
```

#### 健康检查

从客户端机器验证服务端是否正常运行：
```bash
curl http://<kali-ip>:8080/health
# {"status": "ok", "server": "aircrack-mcp"}
```

## 协议

本服务端实现了 [MCP 规范](https://modelcontextprotocol.io/)，使用：

- **传输层**: stdio（stdin/stdout）或 HTTP+SSE
- **协议**: JSON-RPC 2.0
- **MCP 版本**: 2024-11-05

### 支持的方法

| 方法 | 描述 |
|---|---|
| `initialize` | 握手 — 返回服务端能力 |
| `notifications/initialized` | 客户端确认（无响应） |
| `ping` | 健康检查 |
| `tools/list` | 列出可用工具 |
| `tools/call` | 执行工具 |

### 示例会话

```
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"}}}
← {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"aircrack-mcp","version":"1.0.0"}}}

→ {"jsonrpc":"2.0","method":"notifications/initialized"}

→ {"jsonrpc":"2.0","id":2,"method":"tools/list"}
← {"jsonrpc":"2.0","id":2,"result":{"tools":[...]}}

→ {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"start_monitor","arguments":{"interface":"wlan0"}}}
← {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Monitor mode enabled on wlan0mon"}],"isError":false}}
```

## 安全性

- **输入验证**: 网卡名称通过 `^[a-zA-Z0-9_-]{1,32}$` 正则验证
- **BSSID 验证**: MAC 地址通过标准格式验证
- **文件验证**: 文件路径在使用前检查是否存在
- **超时控制**: 长时间运行的命令有强制超时，防止挂起
- **无 Shell 执行**: 命令使用基于列表的 `subprocess.run()`（防止 Shell 注入）

---

> ⚠️ **法律声明**: 本工具仅用于**授权的渗透测试和安全研究**。未经授权访问计算机网络是违法的。测试前务必获得书面许可。

---
**由 [Anil Parashar (TechChip)](https://www.youtube.com/@techchipnet) 开发**
