# Aircrack-ng MCP Server

**Developed By: Anil Parashar (TechChip)**  
**YouTube:** [@techchipnet](https://www.youtube.com/@techchipnet) | **Website:** [techchip.net](https://www.techchip.net)


Aircrack-MCP is a Model Context Protocol (MCP) server that enables large language models to interact with Aircrack-ng tools.
It allows AI systems to perform and automate WiFi penetration testing tasks.
This integration streamlines wireless security assessments using intelligent, model-driven workflows.

## Prerequisites

| Requirement | Details |
|---|---|
| Python | 3.10+ |
| aircrack-ng | Must be installed and in `$PATH` |
| Privileges | Root / Administrator (required for monitor mode) |
| OS | Kali Linux recommended (aircrack-ng has best support) |

### Install aircrack-ng

```bash
# Debian / Ubuntu / Kali Linux
sudo apt install aircrack-ng

# Arch
sudo pacman -S aircrack-ng

# macOS (Homebrew)
brew install aircrack-ng
```

## Available Tools

| Tool | Description |
|---|---|
| `start_monitor` | Enable monitor mode on a wireless interface |
| `stop_monitor` | Disable monitor mode |
| `scan_wifi` | Scan nearby WiFi networks (time-limited) |
| `capture_handshake` | Capture WPA handshake for a target BSSID |
| `deauth` | Send deauth packets to force client reconnection |
| `crack_wifi` | Crack WPA/WEP key with a wordlist |
| `list_interfaces` | List all available wireless interfaces |
| `fake_auth` | Fake authentication attack (WEP) |
| `arp_replay` | ARP request replay to generate WEP IVs fast |
| `decrypt_capture` | Decrypt captured packets with a known key |
| `create_evil_twin` | Create a fake AP for MITM testing |
| `auto_crack_wep` | Automatically crack all nearby WEP networks |
| `clean_capture` | Clean capture files for faster WPA cracking |

## Root Privileges Configuration (Linux)

Since `aircrack-ng` tools require root privileges, and MCP servers run in the background without the ability to ask for a password, you must configure `sudo` to allow running the server without a password prompt.

### 1. Configure Passwordless Sudo
Run the following command to edit the sudoers file:
```bash
sudo visudo
```
Add the following line at the end of the file (replace `your_username` and `/path/to/...` with your actual username and absolute path to the script):
```text
your_username ALL=(ALL) NOPASSWD: /usr/bin/python3 /absolute/path/to/aircrack-mcp/aircrackmcp.py
```

## Usage

### Run the server directly
```bash
sudo python3 aircrackmcp.py
```
The server reads JSON-RPC 2.0 messages from **stdin** and writes responses to **stdout**.

### MCP Client Configuration

Add this to your MCP client config (e.g. `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "aircrack": {
      "command": "sudo",
      "args": [
        "python3",
        "/absolute/path/to/aircrak-mcp/aircrackmcp.py"
      ]
    }
  }
}
```

## Protocol

This server implements the [MCP specification](https://modelcontextprotocol.io/) using:

- **Transport**: stdio (stdin/stdout)
- **Protocol**: JSON-RPC 2.0
- **MCP Version**: 2024-11-05

### Supported Methods

| Method | Description |
|---|---|
| `initialize` | Handshake — returns server capabilities |
| `notifications/initialized` | Client confirmation (no response) |
| `ping` | Health check |
| `tools/list` | List available tools |
| `tools/call` | Execute a tool |

### Example Session

```
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"}}}
← {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"aircrack-mcp","version":"1.0.0"}}}

→ {"jsonrpc":"2.0","method":"notifications/initialized"}

→ {"jsonrpc":"2.0","id":2,"method":"tools/list"}
← {"jsonrpc":"2.0","id":2,"result":{"tools":[...]}}

→ {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"start_monitor","arguments":{"interface":"wlan0"}}}
← {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Monitor mode enabled on wlan0mon"}],"isError":false}}
```

## Security

- **Input Validation**: Interface names are validated against `^[a-zA-Z0-9_-]{1,32}$`
- **BSSID Validation**: MAC addresses are validated against standard format
- **File Validation**: File paths are checked for existence before use
- **Timeouts**: Long-running commands have enforced timeouts to prevent hangs
- **No Shell Execution**: Commands use list-based `subprocess.run()` (no shell injection)

---

> ⚠️ **Legal Disclaimer**: This tool is for **authorized penetration testing and security research only**. Unauthorized access to computer networks is illegal. Always obtain written permission before testing.

---
**Developed with ❤️ by [Anil Parashar (TechChip)](https://www.youtube.com/@techchipnet)**
