"""
Aircrack-ng MCP Server
======================
Developed by: Anil Parashar (TechChip)
YouTube: https://www.youtube.com/@techchipnet
Website: https://www.techchip.net

A Model Context Protocol (MCP) server that wraps the aircrack-ng suite.
Communicates via JSON-RPC 2.0 over stdio.

Tools provided:
  - start_monitor     : Enable monitor mode on a wireless interface
  - stop_monitor      : Disable monitor mode
  - scan_wifi         : Scan nearby WiFi networks (time-limited)
  - capture_handshake : Capture WPA handshake for a target BSSID
  - deauth            : Send deauthentication frames to a target
  - crack_wifi        : Crack WPA/WEP key using a wordlist
  - list_interfaces   : List available wireless interfaces
  - fake_auth         : Fake authentication attack (WEP)
  - arp_replay        : ARP request replay attack (WEP IV generation)
  - decrypt_capture   : Decrypt captured packets with known key
  - create_evil_twin  : Create a fake access point
  - auto_crack_wep    : Automatically crack WEP networks
  - clean_capture     : Clean capture files for faster cracking

⚠️  Requires: aircrack-ng suite installed, root/admin privileges.
⚠️  For authorized security testing only.
"""

import json
import sys
import subprocess
import re
import os
import logging

# ---------------------------------------------------------------------------
# Logging — MCP spec: stdout is protocol-only, logs go to stderr
# ---------------------------------------------------------------------------
logging.basicConfig(
    stream=sys.stderr,
    level=logging.DEBUG,
    format="[aircrack-mcp] %(levelname)s %(message)s",
)
log = logging.getLogger("aircrack-mcp")

# ---------------------------------------------------------------------------
# Constants & Branding
# ---------------------------------------------------------------------------
SERVER_NAME = "aircrack-mcp"
SERVER_VERSION = "1.0.0"
SERVER_AUTHOR = "Anil Parashar (TechChip)"
SERVER_YOUTUBE = "@techchipnet"
PROTOCOL_VERSION = "2024-11-05"

# Safe regex for network interface names  (e.g. wlan0, wlan0mon, eth0)
IFACE_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")

# Safe regex for BSSID  (e.g. AA:BB:CC:DD:EE:FF)
BSSID_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

DEFAULT_SCAN_TIMEOUT = 30  # seconds


# ---------------------------------------------------------------------------
# Tool definitions (MCP tool schema)
# ---------------------------------------------------------------------------
TOOLS = [
    {
        "name": "start_monitor",
        "description": (
            "Enable monitor mode on a wireless interface using airmon-ng. "
            "Returns the name of the monitor interface created."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Wireless interface name, e.g. wlan0",
                }
            },
            "required": ["interface"],
        },
    },
    {
        "name": "stop_monitor",
        "description": "Disable monitor mode on an interface using airmon-ng.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Monitor interface name, e.g. wlan0mon",
                }
            },
            "required": ["interface"],
        },
    },
    {
        "name": "scan_wifi",
        "description": (
            "Scan nearby WiFi networks using airodump-ng. "
            "Runs for a limited time (default 30s) then returns results."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Monitor-mode interface, e.g. wlan0mon",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Scan duration in seconds (default 30, max 120)",
                },
            },
            "required": ["interface"],
        },
    },
    {
        "name": "capture_handshake",
        "description": (
            "Capture WPA/WPA2 handshake for a specific BSSID using airodump-ng. "
            "Writes capture to the specified output file."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Monitor-mode interface, e.g. wlan0mon",
                },
                "bssid": {
                    "type": "string",
                    "description": "Target BSSID (MAC), e.g. AA:BB:CC:DD:EE:FF",
                },
                "channel": {
                    "type": "integer",
                    "description": "WiFi channel number (1-14)",
                },
                "output_file": {
                    "type": "string",
                    "description": "Output capture file prefix (no extension)",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Capture duration in seconds (default 60, max 300)",
                },
            },
            "required": ["interface", "bssid", "channel", "output_file"],
        },
    },
    {
        "name": "deauth",
        "description": (
            "Send deauthentication packets to a target using aireplay-ng. "
            "Used to force clients to reconnect so a handshake can be captured."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Monitor-mode interface, e.g. wlan0mon",
                },
                "bssid": {
                    "type": "string",
                    "description": "Target access point BSSID",
                },
                "count": {
                    "type": "integer",
                    "description": "Number of deauth packets to send (default 10, max 100)",
                },
                "client": {
                    "type": "string",
                    "description": "Optional: specific client MAC to deauth",
                },
            },
            "required": ["interface", "bssid"],
        },
    },
    {
        "name": "crack_wifi",
        "description": (
            "Attempt to crack a WPA/WEP key from a capture file "
            "using aircrack-ng with a wordlist."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "capture_file": {
                    "type": "string",
                    "description": "Path to .cap capture file",
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist file",
                },
            },
            "required": ["capture_file", "wordlist"],
        },
    },
    {
        "name": "list_interfaces",
        "description": "List all available wireless interfaces using airmon-ng.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "fake_auth",
        "description": (
            "Perform fake authentication attack against a WEP AP using aireplay-ng. "
            "Required before ARP replay or other WEP injection attacks."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Monitor-mode interface, e.g. wlan0mon",
                },
                "bssid": {
                    "type": "string",
                    "description": "Target access point BSSID",
                },
                "source_mac": {
                    "type": "string",
                    "description": "Your wireless adapter MAC address",
                },
                "reassoc_delay": {
                    "type": "integer",
                    "description": "Reassociation timing in seconds (default 0)",
                },
            },
            "required": ["interface", "bssid", "source_mac"],
        },
    },
    {
        "name": "arp_replay",
        "description": (
            "ARP request replay attack using aireplay-ng. "
            "Captures and reinjects ARP packets to generate WEP IVs rapidly."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Monitor-mode interface, e.g. wlan0mon",
                },
                "bssid": {
                    "type": "string",
                    "description": "Target access point BSSID",
                },
                "source_mac": {
                    "type": "string",
                    "description": "Your wireless adapter MAC address",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Duration in seconds (default 60, max 300)",
                },
            },
            "required": ["interface", "bssid"],
        },
    },
    {
        "name": "decrypt_capture",
        "description": (
            "Decrypt a WEP or WPA capture file using airdecap-ng. "
            "Requires the network key (WEP hex or WPA passphrase)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "capture_file": {
                    "type": "string",
                    "description": "Path to .cap capture file",
                },
                "key": {
                    "type": "string",
                    "description": "WEP key (hex) or WPA passphrase",
                },
                "essid": {
                    "type": "string",
                    "description": "Network ESSID (required for WPA)",
                },
                "is_wep": {
                    "type": "boolean",
                    "description": "True for WEP, false for WPA (default false)",
                },
            },
            "required": ["capture_file", "key"],
        },
    },
    {
        "name": "create_evil_twin",
        "description": (
            "Create a fake access point (evil twin) using airbase-ng. "
            "Used for MITM testing and rogue AP detection assessments."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Monitor-mode interface, e.g. wlan0mon",
                },
                "essid": {
                    "type": "string",
                    "description": "SSID name for the fake AP",
                },
                "channel": {
                    "type": "integer",
                    "description": "WiFi channel (1-14)",
                },
                "bssid": {
                    "type": "string",
                    "description": "Optional: spoof this BSSID",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Duration in seconds (default 60, max 300)",
                },
            },
            "required": ["interface", "essid", "channel"],
        },
    },
    {
        "name": "auto_crack_wep",
        "description": (
            "Automatically crack all nearby WEP networks using besside-ng. "
            "Captures IVs and cracks keys without manual intervention."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Monitor-mode interface, e.g. wlan0mon",
                },
                "bssid": {
                    "type": "string",
                    "description": "Optional: target specific BSSID only",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Duration in seconds (default 120, max 600)",
                },
            },
            "required": ["interface"],
        },
    },
    {
        "name": "clean_capture",
        "description": (
            "Clean a WPA capture file using wpaclean. "
            "Strips unnecessary packets, keeping only handshake data for faster cracking."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_file": {
                    "type": "string",
                    "description": "Path to input .cap file",
                },
                "output_file": {
                    "type": "string",
                    "description": "Path for cleaned output .cap file",
                },
            },
            "required": ["input_file", "output_file"],
        },
    },
]


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def validate_interface(name: str) -> str | None:
    """Return error message if interface name is invalid, else None."""
    if not IFACE_RE.match(name):
        return f"Invalid interface name: '{name}'. Must be alphanumeric, 1-32 chars."
    return None


def validate_bssid(bssid: str) -> str | None:
    """Return error message if BSSID is invalid, else None."""
    if not BSSID_RE.match(bssid):
        return f"Invalid BSSID: '{bssid}'. Expected format AA:BB:CC:DD:EE:FF."
    return None


def validate_file_exists(path: str) -> str | None:
    """Return error message if file does not exist."""
    if not os.path.isfile(path):
        return f"File not found: '{path}'."
    return None


def clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, value))


# ---------------------------------------------------------------------------
# Command runner
# ---------------------------------------------------------------------------
def run_cmd(cmd: list[str], timeout: int | None = None) -> dict:
    """Run a shell command and return structured result."""
    log.info("Running: %s (timeout=%s)", " ".join(cmd), timeout)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": True,
            "stdout": "(scan timed out — this is expected for time-limited scans)",
            "stderr": "",
            "returncode": 0,
        }
    except FileNotFoundError:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Command not found: {cmd[0]}. Is aircrack-ng installed?",
            "returncode": -1,
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
        }


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------
def handle_start_monitor(args: dict) -> dict:
    iface = args["interface"]
    if err := validate_interface(iface):
        return {"isError": True, "text": err}
    result = run_cmd(["airmon-ng", "start", iface])
    return {"isError": not result["success"], "text": result["stdout"] or result["stderr"]}


def handle_stop_monitor(args: dict) -> dict:
    iface = args["interface"]
    if err := validate_interface(iface):
        return {"isError": True, "text": err}
    result = run_cmd(["airmon-ng", "stop", iface])
    return {"isError": not result["success"], "text": result["stdout"] or result["stderr"]}


def handle_scan_wifi(args: dict) -> dict:
    iface = args["interface"]
    if err := validate_interface(iface):
        return {"isError": True, "text": err}

    timeout = clamp(args.get("timeout", DEFAULT_SCAN_TIMEOUT), 5, 120)

    # airodump-ng uses ncurses for display — stdout capture doesn't work.
    # Solution: write to CSV file, then read and return the file contents.
    import tempfile
    tmp_dir = tempfile.mkdtemp(prefix="aircrack_scan_")
    tmp_prefix = os.path.join(tmp_dir, "scan")

    cmd = [
        "airodump-ng", iface,
        "--write", tmp_prefix,
        "--output-format", "csv",
        "--write-interval", "1",
    ]

    # Run scan — will timeout after the specified duration (expected behavior)
    run_cmd(cmd, timeout=timeout)

    # Read the CSV output file
    csv_file = tmp_prefix + "-01.csv"
    output = ""
    try:
        if os.path.isfile(csv_file):
            with open(csv_file, "r", errors="ignore") as f:
                output = f.read().strip()
        if not output:
            output = "No networks found or scan produced no output."
    except Exception as e:
        output = f"Error reading scan results: {e}"
    finally:
        # Cleanup temp files
        try:
            import glob
            for f in glob.glob(tmp_prefix + "*"):
                os.remove(f)
            os.rmdir(tmp_dir)
        except OSError:
            pass

    return {"isError": False, "text": f"Scan ran for {timeout}s.\n\n{output}"}


def handle_capture_handshake(args: dict) -> dict:
    iface = args["interface"]
    bssid = args["bssid"]
    channel = args["channel"]
    output_file = args["output_file"]
    timeout = clamp(args.get("timeout", 60), 10, 300)

    if err := validate_interface(iface):
        return {"isError": True, "text": err}
    if err := validate_bssid(bssid):
        return {"isError": True, "text": err}
    if not 1 <= channel <= 14:
        return {"isError": True, "text": f"Invalid channel: {channel}. Must be 1-14."}

    result = run_cmd(
        [
            "airodump-ng",
            "--bssid", bssid,
            "--channel", str(channel),
            "--write", output_file,
            "--output-format", "pcap,csv",
            iface,
        ],
        timeout=timeout,
    )

    # Check what files were created
    import glob
    created_files = glob.glob(output_file + "*")
    if created_files:
        file_list = "\n".join(f"  - {f} ({os.path.getsize(f)} bytes)" for f in created_files)
        output = f"Capture files created:\n{file_list}"
    else:
        output = result["stderr"] or "No capture files created. Handshake may not have been captured."

    return {"isError": False, "text": f"Captured for {timeout}s on channel {channel} (BSSID: {bssid}).\n\n{output}"}


def handle_deauth(args: dict) -> dict:
    iface = args["interface"]
    bssid = args["bssid"]
    count = clamp(args.get("count", 10), 1, 100)

    if err := validate_interface(iface):
        return {"isError": True, "text": err}
    if err := validate_bssid(bssid):
        return {"isError": True, "text": err}

    cmd = [
        "aireplay-ng",
        "--deauth", str(count),
        "-a", bssid,
    ]

    # Optional: target specific client
    client = args.get("client")
    if client:
        if err := validate_bssid(client):
            return {"isError": True, "text": f"Invalid client MAC: {err}"}
        cmd.extend(["-c", client])

    cmd.append(iface)

    result = run_cmd(cmd, timeout=30)
    output = result["stdout"] or result["stderr"]
    return {"isError": not result["success"], "text": output}


def handle_crack_wifi(args: dict) -> dict:
    capture_file = args["capture_file"]
    wordlist = args["wordlist"]

    if err := validate_file_exists(capture_file):
        return {"isError": True, "text": err}
    if err := validate_file_exists(wordlist):
        return {"isError": True, "text": err}

    result = run_cmd(["aircrack-ng", capture_file, "-w", wordlist])
    output = result["stdout"] or result["stderr"]
    return {"isError": not result["success"], "text": output}


def handle_list_interfaces(args: dict) -> dict:
    result = run_cmd(["airmon-ng"])
    output = result["stdout"] or result["stderr"]
    return {"isError": not result["success"], "text": output}


def handle_fake_auth(args: dict) -> dict:
    iface = args["interface"]
    bssid = args["bssid"]
    source_mac = args["source_mac"]
    delay = args.get("reassoc_delay", 0)

    if err := validate_interface(iface):
        return {"isError": True, "text": err}
    if err := validate_bssid(bssid):
        return {"isError": True, "text": err}
    if err := validate_bssid(source_mac):
        return {"isError": True, "text": f"Invalid source MAC: {err}"}

    cmd = [
        "aireplay-ng",
        "-1", str(delay),
        "-a", bssid,
        "-h", source_mac,
        iface,
    ]
    result = run_cmd(cmd, timeout=30)
    output = result["stdout"] or result["stderr"]
    return {"isError": not result["success"], "text": output}


def handle_arp_replay(args: dict) -> dict:
    iface = args["interface"]
    bssid = args["bssid"]
    timeout = clamp(args.get("timeout", 60), 10, 300)

    if err := validate_interface(iface):
        return {"isError": True, "text": err}
    if err := validate_bssid(bssid):
        return {"isError": True, "text": err}

    cmd = ["aireplay-ng", "-3", "-b", bssid]

    source_mac = args.get("source_mac")
    if source_mac:
        if err := validate_bssid(source_mac):
            return {"isError": True, "text": f"Invalid source MAC: {err}"}
        cmd.extend(["-h", source_mac])

    cmd.append(iface)
    result = run_cmd(cmd, timeout=timeout)
    output = result["stdout"] or result["stderr"]
    return {"isError": not result["success"], "text": f"ARP replay ran for {timeout}s.\n\n{output}"}


def handle_decrypt_capture(args: dict) -> dict:
    capture_file = args["capture_file"]
    key = args["key"]
    is_wep = args.get("is_wep", False)

    if err := validate_file_exists(capture_file):
        return {"isError": True, "text": err}

    if is_wep:
        cmd = ["airdecap-ng", "-w", key, capture_file]
    else:
        essid = args.get("essid", "")
        if not essid:
            return {"isError": True, "text": "ESSID is required for WPA decryption."}
        cmd = ["airdecap-ng", "-p", key, "-e", essid, capture_file]

    result = run_cmd(cmd)
    output = result["stdout"] or result["stderr"]
    return {"isError": not result["success"], "text": output}


def handle_create_evil_twin(args: dict) -> dict:
    iface = args["interface"]
    essid = args["essid"]
    channel = args["channel"]
    timeout = clamp(args.get("timeout", 60), 10, 300)

    if err := validate_interface(iface):
        return {"isError": True, "text": err}
    if not 1 <= channel <= 14:
        return {"isError": True, "text": f"Invalid channel: {channel}. Must be 1-14."}

    cmd = ["airbase-ng", "-e", essid, "-c", str(channel)]

    bssid = args.get("bssid")
    if bssid:
        if err := validate_bssid(bssid):
            return {"isError": True, "text": err}
        cmd.extend(["-a", bssid])

    cmd.append(iface)
    result = run_cmd(cmd, timeout=timeout)
    output = result["stdout"] or result["stderr"]
    return {"isError": not result["success"], "text": f"Evil twin ran for {timeout}s.\n\n{output}"}


def handle_auto_crack_wep(args: dict) -> dict:
    iface = args["interface"]
    timeout = clamp(args.get("timeout", 120), 30, 600)

    if err := validate_interface(iface):
        return {"isError": True, "text": err}

    cmd = ["besside-ng", iface]

    bssid = args.get("bssid")
    if bssid:
        if err := validate_bssid(bssid):
            return {"isError": True, "text": err}
        cmd.extend(["-b", bssid])

    result = run_cmd(cmd, timeout=timeout)
    output = result["stdout"] or result["stderr"]
    return {"isError": not result["success"], "text": f"Auto-crack ran for {timeout}s.\n\n{output}"}


def handle_clean_capture(args: dict) -> dict:
    input_file = args["input_file"]
    output_file = args["output_file"]

    if err := validate_file_exists(input_file):
        return {"isError": True, "text": err}

    result = run_cmd(["wpaclean", output_file, input_file])
    output = result["stdout"] or result["stderr"]
    return {"isError": not result["success"], "text": output}


# Map tool names to handlers
TOOL_HANDLERS = {
    "start_monitor": handle_start_monitor,
    "stop_monitor": handle_stop_monitor,
    "scan_wifi": handle_scan_wifi,
    "capture_handshake": handle_capture_handshake,
    "deauth": handle_deauth,
    "crack_wifi": handle_crack_wifi,
    "list_interfaces": handle_list_interfaces,
    "fake_auth": handle_fake_auth,
    "arp_replay": handle_arp_replay,
    "decrypt_capture": handle_decrypt_capture,
    "create_evil_twin": handle_create_evil_twin,
    "auto_crack_wep": handle_auto_crack_wep,
    "clean_capture": handle_clean_capture,
}


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 helpers
# ---------------------------------------------------------------------------
def make_response(req_id, result: dict) -> dict:
    """Build a successful JSON-RPC 2.0 response."""
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def make_error(req_id, code: int, message: str, data=None) -> dict:
    """Build a JSON-RPC 2.0 error response."""
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


# Standard JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


# ---------------------------------------------------------------------------
# MCP request handler
# ---------------------------------------------------------------------------
def handle_request(req: dict) -> dict:
    """Process a single MCP JSON-RPC request and return a response."""
    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    log.debug("← method=%s id=%s", method, req_id)

    # ---- initialize ----
    if method == "initialize":
        return make_response(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": {},
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
            },
        })

    # ---- notifications/initialized (no response needed) ----
    if method == "notifications/initialized":
        return None  # Notifications don't get responses

    # ---- ping ----
    if method == "ping":
        return make_response(req_id, {})

    # ---- tools/list ----
    if method == "tools/list":
        return make_response(req_id, {"tools": TOOLS})

    # ---- tools/call ----
    if method == "tools/call":
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})

        handler = TOOL_HANDLERS.get(tool_name)
        if not handler:
            return make_error(
                req_id,
                INVALID_PARAMS,
                f"Unknown tool: '{tool_name}'",
            )

        try:
            result = handler(tool_args)
            return make_response(req_id, {
                "content": [
                    {"type": "text", "text": result["text"]}
                ],
                "isError": result.get("isError", False),
            })
        except KeyError as e:
            return make_error(
                req_id,
                INVALID_PARAMS,
                f"Missing required parameter: {e}",
            )
        except Exception as e:
            log.exception("Tool execution error")
            return make_error(req_id, INTERNAL_ERROR, str(e))

    # ---- Unknown method ----
    return make_error(req_id, METHOD_NOT_FOUND, f"Unknown method: '{method}'")


# ---------------------------------------------------------------------------
# Main stdio loop
# ---------------------------------------------------------------------------
def main():
    """MCP stdio transport: read JSON-RPC from stdin, write to stdout."""
    log.info("Aircrack-ng MCP server started (protocol %s)", PROTOCOL_VERSION)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        # Parse JSON
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            err = make_error(None, PARSE_ERROR, f"Invalid JSON: {e}")
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()
            continue

        # Validate basic JSON-RPC structure
        if not isinstance(req, dict) or "method" not in req:
            err = make_error(
                req.get("id") if isinstance(req, dict) else None,
                INVALID_REQUEST,
                "Invalid request: missing 'method' field.",
            )
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()
            continue

        # Handle request
        response = handle_request(req)

        # Notifications (like initialized) return None — no response sent
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

    log.info("Server shutting down.")


if __name__ == "__main__":
    main()
