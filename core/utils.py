"""
MITM Toolkit Utilities
Windows-specific helpers for network attacks.
"""
import ctypes
import os
import re
import subprocess
import sys
import time
from ctypes import wintypes

# --------------- Admin Check ---------------
def is_admin() -> bool:
    """Return True if running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def require_admin():
    """Exit if not running as admin."""
    if not is_admin():
        print("\n[!] This tool requires Administrator privileges.")
        print("[!] Please re-run from an elevated Command Prompt or PowerShell.\n")
        sys.exit(1)


# --------------- Npcap / Scapy Check ---------------
def check_npcap() -> bool:
    """
    Check if Npcap (or WinPcap) is installed by looking for its DLL.
    Returns True if found.
    """
    # Common Npcap/WinPcap DLL paths
    paths = [
        os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "Npcap", "wpcap.dll"),
        os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "wpcap.dll"),
        os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "SysWOW64", "Npcap", "wpcap.dll"),
        os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "SysWOW64", "wpcap.dll"),
    ]
    for p in paths:
        if os.path.exists(p):
            return True
    return False


def check_scapy() -> bool:
    """Check if Scapy is importable."""
    try:
        import scapy  # noqa: F401
        return True
    except ImportError:
        return False


def run_prerequisite_checks() -> bool:
    """Run all checks. Return True only if everything is ready."""
    print("\n" + "=" * 60)
    print("  MITM Toolkit - Prerequisite Check")
    print("=" * 60)

    ok = True

    # Admin check
    if is_admin():
        print("  [\u2713] Administrator privileges")
    else:
        print("  [\u2717] Administrator privileges - RE-RUN AS ADMIN")
        ok = False

    # Npcap check
    if check_npcap():
        print("  [\u2713] Npcap detected")
    else:
        print("  [\u2717] Npcap NOT found")
        print("       Download from: https://npcap.com/#download")
        print("       Install with 'WinPcap API-compatible Mode' checked!")
        ok = False

    # Scapy check
    if check_scapy():
        import scapy
        print(f"  [\u2713] Scapy {scapy.__version__} installed")
    else:
        print("  [\u2717] Scapy NOT installed - run: pip install scapy")
        ok = False

    print("=" * 60)
    return ok


# --------------- IP Forwarding ---------------
def enable_ip_forwarding() -> bool:
    """
    Enable IP routing on Windows via registry.
    Returns True if successful or already enabled.
    """
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE
        )
        try:
            current, _ = winreg.QueryValueEx(key, "IPEnableRouter")
        except FileNotFoundError:
            current = 0

        if current == 1:
            winreg.CloseKey(key)
            return True

        winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        print("[*] IP forwarding enabled in registry (may require reboot to take effect)")
        return True
    except Exception as e:
        print(f"[!] Failed to enable IP forwarding via registry: {e}")
        print("[*] Trying netsh fallback...")
        try:
            subprocess.run(
                ["netsh", "interface", "ipv4", "set", "global", "forwarding=enabled"],
                capture_output=True, check=True
            )
            print("[*] IP forwarding enabled via netsh")
            return True
        except Exception as e2:
            print(f"[!] netsh fallback also failed: {e2}")
            return False


def check_ip_forwarding() -> bool:
    """Check if IP forwarding is enabled in the registry."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            0, winreg.KEY_READ
        )
        val, _ = winreg.QueryValueEx(key, "IPEnableRouter")
        winreg.CloseKey(key)
        return val == 1
    except Exception:
        return False


def disable_ip_forwarding():
    """Disable IP routing on Windows."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        print("[*] IP forwarding disabled in registry")
    except Exception:
        try:
            subprocess.run(
                ["netsh", "interface", "ipv4", "set", "global", "forwarding=disabled"],
                capture_output=True, check=True
            )
        except Exception:
            pass


# --------------- Network Info ---------------
def get_default_gateway() -> str:
    """Return the default gateway IP as a string."""
    try:
        result = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2]
    except Exception:
        pass
    return ""


def get_local_ip(gateway_ip: str = "") -> str:
    """
    Get the local IP address on the interface that reaches the gateway.
    Falls back to Scapy if available, otherwise uses socket.
    """
    # Try Scapy first (most reliable for finding the right interface)
    try:
        from scapy.all import conf, get_if_addr
        # Try to find the interface with a route to the gateway
        if gateway_ip:
            iface = conf.route.route(gateway_ip)[0]
            return get_if_addr(iface)
    except Exception:
        pass

    # Socket fallback
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((gateway_ip or "8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_local_mac(ip: str = "") -> str:
    """Get the local MAC address. Returns empty string on failure."""
    try:
        from scapy.all import get_if_hwaddr, conf
        if ip:
            route = conf.route.route(ip)
            if route and route[0]:
                return get_if_hwaddr(route[0])
        return get_if_hwaddr(conf.iface)
    except Exception:
        pass

    # Fallback: parse getmac output
    try:
        result = subprocess.run(["getmac"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            m = re.search(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", line)
            if m:
                return m.group(0).replace("-", ":")
    except Exception:
        pass
    return ""


def get_interface_name() -> str:
    """Get the network interface name Scapy will use."""
    try:
        from scapy.all import conf
        return str(conf.iface)
    except Exception:
        return "unknown"


# --------------- Banner ---------------
BANNER = r"""
  ███╗   ███╗  ██╗  ████████╗  ███╗   ███╗
  ████╗ ████║  ██║  ╚══██╔══╝  ████╗ ████║
  ██╔████╔██║  ██║     ██║     ██╔████╔██║
  ██║╚██╔╝██║  ██║     ██║     ██║╚██╔╝██║
  ██║ ╚═╝ ██║  ██║     ██║     ██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝     ╚═╝     ╚═╝     ╚═╝

  ███╗   ███╗   █████╗   ██████╗    █████╗   ██╗   ██╗  ██████╗   ███████╗  ██████╗
  ████╗ ████║  ██╔══██╗  ██╔══██╗  ██╔══██╗  ██║   ██║  ██╔══██╗  ██╔════╝  ██╔══██╗
  ██╔████╔██║  ███████║  ██████╔╝  ███████║  ██║   ██║  ██║  ██║  █████╗    ██████╔╝
  ██║╚██╔╝██║  ██╔══██║  ██╔══██╗  ██╔══██║  ██║   ██║  ██║  ██║  ██╔══╝    ██╔══██╗
  ██║ ╚═╝ ██║  ██║  ██║  ██║  ██║  ██║  ██║  ╚██████╔╝  ██████╔╝  ███████╗  ██║  ██║
  ╚═╝     ╚═╝  ╚═╝  ╚═╝  ╚═╝  ╚═╝  ╚═╝  ╚═╝   ╚═════╝   ╚═════╝   ╚══════╝  ╚═╝  ╚═╝

  v0.5, have fun with networks :)
"""


def print_banner():
    # Switch Windows console to UTF-8 so box-drawing and braille chars render
    if sys.platform == "win32":
        try:
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except OSError:
            pass

    root = os.path.dirname(os.path.dirname(__file__))

    def _load(path):
        try:
            with open(os.path.join(root, path), "r", encoding="utf-8") as f:
                return f.read().splitlines()
        except OSError:
            return []

    skulls = _load("skulls_ascii.txt")
    wifi   = _load("wifi_ascii.txt")

    # Drop trailing empty lines from both arts (skulls file ends with \r\n\r\n)
    while skulls and skulls[-1] == "":
        skulls.pop()
    while wifi and wifi[-1] == "":
        wifi.pop()

    # Pad the shorter art to match the longer one so they line up vertically.
    max_lines = max(len(skulls), len(wifi))
    skulls += [""] * (max_lines - len(skulls))
    wifi   += [""] * (max_lines - len(wifi))

    # Side-by-side: skulls on the left, wifi on the right, with a tab gap.
    gap = "\t"
    art = "\n".join(s + gap + w for s, w in zip(skulls, wifi))

    # Output: BANNER, then a blank line, then the combined skulls+wifi art.
    sys.stdout.buffer.write((BANNER + "\n" + art + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()
