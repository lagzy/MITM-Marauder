"""
Network Scanner Module
Discovers live hosts on the local network via ARP requests.
"""
import ipaddress
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import ARP, Ether, srp, conf, getmacbyip
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Suppress scapy's daemon-thread pipe-cleanup OSError tracebacks.
# On Windows+Npcap, scapy's sendrecv daemon threads crash during cleanup
# with OSError (Bad file descriptor / Invalid argument). These errors are
# harmless but flood stderr. This hook silences them globally.
_original_excepthook = threading.excepthook

def _silent_scapy_hook(args):
    if isinstance(args.exc_type, OSError):
        pass  # scapy sndrcv pipe cleanup — harmless on Windows
    else:
        _original_excepthook(args)

threading.excepthook = _silent_scapy_hook


def get_local_network() -> str:
    """Detect the local network CIDR (e.g., '192.168.1.0/24')."""
    from .utils import get_default_gateway, get_local_ip

    gateway = get_default_gateway()
    local_ip = get_local_ip(gateway)

    # Guess the /24 subnet
    parts = local_ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "192.168.1.0/24"


def arp_scan(network: str, timeout: float = 2.0, verbose: bool = True) -> list[dict]:
    """
    Perform an ARP scan on the given network.
    Returns list of dicts with 'ip' and 'mac' keys.
    """
    if not SCAPY_AVAILABLE:
        print("[!] Scapy is not installed. Cannot scan.")
        return []

    if verbose:
        print(f"\n[*] ARP scanning {network} ...")

    try:
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        answered, _ = srp(packet, timeout=timeout, verbose=0, retry=1)

        hosts = []
        for sent, received in answered:
            host = {"ip": received.psrc, "mac": received.hwsrc}
            hosts.append(host)
            if verbose:
                print(f"  [LIVE] {host['ip']:15s} - {host['mac']}")

        if verbose:
            print(f"\n[*] Found {len(hosts)} live host(s)\n")

        # Sort by IP
        hosts.sort(key=lambda h: [int(x) for x in h["ip"].split(".")])
        return hosts

    except PermissionError:
        print("[!] Permission denied - run as Administrator")
        return []
    except Exception as e:
        print(f"[!] Scan failed: {e}")
        return []


def ping_sweep(network: str, timeout: float = 1.0, max_workers: int = 50, verbose: bool = True) -> list[str]:
    """
    ICMP ping sweep using OS ping command (no scapy sndrcv).
    Returns list of live IPs. Much more stable on Windows than scapy's sr1().
    """
    if verbose:
        print(f"\n[*] ICMP ping sweep on {network} ...")

    net = ipaddress.ip_network(network, strict=False)
    live_ips = []
    lock = threading.Lock()

    def ping_host(ip_str: str) -> str | None:
        try:
            # Windows ping: -n 1 = 1 packet, -w = timeout in ms
            result = subprocess.run(
                ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip_str],
                capture_output=True, timeout=timeout + 1
            )
            # Check for "TTL=" in output (indicates reply)
            if b"TTL=" in result.stdout or b"ttl=" in result.stdout:
                with lock:
                    if verbose:
                        print(f"  [LIVE] {ip_str}")
                return ip_str
        except Exception:
            pass
        return None

    ips = [str(ip) for ip in net.hosts()]
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in ips}
        for future in as_completed(futures):
            result = future.result()
            if result:
                live_ips.append(result)

    live_ips.sort(key=lambda ip: [int(x) for x in ip.split(".")])
    if verbose:
        print(f"\n[*] Found {len(live_ips)} live host(s)\n")
    return live_ips


def smart_scan(network: str | None = None, timeout: float = 2.0,
               verbose: bool = True) -> list[dict]:
    """
    Multi-method network scan. Runs ARP + ICMP ping sweep in parallel,
    merging results. ARP provides IP+MAC, ICMP finds devices behind
    WiFi client isolation (which blocks ARP between wireless clients).

    Returns list of dicts with 'ip' and 'mac' keys.
    MAC will be '??:??:??:??:??:??' for ICMP-discovered hosts whose
    MAC could not be resolved via ARP.
    """
    if network is None:
        network = get_local_network()

    if not SCAPY_AVAILABLE:
        print("[!] Scapy is not installed. Cannot scan.")
        return []

    if verbose:
        print(f"\n[*] Smart scanning {network} (ARP + ICMP)...")
        print("[*] This finds devices even behind WiFi client isolation")

    arp_hosts: list[dict] = []
    icmp_ips: list[str] = []

    # Run ARP and ICMP scans in parallel
    def _run_arp():
        nonlocal arp_hosts
        arp_hosts = arp_scan(network, timeout=timeout, verbose=False)

    def _run_icmp():
        nonlocal icmp_ips
        icmp_ips = ping_sweep(network, timeout=timeout, max_workers=100, verbose=False)

    t1 = threading.Thread(target=_run_arp, daemon=True)
    t2 = threading.Thread(target=_run_icmp, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Merge: ARP hosts form the base (they have MACs)
    merged: dict[str, dict] = {}
    for h in arp_hosts:
        merged[h["ip"]] = h

    # Add ICMP-discovered hosts missing from ARP
    for ip in icmp_ips:
        if ip not in merged:
            # Try targeted ARP resolution (might fail on isolated WiFi)
            mac = _resolve_single_mac(ip, timeout=1.0)
            merged[ip] = {"ip": ip, "mac": mac or "??:??:??:??:??:??"}

    hosts = list(merged.values())
    hosts.sort(key=lambda h: [int(x) for x in h["ip"].split(".")])

    if verbose:
        for h in hosts:
            mac_str = h["mac"]
            tag = ""
            if mac_str == "??:??:??:??:??:??":
                tag = " [ICMP only - MAC unknown]"
            print(f"  [LIVE] {h['ip']:15s} - {mac_str}{tag}")
        print(f"\n[*] Found {len(hosts)} live host(s) ({len(arp_hosts)} via ARP, {len(icmp_ips)} via ICMP)\n")

    return hosts


def _resolve_single_mac(ip: str, timeout: float = 1.0) -> str | None:
    """Try to resolve a single MAC via OS ping+cache (no scapy sndrcv)."""
    try:
        # Ping to force ARP resolution, then read OS cache
        subprocess.run(
            ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip],
            capture_output=True, timeout=timeout + 1
        )
        result = subprocess.run(
            ["arp", "-a", ip],
            capture_output=True, text=True, timeout=2
        )
        for line in result.stdout.splitlines():
            if ip in line:
                m = re.search(r"(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})", line)
                if m:
                    return m.group(1).replace("-", ":").lower()
    except Exception:
        pass

    # Fallback: OS ARP cache (might already be populated)
    try:
        return getmacbyip(ip)
    except Exception:
        return None


def get_targets(network: str | None = None) -> list[dict]:
    """
    Interactive target selection. Uses smart scan and lets user pick targets.
    """
    if network is None:
        network = get_local_network()

    hosts = smart_scan(network)

    if not hosts:
        print("[!] No hosts found.")
        return []

    from .utils import get_default_gateway
    gateway = get_default_gateway()

    # Mark the gateway
    for h in hosts:
        h["is_gateway"] = (h["ip"] == gateway)

    print("\n  #   IP Address        MAC Address          Role")
    print("  --- ---------------- -------------------- --------")
    for i, h in enumerate(hosts):
        role = "GATEWAY" if h["is_gateway"] else ""
        print(f"  {i:2d}  {h['ip']:16s} {h['mac']:20s} {role}")

    print("\n  Enter target numbers (comma-separated, e.g. '0,1,3' or 'all'):")
    choice = input("  > ").strip()

    if choice.lower() == "all":
        return hosts

    try:
        indices = [int(x.strip()) for x in choice.split(",")]
        return [hosts[i] for i in indices if 0 <= i < len(hosts)]
    except (ValueError, IndexError):
        print("[!] Invalid selection.")
        return []


if __name__ == "__main__":
    hosts = get_targets()
    print(f"\nSelected: {hosts}")
