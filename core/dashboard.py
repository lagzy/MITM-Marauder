"""
Kill Switch Real-Time Dashboard
================================
Live terminal visualization of ARP poison packet flow using the `rich` library.
Shows per-target packet counts, real-time PPS, and visual throughput bars.

Usage (standalone):  python -m core.dashboard
Usage (integrated):  from core.dashboard import show_kill_dashboard
                     show_kill_dashboard()  # blocks until user exits
"""
import threading
import time

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

# Late imports to avoid slowing down mitm_app startup
# These are only used when the dashboard is actually shown.
_get_kill_metrics = None
_is_killswitch_active = None
_stop_killswitch = None


def _lazy_import():
    """Lazy-load arp_spoof functions (only when dashboard is actually shown)."""
    global _get_kill_metrics, _is_killswitch_active, _stop_killswitch
    if _get_kill_metrics is None:
        from core.arp_spoof import get_kill_metrics, is_killswitch_active, stop_killswitch
        _get_kill_metrics = get_kill_metrics
        _is_killswitch_active = is_killswitch_active
        _stop_killswitch = stop_killswitch


def _format_duration(seconds: float) -> str:
    """Format seconds as HH:MM:SS."""
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    if h > 0:
        return f"{h:02d}:{m:02d}:{s:02d}"
    elif m > 0:
        return f"{m:02d}:{s:02d}"
    return f"{s}s"


def _format_number(n: int) -> str:
    """Format large numbers with commas."""
    return f"{n:,}"


def _build_layout(metrics: dict) -> Layout:
    """Build the complete dashboard layout from metrics snapshot."""
    active = metrics.get("active", False)
    total_pkts = metrics.get("total_packets", 0)
    elapsed = metrics.get("elapsed", 0.0)
    pps = metrics.get("pps", 0.0)
    targets = metrics.get("targets", [])

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=7),
        Layout(name="body"),
    )

    # ── HEADER ──
    status_color = "bold red" if active else "dim white"
    status_text = "WiFi Pisoning Active" if active else "WiFi Pisoning stopped"
    uptime_str = _format_duration(elapsed)
    n_targets = len(set(t.get("ip", "") for t in targets))
    n_threads = len(targets)

    header_text = Text()
    header_text.append(f"\n  {status_text}", style=status_color)
    header_text.append(f"  —  {uptime_str}\n\n", style="bold cyan")
    header_text.append(
        f"  Targets: {n_targets}  │  Threads: {n_threads}  │  "
        f"Packets: {_format_number(total_pkts)}\n",
        style="white"
    )
    rate_style = "bold green" if pps > 100 else "yellow"
    header_text.append(f"  Rate: {pps:,.0f} pkt/sec  ", style=rate_style)
    header_text.append("q=Menu  s=Stop", style="dim")

    layout["header"].update(Panel(header_text, box=box.HEAVY,
                                  border_style="red" if active else "dim"))

    # ── BODY: Per-target table ──
    if targets:
        # Aggregate by IP (merge target+gateway directions)
        aggregated: dict[str, dict] = {}
        for t in targets:
            ip = t["ip"]
            mac = t.get("mac", "??:??:??:??:??:??")
            if ip not in aggregated:
                aggregated[ip] = {"target": 0, "gateway": 0, "mac": mac}
            else:
                # Prefer real MAC over "broadcast" placeholder
                if mac != "broadcast":
                    aggregated[ip]["mac"] = mac
            aggregated[ip][t["direction"]] = t.get("packets", 0)

        max_pkts = max(
            (v["target"] + v["gateway"]) for v in aggregated.values()
        ) if aggregated else 1

        table = Table(
            title=f"Per-Target ARP Poison Flow ({len(aggregated)} hosts)",
            box=box.ROUNDED,
            expand=True,
            title_style="bold cyan",
        )
        table.add_column("Target IP", style="bold white", width=18)
        table.add_column("MAC", style="dim", width=20)
        table.add_column("→ GW", justify="right", style="red", width=10)
        table.add_column("← GW", justify="right", style="blue", width=10)
        table.add_column("Total", justify="right", style="bold yellow", width=11)
        table.add_column("Throughput", width=30)

        bar_width = 28
        # Only show top 20 to avoid terminal overload with many targets
        sorted_targets = sorted(aggregated.items(),
                                key=lambda x: x[1]["target"] + x[1]["gateway"],
                                reverse=True)
        for ip, dirs in sorted_targets[:20]:
            t_pkts = dirs["target"]
            g_pkts = dirs["gateway"]
            total = t_pkts + g_pkts
            pct = (total / max_pkts * bar_width) if max_pkts > 0 else 0
            filled = int(pct)
            if total > 0:
                t_portion = int(t_pkts / total * filled)
                g_portion = filled - t_portion
            else:
                t_portion = g_portion = 0
            empty = bar_width - filled

            bar = ""
            if t_portion > 0:
                bar += f"[red]{'█' * t_portion}[/red]"
            if g_portion > 0:
                bar += f"[blue]{'█' * g_portion}[/blue]"
            if empty > 0:
                bar += f"[dim]{'░' * empty}[/dim]"

            table.add_row(
                ip,
                dirs.get("mac", "??:??:??:??:??:??"),
                _format_number(t_pkts),
                _format_number(g_pkts),
                _format_number(total),
                bar,
            )

        if len(sorted_targets) > 20:
            table.add_row(
                f"... +{len(sorted_targets) - 20} more",
                "", "", "", "",
                f"[dim]({len(sorted_targets)} targets total)[/dim]"
            )

        # Legend row
        legend = Text("  █ [red]→ GW[/red]  █ [blue]← GW[/blue]  q=Menu  s=Stop",
                      style="dim")
        table.add_row("", "", "", "", "", legend)

        layout["body"].update(Panel(table, box=box.ROUNDED, border_style="cyan"))
    else:
        empty = Text("\n  No packet data yet...\n", style="dim italic")
        layout["body"].update(Panel(empty, box=box.ROUNDED, border_style="cyan"))

    return layout


def show_kill_dashboard():
    """
    Show a full-screen live dashboard of the Kill Switch.
    Blocks until user presses 'q'/'Enter' (quit to menu) or 's' (stop kill switch).
    Kill switch continues running in background when pressing 'q'.

    Uses msvcrt on Windows for non-blocking keyboard input.
    """
    _lazy_import()

    if not _is_killswitch_active():
        print("[!] Kill Switch is not active. Start it first.")
        return

    # Set up keyboard listener on Windows (msvcrt is Windows-only)
    key_pressed = threading.Event()
    key_value = {"ch": None}

    def keyboard_listener():
        try:
            import msvcrt as m  # Windows-only (this tool only runs on Windows)
        except ImportError:
            # Non-Windows fallback — select-based stdin poll (untested, requires raw tty)
            import sys, select
            while not key_pressed.is_set():
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    ch = sys.stdin.read(1)
                    key_value["ch"] = ch.encode() if isinstance(ch, str) else ch
                    key_pressed.set()
                    break
                time.sleep(0.05)
            return

        while not key_pressed.is_set():
            if m.kbhit():
                ch = m.getch()
                key_value["ch"] = ch
                key_pressed.set()
                break
            time.sleep(0.05)

    kb_thread = threading.Thread(target=keyboard_listener, daemon=True)
    kb_thread.start()

    console = Console()

    with Live(_build_layout(_get_kill_metrics()), console=console,
              screen=True, refresh_per_second=4, transient=False) as live:
        while not key_pressed.is_set():
            metrics = _get_kill_metrics()
            live.update(_build_layout(metrics))
            time.sleep(0.3)

    # Live.__exit__ already restored the terminal
    ch = key_value.get("ch", b"")
    if ch and ch.lower() == b"s":
        _stop_killswitch()
        print("\n[✓] WiFi Pisoning stopped. Returning to menu...")
    elif ch == b"\r" or ch:
        print("\n[*] WiFi Pisoning still running. Press S in menu to stop.\n")


if __name__ == "__main__":
    print("Dashboard standalone mode — import and call show_kill_dashboard() instead.")
    print("Run from within the MITM toolkit after starting Kill Switch.")
