"""Shockwave UI - Terminal interface rendering."""

import os
import shutil

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.align import Align
from rich import box

from shockwave.ascii_art import (
    SHOCKWAVE_TITLE,
    SHOCKWAVE_CHAR,
    DECEPTICON_LOGO_SMALL,
    GLOBE_ICON,
)

console = Console(highlight=False)

PURPLE = "bright_magenta"
DARK_PURPLE = "magenta"
GREEN = "green"
CYAN = "cyan"
RED = "red"
YELLOW = "yellow"
WHITE = "white"
DIM = "dim"

BORDER_STYLE = "bright_magenta"
TITLE_STYLE = "bold bright_magenta"


def clear_screen():
    """Clear the terminal screen."""
    os.system("clear" if os.name != "nt" else "cls")


def get_terminal_width():
    """Get terminal width."""
    return shutil.get_terminal_size().columns


def render_splash_screen(target, target_type, username, resolved_ip=None, datetime_str=""):
    """Render the full splash screen matching the Decepticon theme."""
    clear_screen()
    width = get_terminal_width()

    _render_header_banner(width)
    _render_target_info(target, target_type, username, datetime_str, width)
    _render_init_log(target, resolved_ip, width)
    _render_footer(width)


def _render_header_banner(width):
    """Render the top banner with ASCII art and title."""
    char_lines = [l for l in SHOCKWAVE_CHAR.split("\n") if l.strip()]
    title_lines = [l for l in SHOCKWAVE_TITLE.split("\n") if l.strip()]

    char_max_width = max(len(l) for l in char_lines) if char_lines else 0

    inner_width = width - 6

    if inner_width >= char_max_width + 78:
        right_col_width = inner_width - char_max_width - 2

        subtitle_line = "— NETWORK DIAGNOSTIC TOOLKIT —"
        version_line = "VERSION 0.1.0"

        logo_lines = [l for l in DECEPTICON_LOGO_SMALL.split("\n") if l.strip()]
        motto_lines = [
            "LOGIC. SUPERIORITY.",
            "OBJECTIVE: CONTROL.",
            "",
            "DECEPTICON INTELLIGENCE UNIT",
        ]

        right_lines = []
        for tl in title_lines:
            right_lines.append(("title", tl))

        right_lines.append(("subtitle", ""))
        right_lines.append(("subtitle", subtitle_line))
        right_lines.append(("subtitle", ""))
        right_lines.append(("version", version_line))
        right_lines.append(("subtitle", ""))

        motto_block_start = len(right_lines)
        max_motto_height = max(len(logo_lines), len(motto_lines))
        for i in range(max_motto_height):
            logo_part = logo_lines[i] if i < len(logo_lines) else ""
            motto_part = motto_lines[i] if i < len(motto_lines) else ""
            right_lines.append(("motto", (logo_part, motto_part)))

        max_lines = max(len(char_lines), len(right_lines))

        banner_text = Text()
        for i in range(max_lines):
            left = char_lines[i] if i < len(char_lines) else ""
            left_padded = left.ljust(char_max_width)

            if i < len(right_lines):
                rtype, rdata = right_lines[i]
                banner_text.append(left_padded, style=DARK_PURPLE)
                banner_text.append("  ", style="")

                if rtype == "title":
                    banner_text.append(rdata, style=f"bold {PURPLE}")
                elif rtype == "subtitle":
                    banner_text.append(rdata, style=f"bold {PURPLE}")
                elif rtype == "version":
                    banner_text.append(rdata, style=f"bold {GREEN}")
                elif rtype == "motto":
                    logo_part, motto_part = rdata
                    banner_text.append(f"{logo_part:14s}", style=PURPLE)
                    if "DECEPTICON" in motto_part:
                        banner_text.append(motto_part, style=f"bold {PURPLE}")
                    else:
                        banner_text.append(motto_part, style=f"bold {WHITE}")
            else:
                banner_text.append(left_padded, style=DARK_PURPLE)

            banner_text.append("\n")
    else:
        for tl in title_lines:
            banner_text = Text()
            banner_text.append(tl, style=f"bold {PURPLE}")

        banner_text = Text()
        for tl in title_lines:
            banner_text.append(tl + "\n", style=f"bold {PURPLE}")

        banner_text.append("\n")
        banner_text.append("  — NETWORK DIAGNOSTIC TOOLKIT —\n", style=f"bold {PURPLE}")
        banner_text.append("  VERSION 0.1.0\n", style=f"bold {GREEN}")
        banner_text.append("\n")

        for cl in char_lines:
            banner_text.append(cl + "\n", style=DARK_PURPLE)

    banner_panel = Panel(
        banner_text,
        border_style=BORDER_STYLE,
        box=box.ROUNDED,
        padding=(0, 1),
    )
    console.print(banner_panel)


def _render_target_info(target, target_type, username, datetime_str, width):
    """Render the target information panel."""
    info_table = Table(show_header=False, show_edge=False, box=None, padding=(0, 1), expand=True)
    info_table.add_column("icon", width=3, justify="center")
    info_table.add_column("label", width=16, style=f"bold {PURPLE}")
    info_table.add_column("sep", width=3, justify="center")
    info_table.add_column("value", ratio=1)

    target_val = Text(target, style=f"bold {GREEN}")
    status_val = Text("Resolving host...", style=f"bold {YELLOW}")
    time_val = Text(datetime_str, style=WHITE)
    user_val = Text(username, style=WHITE)

    info_table.add_row(
        Text("◎", style=CYAN), "TARGET", Text(":", style=DIM), target_val,
    )
    info_table.add_row(
        Text("⚡", style=YELLOW), "STATUS", Text(":", style=DIM), status_val,
    )
    info_table.add_row(
        Text("◷", style=CYAN), "DATE & TIME", Text(":", style=DIM), time_val,
    )
    info_table.add_row(
        Text("☉", style=CYAN), "USER", Text(":", style=DIM), user_val,
    )

    type_text = Text(justify="center")
    type_text.append("[ TARGET TYPE ]\n\n", style=f"bold {PURPLE}")
    for line in GLOBE_ICON.strip().split("\n"):
        type_text.append(f"    {line}\n", style=CYAN)
    type_text.append(f"\n     {target_type.upper()}", style=f"bold {CYAN}")

    outer_table = Table(show_header=False, show_edge=False, box=None, expand=True, padding=0)
    outer_table.add_column(ratio=2)
    outer_table.add_column(ratio=1, justify="center")
    outer_table.add_row(info_table, type_text)

    info_panel = Panel(
        outer_table,
        title=Text(" ꕥ TARGET INFORMATION ", style=f"bold {PURPLE}"),
        title_align="left",
        border_style=BORDER_STYLE,
        box=box.ROUNDED,
        padding=(1, 2),
    )
    console.print(info_panel)


def _render_init_log(target, resolved_ip, width):
    """Render the initialization log and system status panels side by side."""
    log_text = Text()
    log_text.append("[i] ", style=f"bold {CYAN}")
    log_text.append("Initializing Shockwave...\n", style=WHITE)
    log_text.append("[i] ", style=f"bold {CYAN}")
    log_text.append("Checking target...\n", style=WHITE)

    if resolved_ip:
        log_text.append("[+] ", style=f"bold {GREEN}")
        log_text.append("Host resolved successfully\n", style=f"bold {GREEN}")
        log_text.append(f"     -> Hostname  : ", style=WHITE)
        log_text.append(f"{target}\n", style=f"bold {WHITE}")
        log_text.append(f"     -> IPv4      : ", style=WHITE)
        log_text.append(f"{resolved_ip}\n", style=f"bold {CYAN}")
        log_text.append("[√] ", style=f"bold {GREEN}")
        log_text.append("Ready.", style=f"bold {GREEN}")
    else:
        log_text.append("[!] ", style=f"bold {RED}")
        log_text.append("Could not resolve host\n", style=f"bold {RED}")
        log_text.append("[√] ", style=f"bold {GREEN}")
        log_text.append("Ready (using target as-is).", style=f"bold {GREEN}")

    log_panel = Panel(
        log_text,
        title=Text(" ꕥ INITIALIZATION LOG ", style=f"bold {PURPLE}"),
        title_align="left",
        border_style=BORDER_STYLE,
        box=box.ROUNDED,
        padding=(1, 2),
        expand=True,
    )

    status_table = Table(show_header=False, show_edge=False, box=None, padding=(0, 1), expand=True)
    status_table.add_column("component", style=f"bold {WHITE}", width=14)
    status_table.add_column("sep", width=3, justify="center", style=DIM)
    status_table.add_column("status", justify="center")

    components = ["RESOLVER", "NETWORK", "ENGINE", "DATABASE", "UI MODULE"]
    for comp in components:
        ok_text = Text()
        ok_text.append("[  ", style=DARK_PURPLE)
        ok_text.append("OK", style=f"bold {GREEN}")
        ok_text.append("  ]", style=DARK_PURPLE)
        status_table.add_row(comp, ":", ok_text)

    status_panel = Panel(
        status_table,
        title=Text(" SYSTEM STATUS ", style=f"bold {PURPLE}"),
        title_align="left",
        border_style=BORDER_STYLE,
        box=box.ROUNDED,
        padding=(1, 2),
        expand=True,
    )

    columns = Columns([log_panel, status_panel], expand=True, equal=False, padding=0)
    console.print(columns)


def _render_footer(width):
    """Render the bottom status bar."""
    footer_table = Table(show_header=False, show_edge=False, box=None, expand=True, padding=0)
    footer_table.add_column(justify="left", ratio=1)
    footer_table.add_column(justify="center", ratio=2)
    footer_table.add_column(justify="right", ratio=1)

    footer_table.add_row(
        Text("SHOCKWAVE v0.1.0", style=f"bold {PURPLE}"),
        Text("NETWORK DIAGNOSTIC TOOLKIT", style=f"bold {DIM}"),
        Text("DECEPTICON INTELLIGENCE UNIT", style=f"bold {PURPLE}"),
    )

    console.print()
    console.print(
        Panel(
            footer_table,
            border_style=DARK_PURPLE,
            box=box.HORIZONTALS,
            padding=0,
        )
    )


def print_prompt():
    """Print the command prompt and return user input."""
    try:
        return input("\033[35m shockwave > \033[0m")
    except (EOFError, KeyboardInterrupt):
        return "exit"


def print_help():
    """Display available commands."""
    help_table = Table(
        title=Text(" AVAILABLE COMMANDS ", style=f"bold {PURPLE}"),
        show_header=True,
        header_style=f"bold {PURPLE}",
        border_style=BORDER_STYLE,
        box=box.ROUNDED,
        padding=(0, 2),
        expand=True,
    )
    help_table.add_column("Command", style=f"bold {CYAN}", width=20)
    help_table.add_column("Description", style=WHITE)
    help_table.add_column("Usage", style=f"{DIM}")

    commands = [
        ("resolve", "Resolve hostname to IPv4", "resolve"),
        ("ping", "Ping target host", "ping [count]"),
        ("sweep", "Ping sweep a network range", "sweep <base_ip> [start-end]"),
        ("scan", "Scan common ports on target", "scan"),
        ("cscan", "Custom port scan", "cscan <port_spec>"),
        ("dns", "DNS records lookup (A, CNAME, PTR, MX, NS)", "dns"),
        ("trace", "Traceroute to target", "trace"),
        ("headers", "HTTP response headers", "headers"),
        ("whois", "WHOIS lookup (port 43)", "whois"),
        ("geo", "Geolocate IP address", "geo"),
        ("netinfo", "Local network information", "netinfo"),
        ("target", "Change target", "target <new_target>"),
        ("clear", "Clear screen", "clear"),
        ("banner", "Show splash screen again", "banner"),
        ("help", "Show this help", "help"),
        ("exit", "Exit Shockwave", "exit"),
    ]

    for cmd, desc, usage in commands:
        help_table.add_row(cmd, desc, usage)

    console.print()
    console.print(help_table)
    console.print()


def print_result_panel(title, content, style="info"):
    """Print a styled result panel."""
    if style == "success":
        border = GREEN
    elif style == "error":
        border = RED
    elif style == "warning":
        border = YELLOW
    else:
        border = BORDER_STYLE

    panel = Panel(
        content,
        title=Text(f" ꕥ {title} ", style=f"bold {PURPLE}"),
        title_align="left",
        border_style=border,
        box=box.ROUNDED,
        padding=(1, 2),
    )
    console.print()
    console.print(panel)


def print_info(message):
    """Print an info message."""
    text = Text()
    text.append(" [i] ", style=f"bold {CYAN}")
    text.append(message, style=WHITE)
    console.print(text)


def print_success(message):
    """Print a success message."""
    text = Text()
    text.append(" [+] ", style=f"bold {GREEN}")
    text.append(message, style=f"bold {GREEN}")
    console.print(text)


def print_error(message):
    """Print an error message."""
    text = Text()
    text.append(" [!] ", style=f"bold {RED}")
    text.append(message, style=f"bold {RED}")
    console.print(text)


def print_warning(message):
    """Print a warning message."""
    text = Text()
    text.append(" [!] ", style=f"bold {YELLOW}")
    text.append(message, style=YELLOW)
    console.print(text)


def format_resolve_result(result):
    """Format resolve host result."""
    text = Text()
    if result["success"]:
        text.append("Host resolved successfully\n\n", style=f"bold {GREEN}")
        text.append("  Hostname  : ", style=f"bold {PURPLE}")
        text.append(f"{result['hostname']}\n", style=WHITE)
        text.append("  IPv4      : ", style=f"bold {PURPLE}")
        text.append(f"{result['ipv4']}\n", style=f"bold {CYAN}")
    else:
        text.append(f"Resolution failed: {result['error']}", style=f"bold {RED}")
    return text


def format_ping_result(result):
    """Format ping result."""
    text = Text()
    if result["success"]:
        text.append(f"Ping results for {result['target']}:\n\n", style=f"bold {GREEN}")
        for line in result["output"].split("\n"):
            if "time=" in line:
                text.append(f"  {line}\n", style=CYAN)
            elif "statistics" in line or "packets" in line or "rtt" in line:
                text.append(f"  {line}\n", style=f"bold {WHITE}")
            elif line.strip():
                text.append(f"  {line}\n", style=WHITE)
    else:
        text.append(f"Ping failed: {result.get('error', 'Unknown error')}", style=f"bold {RED}")
    return text


def format_sweep_result(result):
    """Format ping sweep result."""
    text = Text()
    if result.get("success"):
        alive_count = len(result["alive"])
        text.append(f"Sweep complete: {alive_count}/{result['total']} hosts alive\n\n", style=f"bold {GREEN}")
        if result["alive"]:
            text.append("  Alive hosts:\n", style=f"bold {PURPLE}")
            for ip in result["alive"]:
                text.append(f"    [+] {ip}\n", style=f"bold {GREEN}")
    else:
        text.append(f"Sweep failed: {result.get('error', 'Unknown error')}", style=f"bold {RED}")
    return text


def format_port_scan_result(result):
    """Format port scan result."""
    if result.get("success"):
        open_count = len(result["open"])

        if result["open"]:
            scan_table = Table(
                title=Text(f"Scan complete on {result['target']}: {open_count}/{result['total']} ports open", style=f"bold {GREEN}"),
                show_header=True,
                header_style=f"bold {PURPLE}",
                box=box.SIMPLE,
                padding=(0, 2),
            )
            scan_table.add_column("PORT", style=f"bold {CYAN}", justify="right")
            scan_table.add_column("STATE", style=f"bold {GREEN}")
            scan_table.add_column("SERVICE", style=WHITE)

            for entry in result["open"]:
                scan_table.add_row(str(entry["port"]), "OPEN", entry["service"])

            return scan_table

        text = Text()
        text.append(f"Scan complete on {result['target']}: 0/{result['total']} ports open\n\n", style=f"bold {GREEN}")
        text.append("  No open ports found.", style=YELLOW)
        return text

    text = Text()
    text.append(f"Scan failed: {result.get('error', 'Unknown error')}", style=f"bold {RED}")
    return text


def format_dns_result(result):
    """Format DNS records result."""
    text = Text()
    text.append(f"DNS Records for {result['target']}:\n\n", style=f"bold {GREEN}")

    record_types = [
        ("A", result.get("A", [])),
        ("CNAME", result.get("CNAME", [])),
        ("PTR", result.get("PTR", [])),
        ("MX", result.get("MX", [])),
        ("NS", result.get("NS", [])),
    ]

    for rtype, records in record_types:
        text.append(f"  {rtype} Records:\n", style=f"bold {PURPLE}")
        if records:
            for record in records:
                text.append(f"    -> {record}\n", style=CYAN)
        else:
            text.append("    (none)\n", style=DIM)
        text.append("\n")

    return text


def format_traceroute_result(result):
    """Format traceroute result."""
    if result["success"]:
        if result["hops"]:
            trace_table = Table(
                title=Text(f"Traceroute to {result['target']}", style=f"bold {GREEN}"),
                show_header=True,
                header_style=f"bold {PURPLE}",
                box=box.SIMPLE,
                padding=(0, 2),
            )
            trace_table.add_column("HOP", style=f"bold {CYAN}", justify="right", width=5)
            trace_table.add_column("HOST", style=WHITE)
            trace_table.add_column("IP", style=CYAN)
            trace_table.add_column("RTT", style=GREEN)

            for hop in result["hops"]:
                rtt_str = " / ".join(f"{r} ms" if r != "*" else "*" for r in hop["rtt"])
                trace_table.add_row(
                    str(hop["hop"]),
                    hop["host"],
                    hop["ip"],
                    rtt_str,
                )
            return trace_table

        text = Text()
        text.append(f"Traceroute to {result['target']}:\n\n", style=f"bold {GREEN}")
        text.append(result.get("raw_output", "No hops recorded"), style=WHITE)
        return text

    text = Text()
    text.append(f"Traceroute failed: {result['error']}", style=f"bold {RED}")
    return text


def format_headers_result(result):
    """Format HTTP headers result."""
    if result["success"]:
        headers_table = Table(
            title=Text(f"{result['protocol']}:{result['port']} -> {result['status']} {result.get('status_reason', '')}", style=f"bold {GREEN}"),
            show_header=True,
            header_style=f"bold {PURPLE}",
            box=box.SIMPLE,
            padding=(0, 2),
        )
        headers_table.add_column("HEADER", style=f"bold {CYAN}")
        headers_table.add_column("VALUE", style=WHITE)

        for key, value in result["headers"].items():
            headers_table.add_row(key, str(value))

        return headers_table

    text = Text()
    text.append(f"HTTP Headers failed: {result.get('error', 'Unknown error')}", style=f"bold {RED}")
    return text


def format_whois_result(result):
    """Format WHOIS lookup result."""
    text = Text()
    if result["success"]:
        text.append(f"WHOIS for {result['target']} (server: {result['whois_server']})\n\n", style=f"bold {GREEN}")

        important_keys = [
            "domain name", "registrar", "creation date", "updated date",
            "registry expiry date", "registrant organization",
            "registrant country", "name server", "dnssec",
        ]

        parsed = result.get("parsed", {})
        shown = set()

        for key in important_keys:
            if key in parsed:
                value = parsed[key]
                if isinstance(value, list):
                    value = ", ".join(value)
                text.append(f"  {key.upper():30s} : ", style=f"bold {PURPLE}")
                text.append(f"{value}\n", style=WHITE)
                shown.add(key)

        remaining = {k: v for k, v in parsed.items() if k not in shown and k not in ("refer", "whois")}
        if remaining:
            text.append(f"\n  Additional Records:\n", style=f"bold {PURPLE}")
            for key, value in list(remaining.items())[:20]:
                if isinstance(value, list):
                    value = ", ".join(str(v) for v in value)
                text.append(f"    {key:28s} : ", style=PURPLE)
                text.append(f"{value}\n", style=DIM)

    else:
        text.append(f"WHOIS failed: {result.get('error', 'Unknown error')}", style=f"bold {RED}")
    return text


def format_geo_result(result):
    """Format geolocation result."""
    text = Text()
    if result["success"]:
        text.append(f"Geolocation for {result['ip']}:\n\n", style=f"bold {GREEN}")

        fields = [
            ("Country", result.get("country")),
            ("Region", result.get("region")),
            ("City", result.get("city")),
            ("ZIP", result.get("zip")),
            ("Latitude", str(result.get("latitude"))),
            ("Longitude", str(result.get("longitude"))),
            ("Timezone", result.get("timezone")),
            ("ISP", result.get("isp")),
            ("Organization", result.get("org")),
            ("AS", result.get("as")),
        ]

        for label, value in fields:
            text.append(f"  {label:15s} : ", style=f"bold {PURPLE}")
            text.append(f"{value}\n", style=WHITE)
    else:
        text.append(f"Geolocation failed: {result.get('error', 'Unknown error')}", style=f"bold {RED}")
    return text


def format_netinfo_result(result):
    """Format local network info result."""
    text = Text()
    text.append("Local Network Information:\n\n", style=f"bold {GREEN}")

    text.append("  Hostname    : ", style=f"bold {PURPLE}")
    text.append(f"{result.get('hostname', 'N/A')}\n", style=WHITE)
    text.append("  Local IP    : ", style=f"bold {PURPLE}")
    text.append(f"{result.get('local_ip', 'N/A')}\n", style=f"bold {CYAN}")
    text.append("  Public IP   : ", style=f"bold {PURPLE}")
    text.append(f"{result.get('public_ip', 'N/A')}\n", style=f"bold {CYAN}")

    interfaces = result.get("interfaces", [])
    if interfaces:
        text.append("\n  Interfaces:\n", style=f"bold {PURPLE}")
        for iface in interfaces:
            text.append(f"    {iface['interface']:12s} : ", style=PURPLE)
            text.append(f"{iface['ip']}\n", style=CYAN)

    return text
