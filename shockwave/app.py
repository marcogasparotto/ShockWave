"""Shockwave - Main Application."""

import getpass
import socket
from datetime import datetime

from shockwave import ui
from shockwave.modules.resolver import resolve_host
from shockwave.modules.ping_sweep import ping_single, ping_sweep
from shockwave.modules.port_scan import scan_common_ports, scan_custom_ports
from shockwave.modules.dns_records import get_dns_records
from shockwave.modules.traceroute import traceroute
from shockwave.modules.http_headers import get_http_headers
from shockwave.modules.whois_lookup import whois_lookup
from shockwave.modules.geolocate import geolocate_ip
from shockwave.modules.net_info import get_local_network_info


class ShockwaveApp:
    """Main Shockwave application class."""

    def __init__(self, target):
        self.target = target
        self.resolved_ip = None
        self.target_type = self._detect_target_type(target)
        self.username = getpass.getuser()
        self.running = True

    def _detect_target_type(self, target):
        """Detect if target is a domain, IP, or network."""
        try:
            socket.inet_aton(target)
            return "IP"
        except socket.error:
            pass

        if "/" in target:
            return "NETWORK"

        return "DOMAIN"

    def _resolve_target(self):
        """Resolve the target hostname."""
        result = resolve_host(self.target)
        if result["success"]:
            self.resolved_ip = result["ipv4"]
        return result

    def run(self):
        """Run the Shockwave application."""
        self._resolve_target()
        datetime_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        ui.render_splash_screen(
            target=self.target,
            target_type=self.target_type,
            username=self.username,
            resolved_ip=self.resolved_ip,
            datetime_str=datetime_str,
        )

        ui.console.print()

        while self.running:
            try:
                cmd_input = ui.print_prompt().strip()
                if not cmd_input:
                    continue

                parts = cmd_input.split(None, 1)
                cmd = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ""

                self._handle_command(cmd, args)

            except KeyboardInterrupt:
                ui.console.print()
                ui.print_warning("Use 'exit' to quit Shockwave.")
            except Exception as e:
                ui.print_error(f"Unexpected error: {e}")

    def _handle_command(self, cmd, args):
        """Handle a user command."""
        commands = {
            "resolve": self._cmd_resolve,
            "ping": self._cmd_ping,
            "sweep": self._cmd_sweep,
            "scan": self._cmd_scan,
            "cscan": self._cmd_cscan,
            "dns": self._cmd_dns,
            "trace": self._cmd_trace,
            "headers": self._cmd_headers,
            "whois": self._cmd_whois,
            "geo": self._cmd_geo,
            "netinfo": self._cmd_netinfo,
            "target": self._cmd_target,
            "clear": self._cmd_clear,
            "banner": self._cmd_banner,
            "help": self._cmd_help,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
        }

        handler = commands.get(cmd)
        if handler:
            handler(args)
        else:
            ui.print_error(f"Unknown command: '{cmd}'. Type 'help' for available commands.")

    def _get_scan_target(self):
        """Get the IP to scan (resolved or original target)."""
        return self.resolved_ip or self.target

    def _cmd_resolve(self, args):
        """Handle resolve command."""
        target = args.strip() if args.strip() else self.target
        ui.print_info(f"Resolving {target}...")
        result = resolve_host(target)
        content = ui.format_resolve_result(result)
        ui.print_result_panel("RESOLVE HOST", content, "success" if result["success"] else "error")

    def _cmd_ping(self, args):
        """Handle ping command."""
        count = 4
        if args.strip().isdigit():
            count = int(args.strip())

        target = self._get_scan_target()
        ui.print_info(f"Pinging {target} ({count} packets)...")
        result = ping_single(target, count=count)
        content = ui.format_ping_result(result)
        ui.print_result_panel("PING", content, "success" if result["success"] else "error")

    def _cmd_sweep(self, args):
        """Handle sweep command."""
        parts = args.strip().split()
        if not parts:
            ip = self._get_scan_target()
            base = ".".join(ip.split(".")[:3])
            start, end = 1, 254
        else:
            base = parts[0]
            if len(parts) > 1 and "-" in parts[1]:
                range_parts = parts[1].split("-")
                start, end = int(range_parts[0]), int(range_parts[1])
            else:
                start, end = 1, 254

        ui.print_info(f"Sweeping {base}.{start}-{end}...")
        result = ping_sweep(base, start=start, end=end)
        content = ui.format_sweep_result(result)
        ui.print_result_panel("PING SWEEP", content, "success" if result.get("success") else "error")

    def _cmd_scan(self, args):
        """Handle scan command."""
        target = self._get_scan_target()
        ui.print_info(f"Scanning common ports on {target}...")
        result = scan_common_ports(target)
        content = ui.format_port_scan_result(result)
        ui.print_result_panel("PORT SCAN", content, "success" if result.get("success") else "error")

    def _cmd_cscan(self, args):
        """Handle custom port scan command."""
        if not args.strip():
            ui.print_error("Usage: cscan <port_spec>  (e.g., cscan 1-1024 or cscan 22,80,443)")
            return

        target = self._get_scan_target()
        ui.print_info(f"Custom scanning ports {args.strip()} on {target}...")
        result = scan_custom_ports(target, args.strip())
        content = ui.format_port_scan_result(result)
        ui.print_result_panel("CUSTOM PORT SCAN", content, "success" if result.get("success") else "error")

    def _cmd_dns(self, args):
        """Handle DNS records command."""
        target = args.strip() if args.strip() else self.target
        ui.print_info(f"Querying DNS records for {target}...")
        result = get_dns_records(target)
        content = ui.format_dns_result(result)
        ui.print_result_panel("DNS RECORDS", content)

    def _cmd_trace(self, args):
        """Handle traceroute command."""
        target = self._get_scan_target()
        ui.print_info(f"Traceroute to {target}...")
        result = traceroute(target)
        content = ui.format_traceroute_result(result)
        ui.print_result_panel("TRACEROUTE", content, "success" if result["success"] else "error")

    def _cmd_headers(self, args):
        """Handle HTTP headers command."""
        target = self.target
        ui.print_info(f"Fetching HTTP headers from {target}...")
        result = get_http_headers(target)
        content = ui.format_headers_result(result)
        ui.print_result_panel("HTTP HEADERS", content, "success" if result["success"] else "error")

    def _cmd_whois(self, args):
        """Handle WHOIS command."""
        target = args.strip() if args.strip() else self.target
        ui.print_info(f"WHOIS lookup for {target} (port 43)...")
        result = whois_lookup(target)
        content = ui.format_whois_result(result)
        ui.print_result_panel("WHOIS LOOKUP", content, "success" if result["success"] else "error")

    def _cmd_geo(self, args):
        """Handle geolocate command."""
        target = args.strip() if args.strip() else self._get_scan_target()
        ui.print_info(f"Geolocating {target}...")
        result = geolocate_ip(target)
        content = ui.format_geo_result(result)
        ui.print_result_panel("GEOLOCATE IP", content, "success" if result["success"] else "error")

    def _cmd_netinfo(self, args):
        """Handle netinfo command."""
        ui.print_info("Gathering local network information...")
        result = get_local_network_info()
        content = ui.format_netinfo_result(result)
        ui.print_result_panel("LOCAL NETWORK INFO", content)

    def _cmd_target(self, args):
        """Handle target change command."""
        if not args.strip():
            ui.print_error("Usage: target <new_target>")
            return

        new_target = args.strip()
        self.target = new_target
        self.target_type = self._detect_target_type(new_target)
        self.resolved_ip = None

        ui.print_info(f"Target changed to: {new_target}")
        result = self._resolve_target()
        if result["success"]:
            ui.print_success(f"Resolved to: {self.resolved_ip}")
        else:
            ui.print_warning(f"Could not resolve: {result.get('error', 'unknown error')}")

    def _cmd_clear(self, args):
        """Handle clear command."""
        ui.clear_screen()

    def _cmd_banner(self, args):
        """Handle banner command."""
        datetime_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ui.render_splash_screen(
            target=self.target,
            target_type=self.target_type,
            username=self.username,
            resolved_ip=self.resolved_ip,
            datetime_str=datetime_str,
        )

    def _cmd_help(self, args):
        """Handle help command."""
        ui.print_help()

    def _cmd_exit(self, args):
        """Handle exit command."""
        ui.console.print()
        ui.print_info("Shockwave shutting down...")
        ui.print_success("Decepticons, retreat!")
        ui.console.print()
        self.running = False
