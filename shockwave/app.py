"""Shockwave - Aplicação principal."""

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
    """Classe principal da aplicação Shockwave."""

    def __init__(self, target):
        self.target = target
        self.resolved_ip = None
        self.target_type = self._detect_target_type(target)
        self.username = getpass.getuser()
        self.running = True

    def _detect_target_type(self, target):
        """Detecta se o alvo é um domínio, IP ou rede."""
        try:
            socket.inet_aton(target)
            return "IP"
        except socket.error:
            pass

        if "/" in target:
            return "REDE"

        return "DOMÍNIO"

    def _resolve_target(self):
        """Resolve o hostname do alvo."""
        result = resolve_host(self.target)
        if result["success"]:
            self.resolved_ip = result["ipv4"]
        return result

    def run(self):
        """Executa a aplicação Shockwave."""
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
                ui.print_warning("Use 'exit' para sair do Shockwave.")
            except Exception as e:
                ui.print_error(f"Erro inesperado: {e}")

    def _handle_command(self, cmd, args):
        """Trata um comando do usuário."""
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
            ui.print_error(f"Comando desconhecido: '{cmd}'. Digite 'help' para ver os comandos disponíveis.")

    def _get_scan_target(self):
        """Retorna o IP a ser usado nas operações (resolvido ou o alvo original)."""
        return self.resolved_ip or self.target

    def _cmd_resolve(self, args):
        """Trata o comando resolve."""
        target = args.strip() if args.strip() else self.target
        with ui.spinner(f"Resolvendo {target}..."):
            result = resolve_host(target)
        content = ui.format_resolve_result(result)
        ui.print_result_panel("RESOLVER HOST", content, "success" if result["success"] else "error")

    def _cmd_ping(self, args):
        """Trata o comando ping."""
        count = 4
        if args.strip().isdigit():
            count = int(args.strip())

        target = self._get_scan_target()
        with ui.spinner(f"Enviando ping para {target} ({count} pacotes)..."):
            result = ping_single(target, count=count)
        content = ui.format_ping_result(result)
        ui.print_result_panel("PING", content, "success" if result["success"] else "error")

    def _cmd_sweep(self, args):
        """Trata o comando sweep."""
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

        with ui.spinner(f"Varrendo {base}.{start}-{end}..."):
            result = ping_sweep(base, start=start, end=end)
        content = ui.format_sweep_result(result)
        ui.print_result_panel("VARREDURA DE PING", content, "success" if result.get("success") else "error")

    def _cmd_scan(self, args):
        """Trata o comando scan."""
        target = self._get_scan_target()
        with ui.spinner(f"Escaneando portas comuns em {target}..."):
            result = scan_common_ports(target)
        content = ui.format_port_scan_result(result)
        ui.print_result_panel("ESCANEAMENTO DE PORTAS", content, "success" if result.get("success") else "error")

    def _cmd_cscan(self, args):
        """Trata o comando de escaneamento customizado."""
        if not args.strip():
            ui.print_error("Uso: cscan <especificação_de_portas>  (ex: cscan 1-1024 ou cscan 22,80,443)")
            return

        target = self._get_scan_target()
        with ui.spinner(f"Escaneamento customizado das portas {args.strip()} em {target}..."):
            result = scan_custom_ports(target, args.strip())
        content = ui.format_port_scan_result(result)
        ui.print_result_panel("ESCANEAMENTO CUSTOMIZADO", content, "success" if result.get("success") else "error")

    def _cmd_dns(self, args):
        """Trata o comando de registros DNS."""
        target = args.strip() if args.strip() else self.target
        with ui.spinner(f"Consultando registros DNS de {target}..."):
            result = get_dns_records(target)
        content = ui.format_dns_result(result)
        ui.print_result_panel("REGISTROS DNS", content)

    def _cmd_trace(self, args):
        """Trata o comando traceroute."""
        target = self._get_scan_target()
        with ui.spinner(f"Executando traceroute até {target}..."):
            result = traceroute(target)
        content = ui.format_traceroute_result(result)
        ui.print_result_panel("TRACEROUTE", content, "success" if result["success"] else "error")

    def _cmd_headers(self, args):
        """Trata o comando de cabeçalhos HTTP."""
        target = self.target
        with ui.spinner(f"Buscando cabeçalhos HTTP de {target}..."):
            result = get_http_headers(target)
        content = ui.format_headers_result(result)
        ui.print_result_panel("CABEÇALHOS HTTP", content, "success" if result["success"] else "error")

    def _cmd_whois(self, args):
        """Trata o comando WHOIS."""
        target = args.strip() if args.strip() else self.target
        with ui.spinner(f"Consultando WHOIS de {target} (porta 43)..."):
            result = whois_lookup(target)
        content = ui.format_whois_result(result)
        ui.print_result_panel("CONSULTA WHOIS", content, "success" if result["success"] else "error")

    def _cmd_geo(self, args):
        """Trata o comando de geolocalização."""
        target = args.strip() if args.strip() else self._get_scan_target()
        with ui.spinner(f"Geolocalizando {target}..."):
            result = geolocate_ip(target)
        content = ui.format_geo_result(result)
        ui.print_result_panel("GEOLOCALIZAÇÃO", content, "success" if result["success"] else "error")

    def _cmd_netinfo(self, args):
        """Trata o comando netinfo."""
        with ui.spinner("Coletando informações da rede local..."):
            result = get_local_network_info()
        content = ui.format_netinfo_result(result)
        ui.print_result_panel("INFORMAÇÕES DE REDE LOCAL", content)

    def _cmd_target(self, args):
        """Trata a troca de alvo."""
        if not args.strip():
            ui.print_error("Uso: target <novo_alvo>")
            return

        new_target = args.strip()
        self.target = new_target
        self.target_type = self._detect_target_type(new_target)
        self.resolved_ip = None

        ui.print_info(f"Alvo alterado para: {new_target}")
        with ui.spinner(f"Resolvendo {new_target}..."):
            result = self._resolve_target()
        if result["success"]:
            ui.print_success(f"Resolvido para: {self.resolved_ip}")
        else:
            ui.print_warning(f"Não foi possível resolver: {result.get('error', 'erro desconhecido')}")

    def _cmd_clear(self, args):
        """Trata o comando clear."""
        ui.clear_screen()

    def _cmd_banner(self, args):
        """Trata o comando banner."""
        datetime_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ui.render_splash_screen(
            target=self.target,
            target_type=self.target_type,
            username=self.username,
            resolved_ip=self.resolved_ip,
            datetime_str=datetime_str,
        )

    def _cmd_help(self, args):
        """Trata o comando help."""
        ui.print_help()

    def _cmd_exit(self, args):
        """Trata o comando exit."""
        ui.console.print()
        ui.print_info("Encerrando o Shockwave...")
        ui.print_success("Sessão encerrada. Até a próxima!")
        ui.console.print()
        self.running = False