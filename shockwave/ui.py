"""Shockwave UI - Console interface with Rich, purple/black theme."""

import os
import shutil
from contextlib import contextmanager

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

from shockwave import __version__
from shockwave.theme import (
    PRIMARY, PRIMARY_DIM, ACCENT, SUCCESS, WARNING, DANGER, TEXT, MUTED,
    BORDER_STYLE, ICONS, gradient_text, gradient_inline,
)
from shockwave.ascii_art import SHOCKWAVE_TITLE

console = Console(highlight=False, color_system="auto")

# Aliases
PURPLE = PRIMARY
DARK_PURPLE = PRIMARY_DIM
GREEN = SUCCESS
CYAN = ACCENT
RED = DANGER
YELLOW = WARNING
WHITE = TEXT
DIM = MUTED

# ---------------------------------------------------------------------------
# CORE
# ---------------------------------------------------------------------------

def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")

def get_terminal_width():
    return shutil.get_terminal_size().columns

@contextmanager
def spinner(message):
    with console.status(
        Text.assemble((f" {ICONS['info']} ", f"bold {ACCENT}"), (message, TEXT)),
        spinner="dots",
        spinner_style=ACCENT,
    ):
        yield

# ---------------------------------------------------------------------------
# SPLASH SCREEN
# ---------------------------------------------------------------------------

def render_splash_screen(target, target_type, username, resolved_ip=None, datetime_str=""):
    clear_screen()
    width = get_terminal_width()
    _render_header(width)
    console.print()
    _render_target_panel(target, target_type, username, resolved_ip, datetime_str, width)
    console.print()
    _render_log_panel(target, resolved_ip, width)
    console.print()
    _render_footer(width)

def _render_header(width):
    title_lines = [l for l in SHOCKWAVE_TITLE.split("\n") if l.strip()]
    art_width = max(len(l) for l in title_lines) if title_lines else 0

    if width < art_width + 6:
        content = Text()
        content.append(gradient_inline("S H O C K W A V E"))
    else:
        content = gradient_text(title_lines)

    panel = Panel(
        Align.center(content),
        border_style=BORDER_STYLE,
        box=box.ROUNDED,
        padding=(1, 2),
    )
    console.print(panel)

def _render_target_panel(target, target_type, username, resolved_ip, datetime_str, width):
    info_table = Table(show_header=False, show_edge=False, box=None, padding=(0, 1), expand=True)
    info_table.add_column("icon", width=3, justify="center")
    info_table.add_column("label", width=16, style=f"bold {PRIMARY}")
    info_table.add_column("sep", width=3, justify="center")
    info_table.add_column("value", ratio=1)

    status_val = (Text(f"Resolvido -> {resolved_ip}", style=f"bold {SUCCESS}")
                  if resolved_ip
                  else Text("Nao foi possivel resolver", style=f"bold {WARNING}"))

    rows = [
        (ICONS["target"], "ALVO", Text(target, style=f"bold {SUCCESS}")),
        (ICONS["status"], "TIPO", Text(target_type.upper(), style=f"bold {ACCENT}")),
        (ICONS["status"], "STATUS", status_val),
        (ICONS["time"], "DATA E HORA", Text(datetime_str, style=TEXT)),
        (ICONS["user"], "USUARIO", Text(username, style=TEXT)),
    ]

    for icon, label, val in rows:
        info_table.add_row(Text(icon, style=ACCENT), label, Text(":", style=MUTED), val)

    console.print(Panel(info_table,
                        title=f" {ICONS['section']} INFORMACOES DO ALVO ",
                        title_align="left",
                        border_style=BORDER_STYLE,
                        box=box.ROUNDED,
                        padding=(1, 2)))

def _render_log_panel(target, resolved_ip, width):
    log_text = Text()
    log_text.append(f" {ICONS['info']} Inicializando Shockwave...\n", style=TEXT)
    if resolved_ip:
        log_text.append(f" {ICONS['success']} Host resolvido: {resolved_ip}\n", style=SUCCESS)
    else:
        log_text.append(f" {ICONS['warning']} Falha na resolucao\n", style=DANGER)
    console.print(Panel(log_text,
                        title=f" {ICONS['section']} LOG DE INICIALIZACAO ",
                        title_align="left",
                        border_style=BORDER_STYLE,
                        box=box.ROUNDED,
                        padding=(1, 2)))

def _render_footer(width):
    footer_text = Text(justify="center")
    footer_text.append(f"SHOCKWAVE v{__version__}", style=f"bold {PRIMARY}")
    footer_text.append(" | ", style=MUTED)
    footer_text.append("FERRAMENTA DE DIAGNOSTICO DE REDE", style=f"bold {MUTED}")
    console.print(Panel(Align.center(footer_text),
                        border_style=PRIMARY_DIM,
                        box=box.HORIZONTALS,
                        padding=0))

# ---------------------------------------------------------------------------
# PROMPT & MESSAGES
# ---------------------------------------------------------------------------

def print_prompt():
    try:
        arrow = "\033[38;5;92m\u276f\033[38;5;128m\u276f\033[38;5;165m\u276f\033[0m"
        return input(f" {arrow} \033[1m")
    except (EOFError, KeyboardInterrupt):
        return "exit"

def print_result_panel(title, content, style="info"):
    border_map = {"success": SUCCESS, "error": DANGER, "warning": WARNING}
    icon_map = {"success": ICONS["success"], "error": ICONS["error"], "warning": ICONS["warning"]}
    console.print(Panel(content,
                        title=f" {icon_map.get(style, ICONS['section'])} {title} ",
                        title_align="left",
                        border_style=border_map.get(style, BORDER_STYLE),
                        box=box.ROUNDED,
                        padding=(1, 2)))

def print_info(message):
    console.print(Text.assemble((f" {ICONS['info']} ", f"bold {ACCENT}"), (message, TEXT)))

def print_success(message):
    console.print(Text.assemble((f" {ICONS['success']} ", f"bold {SUCCESS}"), (message, f"bold {SUCCESS}")))

def print_error(message):
    console.print(Text.assemble((f" {ICONS['error']} ", f"bold {DANGER}"), (message, f"bold {DANGER}")))

def print_warning(message):
    console.print(Text.assemble((f" {ICONS['warning']} ", f"bold {WARNING}"), (message, WARNING)))

def format_text(s):
    return Text(s, style=TEXT)

# ---------------------------------------------------------------------------
# HELP
# ---------------------------------------------------------------------------

def print_help():
    groups = [
        ("DESCOBERTA DE REDE", [
            ("resolve", "Resolve hostname para IPv4", "resolve [alvo]"),
            ("rdns", "Reverse DNS", "rdns [ip]"),
            ("ping", "Ping no alvo", "ping [qtd]"),
            ("sweep", "Varredura de ping", "sweep [base] [inicio-fim]"),
            ("arp", "ARP Scan na rede local", "arp [interface]"),
            ("tcpdiscovery", "TCP Host Discovery", "tcpdiscovery [ip]"),
            ("udpdiscovery", "UDP Host Discovery", "udpdiscovery [ip]"),
            ("cidr", "CIDR Scanner", "cidr [rede/prefixo]"),
            ("gateway", "Detecta gateway padrao", "gateway"),
            ("interfaces", "Lista interfaces de rede", "interfaces"),
            ("mac", "Descobre MAC de um IP", "mac [ip]"),
            ("vendor", "Identifica fabricante (OUI)", "vendor <mac>"),
        ]),
        ("ENUMERACAO", [
            ("dns", "Registros DNS", "dns [alvo]"),
            ("whois", "Consulta WHOIS", "whois [alvo]"),
            ("asn", "ASN Lookup", "asn [alvo]"),
            ("geo", "Geolocaliza IP", "geo [ip]"),
            ("subdomains", "Enumera subdominos", "subdomains [dominio]"),
            ("dnssec", "Detecta DNSSEC", "dnssec [dominio]"),
            ("zonetransfer", "Zone Transfer Check", "zonetransfer [dominio]"),
            ("cdn", "Detecta CDN", "cdn [dominio]"),
        ]),
        ("PORT SCANNING", [
            ("scan", "Portas comuns", "scan"),
            ("fullscan", "Scan completo (1-65535)", "fullscan"),
            ("cscan", "Scan customizado", "cscan <portas>"),
            ("tcpscan", "TCP Connect Scan", "tcpscan"),
            ("udpscan", "UDP Scan", "udpscan"),
            ("synscan", "SYN Scan", "synscan [portas]"),
            ("ackscan", "ACK Scan", "ackscan [portas]"),
            ("finscan", "FIN Scan", "finscan [portas]"),
            ("nullscan", "NULL Scan", "nullscan [portas]"),
            ("xmasscan", "XMAS Scan", "xmasscan [portas]"),
            ("winscan", "Window Scan", "winscan [portas]"),
            ("idlescan", "Idle Scan", "idlescan <zombie> [portas]"),
            ("fragscan", "Fragment Scan", "fragscan [portas]"),
            ("adaptive", "Adaptive Timing Scan", "adaptive [timing 0-5]"),
        ]),
        ("IDENTIFICACAO DE SERVICOS", [
            ("banner", "Banner Grabbing", "banner <porta>"),
            ("svcdetect", "Service Detection", "svcdetect"),
            ("version", "Version Detection", "version <porta>"),
            ("httpdetect", "HTTP Detection", "httpdetect [porta]"),
            ("sshdetect", "SSH Detection", "sshdetect [porta]"),
            ("ftpdetect", "FTP Detection", "ftpdetect [porta]"),
            ("smtpdetect", "SMTP Detection", "smtpdetect [porta]"),
            ("smbdetect", "SMB Detection", "smbdetect"),
            ("snmpdetect", "SNMP Detection", "snmpdetect"),
            ("dbdetect", "Database Detection", "dbdetect"),
            ("mqttdetect", "MQTT Detection", "mqttdetect [porta]"),
            ("redisdetect", "Redis Detection", "redisdetect [porta]"),
        ]),
        ("FINGERPRINTING", [
            ("osdetect", "OS Detection", "osdetect"),
            ("devicetype", "Device Type Detection", "devicetype"),
            ("tcpstack", "TCP/IP Stack Analysis", "tcpstack"),
            ("ttl", "TTL Analysis", "ttl"),
            ("mss", "MSS Analysis", "mss"),
            ("winsize", "Window Size Analysis", "winsize"),
        ]),
        ("SSL / TLS", [
            ("cert", "Certificate Viewer", "cert"),
            ("certval", "Certificate Validation", "certval"),
            ("ciphers", "Cipher Enumeration", "ciphers"),
            ("tlsver", "TLS Version Detection", "tlsver"),
            ("hsts", "HSTS Detection", "hsts"),
            ("alpn", "ALPN Detection", "alpn"),
            ("weakciphers", "Weak Cipher Detection", "weakciphers"),
            ("certexpiry", "Certificate Expiration", "certexpiry"),
        ]),
        ("HTTP ANALYSIS", [
            ("headers", "HTTP Headers", "headers"),
            ("secheaders", "Security Headers", "secheaders"),
            ("cookies", "Cookie Analysis", "cookies"),
            ("redirects", "Redirect Detection", "redirects"),
            ("compression", "Compression Detection", "compression"),
            ("httpmethods", "HTTP Methods", "httpmethods"),
            ("http2", "HTTP/2 Detection", "http2"),
            ("http3", "HTTP/3 Detection", "http3"),
            ("robots", "robots.txt", "robots"),
            ("sitemap", "sitemap.xml", "sitemap"),
            ("webtech", "Web Technology Detection", "webtech"),
        ]),
        ("PACKET ANALYSIS", [
            ("capture", "Live Packet Capture", "capture [qtd]"),
            ("pcap", "PCAP Reader", "pcap <arquivo>"),
            ("protostats", "Protocol Statistics", "protostats"),
            ("tcpstream", "TCP Stream Analysis", "tcpstream [porta]"),
            ("dnsanalysis", "DNS Packet Analysis", "dnsanalysis"),
            ("httpanalysis", "HTTP Packet Analysis", "httpanalysis [alvo]"),
            ("tlshandshake", "TLS Handshake Analysis", "tlshandshake"),
            ("icmp", "ICMP Analysis", "icmp"),
            ("bandwidth", "Bandwidth Statistics", "bandwidth"),
        ]),
        ("PERFORMANCE", [
            ("latency", "Teste de latencia", "latency"),
            ("packetloss", "Teste de packet loss", "packetloss"),
            ("jitter", "Teste de jitter", "jitter"),
            ("mtudisc", "MTU Discovery", "mtudisc"),
            ("pathmtu", "Path MTU Discovery", "pathmtu"),
            ("throughput", "Estimativa de throughput", "throughput"),
        ]),
        ("RELATORIOS", [
            ("exportjson", "Exportar para JSON", "exportjson [arquivo]"),
            ("exporthtml", "Relatorio HTML", "exporthtml [arquivo]"),
            ("exportcsv", "Exportar para CSV", "exportcsv [arquivo]"),
            ("exportxml", "Exportar para XML", "exportxml [arquivo]"),
            ("exportpdf", "Relatorio PDF", "exportpdf [arquivo]"),
            ("compare", "Comparar scans", "compare"),
        ]),
        ("SISTEMA", [
            ("trace", "Traceroute", "trace"),
            ("netinfo", "Info da rede local", "netinfo"),
            ("target", "Altera o alvo", "target <novo_alvo>"),
            ("clear", "Limpa a tela", "clear"),
            ("splash", "Tela inicial", "splash"),
            ("help", "Mostra esta ajuda", "help"),
            ("exit", "Sai do Shockwave", "exit"),
        ]),
    ]

    help_table = Table(
        title=Text(f" {ICONS['section']} COMANDOS DISPONIVEIS ", style=f"bold {PRIMARY}"),
        show_header=True,
        header_style=f"bold {PRIMARY}",
        border_style=BORDER_STYLE,
        box=box.ROUNDED,
        padding=(0, 2),
        expand=True,
    )
    help_table.add_column("Comando", style=f"bold {ACCENT}", width=20)
    help_table.add_column("Descricao", style=TEXT)
    help_table.add_column("Uso", style=MUTED)

    for group_name, commands in groups:
        help_table.add_row(Text(group_name, style=f"bold {SUCCESS}"), "", "")
        for cmd, desc, usage in commands:
            help_table.add_row(f"  {cmd}", desc, usage)

    console.print()
    console.print(help_table)
    console.print()

# ---------------------------------------------------------------------------
# FORMAT FUNCTIONS
# ---------------------------------------------------------------------------

def format_resolve_result(result):
    text = Text()
    if result["success"]:
        text.append("Host resolvido com sucesso\n\n", style=f"bold {SUCCESS}")
        text.append("  Hostname : ", style=f"bold {PRIMARY}")
        text.append(f"{result['hostname']}\n", style=TEXT)
        text.append("  IPv4     : ", style=f"bold {PRIMARY}")
        text.append(f"{result['ipv4']}\n", style=f"bold {ACCENT}")
    else:
        text.append(f"Falha na resolucao: {result['error']}", style=f"bold {DANGER}")
    return text

def format_ping_result(result):
    text = Text()
    if result["success"]:
        text.append(f"Resultado do ping para {result['target']}:\n\n", style=f"bold {SUCCESS}")
        text.append(result["output"], style=TEXT)
    else:
        text.append(f"Falha no ping: {result.get('error', 'Erro desconhecido')}", style=f"bold {DANGER}")
    return text

def format_sweep_result(result):
    text = Text()
    if result.get("success"):
        alive_count = len(result["alive"])
        text.append(f"Varredura concluida: {alive_count}/{result['total']} hosts ativos\n\n", style=f"bold {SUCCESS}")
        for ip in result["alive"]:
            text.append(f"  {ICONS['success']} {ip}\n", style=f"bold {SUCCESS}")
    else:
        text.append(f"Falha na varredura: {result.get('error', 'Erro desconhecido')}", style=f"bold {DANGER}")
    return text

def format_port_scan_result(result):
    if not result.get("success"):
        return Text(f"Falha: {result.get('error')}", style=f"bold {DANGER}")

    scan_table = Table(title=f"Portas abertas em {result['target']}", box=box.SIMPLE,
                       border_style=PRIMARY_DIM)
    scan_table.add_column("Porta", style=ACCENT)
    scan_table.add_column("Servico")
    for p in result["open"]:
        scan_table.add_row(str(p["port"]), p["service"])

    if not result["open"]:
        return Text("Nenhuma porta aberta encontrada.", style=f"bold {WARNING}")
    return scan_table

def format_udp_scan_result(result):
    if not result.get("success"):
        return Text(f"Falha: {result.get('error')}", style=f"bold {DANGER}")

    text = Text()
    text.append(f"UDP Scan em {result['target']}\n\n", style=f"bold {SUCCESS}")

    if result.get("open"):
        text.append("Portas abertas:\n", style=f"bold {PRIMARY}")
        for p in result["open"]:
            text.append(f"  {p['port']} - {p['service']}\n", style=f"bold {SUCCESS}")

    if result.get("filtered"):
        text.append("\nPortas open|filtered:\n", style=f"bold {WARNING}")
        for p in result["filtered"]:
            text.append(f"  {p['port']} - {p['service']}\n", style=WARNING)

    return text

def format_nmap_scan_result(result):
    if not result.get("success"):
        return Text(f"Falha: {result.get('error', 'Erro desconhecido')}", style=f"bold {DANGER}")

    text = Text()
    scan_type = result.get("scan_type", "Scan")
    text.append(f"{scan_type} em {result.get('target', 'N/A')}\n\n", style=f"bold {SUCCESS}")

    if result.get("note"):
        text.append(f"Nota: {result['note']}\n\n", style=f"bold {WARNING}")

    if result.get("open"):
        text.append("Portas abertas:\n", style=f"bold {PRIMARY}")
        for p in result["open"]:
            port = p.get("port", p.get("port", "?"))
            service = p.get("service", "Unknown")
            text.append(f"  {ICONS['success']} {port} - {service}\n", style=f"bold {SUCCESS}")

    if result.get("filtered"):
        text.append("\nPortas filtradas:\n", style=f"bold {WARNING}")
        for p in result["filtered"]:
            text.append(f"  {ICONS['warning']} {p.get('port', '?')} - {p.get('service', 'Unknown')}\n", style=WARNING)

    if not result.get("open") and not result.get("filtered"):
        text.append("Nenhuma porta aberta/filtrada encontrada.\n", style=f"bold {MUTED}")

    return text

def format_dns_result(result):
    text = Text(f"Registros DNS para {result['target']}:\n\n", style=f"bold {SUCCESS}")
    for rtype in ["A", "CNAME", "MX", "NS", "PTR"]:
        records = result.get(rtype, [])
        text.append(f"  {rtype}: {', '.join(records) if records else 'Nenhum'}\n", style=TEXT)
    return text

def format_traceroute_result(result):
    if not result["success"]:
        return Text(result["error"], style=DANGER)
    text = Text(f"Traceroute para {result['target']}\n\n", style=f"bold {SUCCESS}")
    for hop in result["hops"]:
        rtt = hop.get("rtt", ["*"])
        rtt_str = rtt if isinstance(rtt, str) else ", ".join(str(r) for r in rtt)
        text.append(f" {hop['hop']:>3}  {hop['ip']}  ({rtt_str} ms)\n", style=TEXT)
    return text

def format_headers_result(result):
    if not result["success"]:
        return Text(result.get("error", "Erro"), style=DANGER)
    text = Text(f"Cabecalhos HTTP ({result['status']}):\n", style=f"bold {SUCCESS}")
    for k, v in result["headers"].items():
        text.append(f"  {k}: {v}\n", style=TEXT)
    return text

def format_whois_result(result):
    text = Text("Dados WHOIS:\n", style=f"bold {SUCCESS}")
    for k, v in result.get("parsed", {}).items():
        text.append(f"  {k}: {v}\n", style=TEXT)
    return text

def format_geo_result(result):
    text = Text("Geolocalizacao:\n", style=f"bold {SUCCESS}")
    for k, v in result.items():
        if k not in ["success"]:
            text.append(f"  {k}: {v}\n", style=TEXT)
    return text

def format_netinfo_result(result):
    text = Text("Rede Local:\n", style=f"bold {SUCCESS}")
    text.append(f"  IP: {result.get('local_ip')}\n  Publico: {result.get('public_ip')}\n", style=TEXT)
    text.append(f"  Hostname: {result.get('hostname', 'N/A')}\n", style=TEXT)
    if result.get("interfaces"):
        text.append("\n  Interfaces:\n", style=f"bold {PRIMARY}")
        for iface in result["interfaces"]:
            text.append(f"    {iface.get('interface', 'N/A')}: {iface.get('ip', 'N/A')}\n", style=TEXT)
    return text

# ---------------------------------------------------------------------------
# NEW FORMATTERS
# ---------------------------------------------------------------------------

def format_arp_result(result):
    if not result["success"]:
        return Text(f"Falha: {result.get('error', 'Erro')}", style=f"bold {DANGER}")

    if not result.get("hosts"):
        return Text("Nenhum host encontrado na tabela ARP.", style=f"bold {WARNING}")

    table = Table(box=box.SIMPLE, border_style=PRIMARY_DIM)
    table.add_column("IP", style=ACCENT)
    table.add_column("MAC", style=TEXT)
    table.add_column("Hostname", style=MUTED)
    table.add_column("Vendor", style=PRIMARY)

    for host in result["hosts"]:
        table.add_row(host["ip"], host["mac"], host.get("hostname", ""), host.get("vendor", "Unknown"))

    return table

def format_cidr_result(result):
    if not result.get("success"):
        return Text(f"Falha: {result.get('error', 'Erro')}", style=f"bold {DANGER}")

    text = Text()
    alive = result.get("alive", [])
    total = result.get("total", 0)
    text.append(f"CIDR: {result.get('cidr', 'N/A')}\n", style=f"bold {PRIMARY}")
    text.append(f"Hosts ativos: {len(alive)}/{total}\n\n", style=f"bold {SUCCESS}")
    for ip in alive:
        text.append(f"  {ICONS['success']} {ip}\n", style=f"bold {SUCCESS}")
    return text

def format_interfaces_result(result):
    if not result["success"]:
        return Text(f"Falha: {result.get('error', 'Erro')}", style=f"bold {DANGER}")

    table = Table(box=box.SIMPLE, border_style=PRIMARY_DIM)
    table.add_column("Interface", style=ACCENT)
    table.add_column("Endereco", style=TEXT)

    for iface in result.get("interfaces", []):
        table.add_row(iface["interface"], iface["address"])

    return table

def format_subdomain_result(result):
    if not result["success"]:
        return Text(f"Falha: {result.get('error', 'Erro')}", style=f"bold {DANGER}")

    text = Text()
    text.append(f"Dominio: {result['domain']}\n", style=f"bold {PRIMARY}")
    text.append(f"Verificados: {result.get('total_checked', 0)} | Encontrados: {result.get('found', 0)}\n\n",
                style=f"bold {SUCCESS}")

    for sub in result.get("subdomains", []):
        ips = ", ".join(sub.get("ips", []))
        text.append(f"  {ICONS['success']} {sub['subdomain']}", style=f"bold {ACCENT}")
        text.append(f"  ->  {ips}\n", style=TEXT)

    if not result.get("subdomains"):
        text.append("  Nenhum subdominio encontrado.\n", style=f"bold {MUTED}")

    return text

def format_service_result(result):
    if not result["success"]:
        return Text(f"Falha: {result.get('error', 'Erro')}", style=f"bold {DANGER}")

    items = result.get("services", result.get("databases", []))
    if not items:
        return Text("Nenhum servico detectado.", style=f"bold {WARNING}")

    table = Table(box=box.SIMPLE, border_style=PRIMARY_DIM)
    table.add_column("Porta", style=ACCENT)
    table.add_column("Servico", style=TEXT)
    table.add_column("Versao/Banner", style=MUTED)

    for svc in items:
        port = str(svc.get("port", "?"))
        name = svc.get("service", "Unknown")
        version = svc.get("version", svc.get("banner", ""))
        table.add_row(port, name, version[:60])

    return table

def format_cert_result(result):
    if not result["success"]:
        return Text(f"Falha: {result.get('error', 'Erro')}", style=f"bold {DANGER}")

    text = Text()
    text.append("Certificado SSL/TLS\n\n", style=f"bold {SUCCESS}")
    text.append(f"  Common Name  : ", style=f"bold {PRIMARY}")
    text.append(f"{result.get('common_name', 'N/A')}\n", style=TEXT)
    text.append(f"  Emissor      : ", style=f"bold {PRIMARY}")
    text.append(f"{result.get('issuer_cn', 'N/A')} ({result.get('issuer_org', '')})\n", style=TEXT)
    text.append(f"  Serial       : ", style=f"bold {PRIMARY}")
    text.append(f"{result.get('serial_number', 'N/A')}\n", style=TEXT)
    text.append(f"  Valido desde : ", style=f"bold {PRIMARY}")
    text.append(f"{result.get('not_before', 'N/A')}\n", style=TEXT)
    text.append(f"  Valido ate   : ", style=f"bold {PRIMARY}")
    text.append(f"{result.get('not_after', 'N/A')}\n", style=TEXT)

    san = result.get("san", [])
    if san:
        text.append(f"\n  SANs ({len(san)}):\n", style=f"bold {PRIMARY}")
        for s in san[:10]:
            text.append(f"    {s}\n", style=TEXT)

    return text

def format_tls_version_result(result):
    if not result["success"]:
        return Text(f"Falha: {result.get('error', 'Erro')}", style=f"bold {DANGER}")

    text = Text()
    text.append(f"Versoes TLS para {result['target']}\n\n", style=f"bold {SUCCESS}")

    for version, status in result.get("versions", {}).items():
        icon = ICONS["success"] if "Supported" in status else ICONS["error"]
        style = SUCCESS if "Supported" in status else MUTED
        text.append(f"  {icon} {version}: {status}\n", style=style)

    return text

def format_cert_expiry_result(result):
    if not result["success"]:
        return Text(f"Falha: {result.get('error', 'Erro')}", style=f"bold {DANGER}")

    text = Text()
    status = result.get("status", "UNKNOWN")

    status_colors = {
        "OK": SUCCESS, "ATTENTION": WARNING, "WARNING": WARNING,
        "CRITICAL": DANGER, "EXPIRED": DANGER,
    }
    color = status_colors.get(status, TEXT)

    text.append(f"Status: {status}\n\n", style=f"bold {color}")
    text.append(f"  CN           : {result.get('common_name', 'N/A')}\n", style=TEXT)
    text.append(f"  Expira em    : {result.get('expiry_date', 'N/A')}\n", style=TEXT)

    days = result.get("days_remaining")
    if days is not None:
        text.append(f"  Dias restantes: {days}\n", style=f"bold {color}")

    return text

def format_sec_headers_result(result):
    if not result["success"]:
        return Text(f"Falha: {result.get('error', 'Erro')}", style=f"bold {DANGER}")

    text = Text()
    score = result.get("score", 0)
    score_style = SUCCESS if score >= 70 else (WARNING if score >= 40 else DANGER)
    text.append(f"Score: {score}%\n\n", style=f"bold {score_style}")

    if result.get("present"):
        text.append("Headers presentes:\n", style=f"bold {SUCCESS}")
        for h in result["present"]:
            text.append(f"  {ICONS['success']} {h['header']}: {h['value'][:60]}\n", style=SUCCESS)

    if result.get("missing"):
        text.append("\nHeaders ausentes:\n", style=f"bold {DANGER}")
        for h in result["missing"]:
            sev_style = DANGER if h["severity"] == "high" else (WARNING if h["severity"] == "medium" else MUTED)
            text.append(f"  {ICONS['error']} {h['header']} [{h['severity']}]\n", style=sev_style)

    return text

def format_redirect_result(result):
    if not result["success"]:
        return Text(f"Falha: {result.get('error', 'Erro')}", style=f"bold {DANGER}")

    text = Text()
    text.append(f"Redirects: {result.get('total_redirects', 0)}\n\n", style=f"bold {SUCCESS}")

    for redir in result.get("redirects", []):
        text.append(f"  [{redir.get('status', '?')}] {redir.get('url', 'N/A')}\n", style=TEXT)
        text.append(f"       -> {redir.get('location', 'N/A')}\n", style=f"bold {ACCENT}")

    final = result.get("final_url")
    if final:
        text.append(f"\n  URL final: {final} [{result.get('final_status', '?')}]\n", style=f"bold {SUCCESS}")

    return text

def format_robots_result(result):
    if not result["success"]:
        return Text(f"Falha: {result.get('error', 'Erro')}", style=f"bold {DANGER}")

    text = Text()
    if result.get("exists"):
        text.append("robots.txt encontrado\n\n", style=f"bold {SUCCESS}")

        disallowed = result.get("disallowed_paths", [])
        if disallowed:
            text.append("Paths bloqueados:\n", style=f"bold {PRIMARY}")
            for path in disallowed[:20]:
                text.append(f"  {ICONS['error']} {path}\n", style=WARNING)

        sitemaps = result.get("sitemaps", [])
        if sitemaps:
            text.append("\nSitemaps referenciados:\n", style=f"bold {PRIMARY}")
            for sm in sitemaps:
                text.append(f"  {ICONS['success']} {sm}\n", style=TEXT)
    else:
        text.append("robots.txt nao encontrado.", style=f"bold {WARNING}")

    return text

def format_webtech_result(result):
    if not result["success"]:
        return Text(f"Falha: {result.get('error', 'Erro')}", style=f"bold {DANGER}")

    text = Text()
    text.append("Tecnologias detectadas:\n\n", style=f"bold {SUCCESS}")

    for tech in result.get("technologies", []):
        text.append(f"  {ICONS['success']} {tech}\n", style=f"bold {ACCENT}")

    if result.get("server"):
        text.append(f"\n  Server: {result['server']}\n", style=TEXT)
    if result.get("powered_by"):
        text.append(f"  X-Powered-By: {result['powered_by']}\n", style=TEXT)

    if not result.get("technologies"):
        text.append("  Nenhuma tecnologia identificada.\n", style=f"bold {MUTED}")

    return text

def format_capture_result(result):
    if not result["success"]:
        return Text(f"Falha: {result.get('error', 'Erro')}", style=f"bold {DANGER}")

    text = Text()
    total = result.get("total", result.get("total_packets", 0))
    text.append(f"Pacotes capturados: {total}\n\n", style=f"bold {SUCCESS}")

    for pkt in result.get("packets", [])[:30]:
        text.append(f"  {pkt}\n", style=TEXT)

    if total > 30:
        text.append(f"\n  ... e mais {total - 30} pacotes\n", style=MUTED)

    return text

def format_performance_result(result, title="Performance"):
    if not result["success"]:
        return Text(f"Falha: {result.get('error', 'Erro')}", style=f"bold {DANGER}")

    text = Text()
    text.append(f"{title}\n\n", style=f"bold {SUCCESS}")

    skip_keys = {"success", "target", "individual_rtts", "rtts", "port"}
    for k, v in result.items():
        if k in skip_keys:
            continue
        text.append(f"  {k}: ", style=f"bold {PRIMARY}")
        text.append(f"{v}\n", style=TEXT)

    return text

def format_export_result(result):
    if not result["success"]:
        return Text(f"Falha: {result.get('error', 'Erro')}", style=f"bold {DANGER}")

    text = Text()
    text.append("Exportacao concluida!\n\n", style=f"bold {SUCCESS}")
    text.append(f"  Arquivo: {result.get('filepath', 'N/A')}\n", style=TEXT)

    size = result.get("size_bytes", 0)
    if size:
        if size > 1024 * 1024:
            text.append(f"  Tamanho: {size / 1024 / 1024:.2f} MB\n", style=TEXT)
        elif size > 1024:
            text.append(f"  Tamanho: {size / 1024:.1f} KB\n", style=TEXT)
        else:
            text.append(f"  Tamanho: {size} bytes\n", style=TEXT)

    if result.get("note"):
        text.append(f"\n  Nota: {result['note']}\n", style=WARNING)

    return text

def format_generic_result(result, title="Result"):
    """Generic formatter for any dict result."""
    if not result.get("success"):
        return Text(f"Falha: {result.get('error', 'Erro desconhecido')}", style=f"bold {DANGER}")

    text = Text()
    text.append(f"{title}\n\n", style=f"bold {SUCCESS}")

    skip_keys = {"success", "raw", "raw_output", "content", "packets", "records"}

    for key, value in result.items():
        if key in skip_keys:
            continue

        if isinstance(value, dict):
            text.append(f"  {key}:\n", style=f"bold {PRIMARY}")
            for k2, v2 in value.items():
                text.append(f"    {k2}: {v2}\n", style=TEXT)
        elif isinstance(value, list):
            text.append(f"  {key}: ({len(value)} items)\n", style=f"bold {PRIMARY}")
            for item in value[:10]:
                if isinstance(item, dict):
                    parts = [f"{k}={v}" for k, v in item.items()]
                    text.append(f"    {', '.join(parts)}\n", style=TEXT)
                else:
                    text.append(f"    {item}\n", style=TEXT)
            if len(value) > 10:
                text.append(f"    ... +{len(value) - 10} mais\n", style=MUTED)
        elif isinstance(value, bool):
            icon = ICONS["success"] if value else ICONS["error"]
            style = SUCCESS if value else WARNING
            text.append(f"  {key}: {icon} {value}\n", style=style)
        else:
            text.append(f"  {key}: ", style=f"bold {PRIMARY}")
            text.append(f"{value}\n", style=TEXT)

    return text
