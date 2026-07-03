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

# --- Módulos simulados/esperados (ajuste conforme seu projeto) ---
from shockwave import __version__
from shockwave.theme import (
    PRIMARY, PRIMARY_DIM, ACCENT, SUCCESS, WARNING, DANGER, TEXT, MUTED,
    BORDER_STYLE, ICONS, gradient_text, gradient_inline,
)
from shockwave.ascii_art import SHOCKWAVE_TITLE

# Inicialização do console
console = Console(highlight=False, color_system="auto")

# Aliases de compatibilidade
PURPLE = PRIMARY
DARK_PURPLE = PRIMARY_DIM
GREEN = SUCCESS
CYAN = ACCENT
RED = DANGER
YELLOW = WARNING
WHITE = TEXT
DIM = MUTED

# ---------------------------------------------------------------------------
# CORE & UTILITÁRIOS
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

def display_result(title, result_type, result_data):
    """Integra formatadores e exibe no console."""
    formatters = {
        "resolve": format_resolve_result,
        "ping": format_ping_result,
        "sweep": format_sweep_result,
        "scan": format_port_scan_result,
        "dns": format_dns_result,
        "trace": format_traceroute_result,
        "headers": format_headers_result,
        "whois": format_whois_result,
        "geo": format_geo_result,
        "netinfo": format_netinfo_result,
    }
    formatter = formatters.get(result_type)
    if not formatter:
        print_error(f"Formatador para '{result_type}' não implementado.")
        return

    content = formatter(result_data)
    style = "success" if result_data.get("success") else "error"
    print_result_panel(title, content, style=style)

# ---------------------------------------------------------------------------
# RENDERIZAÇÃO DE TELA (SPLASH)
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
        content = Text()
        for line in title_lines:
            content.append(line + "\n", style=f"bold {PRIMARY}")

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

    status_val = Text(f"Resolvido -> {resolved_ip}", style=f"bold {SUCCESS}") if resolved_ip else Text("Não foi possível resolver", style=f"bold {WARNING}")

    rows = [
        (ICONS["target"], "ALVO", Text(target, style=f"bold {SUCCESS}")),
        (ICONS["status"], "TIPO", Text(target_type.upper(), style=f"bold {ACCENT}")),
        (ICONS["status"], "STATUS", status_val),
        (ICONS["time"], "DATA E HORA", Text(datetime_str, style=TEXT)),
        (ICONS["user"], "USUÁRIO", Text(username, style=TEXT)),
    ]

    for icon, label, val in rows:
        info_table.add_row(Text(icon, style=ACCENT), label, Text(":", style=MUTED), val)

    console.print(Panel(info_table, title=f" {ICONS['section']} INFORMAÇÕES DO ALVO ", title_align="left", border_style=BORDER_STYLE, box=box.ROUNDED, padding=(1, 2)))

def _render_log_panel(target, resolved_ip, width):
    log_text = Text()
    log_text.append(f" {ICONS['info']} Inicializando Shockwave...\n", style=TEXT)
    if resolved_ip:
        log_text.append(f" {ICONS['success']} Host resolvido: {resolved_ip}\n", style=SUCCESS)
    else:
        log_text.append(f" {ICONS['warning']} Falha na resolução\n", style=DANGER)
    
    console.print(Panel(log_text, title=f" {ICONS['section']} LOG DE INICIALIZAÇÃO ", title_align="left", border_style=BORDER_STYLE, box=box.ROUNDED, padding=(1, 2)))

def _render_footer(width):
    footer_text = Text(justify="center")
    footer_text.append(f"SHOCKWAVE v{__version__}", style=f"bold {PRIMARY}")
    footer_text.append(" • ", style=MUTED)
    footer_text.append("FERRAMENTA DE DIAGNÓSTICO DE REDE", style=f"bold {MUTED}")
    console.print(Panel(Align.center(footer_text), border_style=PRIMARY_DIM, box=box.HORIZONTALS, padding=0))

# ---------------------------------------------------------------------------
# INTERFACE DE COMANDOS E FORMATAÇÃO (REUSÁVEIS)
# ---------------------------------------------------------------------------

def print_prompt():
    try:
        arrow = "\033[38;5;177m❯\033[38;5;213m❯\033[38;5;51m❯\033[0m"
        return input(f" {arrow} \033[1m")
    except (EOFError, KeyboardInterrupt):
        return "exit"

def print_result_panel(title, content, style="info"):
    border_map = {"success": SUCCESS, "error": DANGER, "warning": WARNING}
    icon_map = {"success": ICONS["success"], "error": ICONS["error"], "warning": ICONS["warning"]}
    console.print(Panel(content, title=f" {icon_map.get(style, ICONS['section'])} {title} ", title_align="left", border_style=border_map.get(style, BORDER_STYLE), box=box.ROUNDED, padding=(1, 2)))

# --- Funções format_* (A implementação de cada uma permanece conforme seu script) ---
# (format_resolve_result, format_ping_result, etc... inseridas aqui)

def print_info(message): console.print(Text.assemble((f" {ICONS['info']} ", f"bold {ACCENT}"), (message, TEXT)))
def print_success(message): console.print(Text.assemble((f" {ICONS['success']} ", f"bold {SUCCESS}"), (message, f"bold {SUCCESS}")))
def print_error(message): console.print(Text.assemble((f" {ICONS['error']} ", f"bold {DANGER}"), (message, f"bold {DANGER}")))
def print_warning(message): console.print(Text.assemble((f" {ICONS['warning']} ", f"bold {WARNING}"), (message, WARNING)))

def print_help():
    """Exibe os comandos disponíveis, agrupados por categoria."""
    groups = [
        ("RECONHECIMENTO", [
            ("resolve", "Resolve o hostname para IPv4", "resolve"),
            ("dns", "Registros DNS (A, CNAME, PTR, MX, NS)", "dns"),
            ("whois", "Consulta WHOIS (porta 43)", "whois"),
            ("geo", "Geolocaliza um endereço IP", "geo"),
        ]),
        ("SONDAGEM", [
            ("ping", "Faz ping no alvo", "ping [quantidade]"),
            ("sweep", "Varredura de ping em uma faixa de rede", "sweep <ip_base> [início-fim]"),
            ("trace", "Traceroute até o alvo", "trace"),
            ("headers", "Cabeçalhos de resposta HTTP", "headers"),
        ]),
        ("ESCANEAMENTO", [
            ("scan", "Escaneia portas comuns no alvo", "scan"),
            ("cscan", "Escaneamento de portas customizado", "cscan <especificação>"),
        ]),
        ("SISTEMA", [
            ("netinfo", "Informações da rede local", "netinfo"),
            ("target", "Altera o alvo", "target <novo_alvo>"),
            ("clear", "Limpa a tela", "clear"),
            ("banner", "Mostra a tela inicial novamente", "banner"),
            ("help", "Mostra esta ajuda", "help"),
            ("exit", "Sai do Shockwave", "exit"),
        ]),
    ]

    help_table = Table(
        title=Text(f" {ICONS['section']} COMANDOS DISPONÍVEIS ", style=f"bold {PRIMARY}"),
        show_header=True,
        header_style=f"bold {PRIMARY}",
        border_style=BORDER_STYLE,
        box=box.ROUNDED,
        padding=(0, 2),
        expand=True,
    )
    help_table.add_column("Comando", style=f"bold {ACCENT}", width=20)
    help_table.add_column("Descrição", style=TEXT)
    help_table.add_column("Uso", style=MUTED)

    for group_name, commands in groups:
        help_table.add_row(Text(group_name, style=f"bold {SUCCESS}"), "", "")
        for cmd, desc, usage in commands:
            help_table.add_row(f"  {cmd}", desc, usage)

    console.print()
    console.print(help_table)
    console.print()

# --- Funções de Formatação (O restante que faltava) ---

def format_resolve_result(result):
    text = Text()
    if result["success"]:
        text.append("Host resolvido com sucesso\n\n", style=f"bold {SUCCESS}")
        text.append("  Hostname : ", style=f"bold {PRIMARY}")
        text.append(f"{result['hostname']}\n", style=TEXT)
        text.append("  IPv4     : ", style=f"bold {PRIMARY}")
        text.append(f"{result['ipv4']}\n", style=f"bold {ACCENT}")
    else:
        text.append(f"Falha na resolução: {result['error']}", style=f"bold {DANGER}")
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
        text.append(f"Varredura concluída: {alive_count}/{result['total']} hosts ativos\n\n", style=f"bold {SUCCESS}")
        for ip in result["alive"]:
            text.append(f"  {ICONS['success']} {ip}\n", style=f"bold {SUCCESS}")
    else:
        text.append(f"Falha na varredura: {result.get('error', 'Erro desconhecido')}", style=f"bold {DANGER}")
    return text

def format_port_scan_result(result):
    if not result.get("success"):
        return Text(f"Falha: {result.get('error')}", style=f"bold {DANGER}")
    
    scan_table = Table(title=f"Portas abertas em {result['target']}", box=box.SIMPLE)
    scan_table.add_column("Porta", style=ACCENT)
    scan_table.add_column("Serviço")
    for p in result["open"]:
        scan_table.add_row(str(p["port"]), p["service"])
    return scan_table

def format_dns_result(result):
    text = Text(f"Registros DNS para {result['target']}:\n\n", style=f"bold {SUCCESS}")
    for rtype in ["A", "CNAME", "MX", "NS"]:
        records = result.get(rtype, [])
        text.append(f"  {rtype}: {', '.join(records) if records else 'Nenhum'}\n", style=TEXT)
    return text

def format_traceroute_result(result):
    if not result["success"]: return Text(result["error"], style=DANGER)
    text = Text(f"Traceroute para {result['target']}\n\n", style=f"bold {SUCCESS}")
    for hop in result["hops"]:
        text.append(f" {hop['hop']}  {hop['ip']} ({hop['rtt']} ms)\n", style=TEXT)
    return text

def format_headers_result(result):
    if not result["success"]: return Text(result["error"], style=DANGER)
    text = Text(f"Cabeçalhos HTTP ({result['status']}):\n", style=f"bold {SUCCESS}")
    for k, v in result["headers"].items():
        text.append(f"  {k}: {v}\n", style=TEXT)
    return text

def format_whois_result(result):
    text = Text("Dados WHOIS:\n", style=f"bold {SUCCESS}")
    for k, v in result.get("parsed", {}).items():
        text.append(f"  {k}: {v}\n", style=TEXT)
    return text

def format_geo_result(result):
    text = Text("Geolocalização:\n", style=f"bold {SUCCESS}")
    for k, v in result.items():
        if k not in ["success"]: text.append(f"  {k}: {v}\n", style=TEXT)
    return text

def format_netinfo_result(result):
    text = Text("Rede Local:\n", style=f"bold {SUCCESS}")
    text.append(f"  IP: {result.get('local_ip')}\n  Público: {result.get('public_ip')}")
    return text