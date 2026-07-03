"""Shockwave - Aplicacao principal com todos os modulos."""

import getpass
import socket
from datetime import datetime

from shockwave import ui

# --- Modulos existentes ---
from shockwave.modules.resolver import resolve_host
from shockwave.modules.ping_sweep import ping_single, ping_sweep
from shockwave.modules.port_scan import (
    scan_common_ports, scan_custom_ports, scan_full_ports,
    tcp_scan, udp_scan, syn_scan, ack_scan, fin_scan,
    null_scan, xmas_scan, window_scan, idle_scan,
    fragment_scan, adaptive_timing_scan,
)
from shockwave.modules.dns_records import get_dns_records
from shockwave.modules.traceroute import traceroute
from shockwave.modules.http_headers import get_http_headers
from shockwave.modules.whois_lookup import whois_lookup
from shockwave.modules.geolocate import geolocate_ip
from shockwave.modules.net_info import get_local_network_info

# --- Novos modulos ---
from shockwave.modules.network_discovery import (
    reverse_dns, arp_scan, tcp_host_discovery, udp_host_discovery,
    cidr_scan, gateway_detection, network_interface_discovery,
    mac_address_discovery, identify_vendor,
)
from shockwave.modules.enumeration import (
    asn_lookup, subdomain_enumeration, dnssec_detection,
    zone_transfer_check, cdn_detection,
)
from shockwave.modules.service_detection import (
    banner_grab, service_detection, version_detection,
    http_detection, ssh_detection, ftp_detection,
    smtp_detection, smb_detection, snmp_detection,
    database_detection, mqtt_detection, redis_detection,
)
from shockwave.modules.fingerprinting import (
    os_detection, device_type_detection, tcp_stack_analysis,
    ttl_analysis, mss_analysis, window_size_analysis,
)
from shockwave.modules.ssl_tls import (
    certificate_viewer, certificate_validation, cipher_enumeration,
    tls_version_detection, hsts_detection, alpn_detection,
    weak_cipher_detection, expiration_checker,
)
from shockwave.modules.http_analysis import (
    security_headers_check, cookie_analysis, redirect_detection,
    compression_detection, http_methods_detection, http2_detection,
    http3_detection, robots_txt, sitemap_xml, web_technology_detection,
)
from shockwave.modules.packet_analysis import (
    live_packet_capture, pcap_reader, protocol_statistics,
    tcp_stream_analysis, dns_packet_analysis, http_packet_analysis,
    tls_handshake_analysis, icmp_analysis, bandwidth_statistics,
)
from shockwave.modules.performance import (
    latency_test, packet_loss_test, jitter_test,
    mtu_discovery, path_mtu_discovery, throughput_estimation,
)
from shockwave.modules.reports import (
    json_export, html_report, csv_export,
    xml_export, pdf_report, scan_comparison,
)


class ShockwaveApp:
    """Classe principal da aplicacao Shockwave."""

    def __init__(self, target):
        self.target = target
        self.resolved_ip = None
        self.target_type = self._detect_target_type(target)
        self.username = getpass.getuser()
        self.running = True
        self.scan_history = {}

    def _detect_target_type(self, target):
        try:
            socket.inet_aton(target)
            return "IP"
        except socket.error:
            pass
        if "/" in target:
            return "REDE"
        return "DOMINIO"

    def _resolve_target(self):
        result = resolve_host(self.target)
        if result["success"]:
            self.resolved_ip = result["ipv4"]
        return result

    def run(self):
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
        commands = {
            # --- Descoberta de Rede ---
            "resolve": self._cmd_resolve,
            "rdns": self._cmd_rdns,
            "ping": self._cmd_ping,
            "sweep": self._cmd_sweep,
            "arp": self._cmd_arp,
            "tcpdiscovery": self._cmd_tcp_discovery,
            "udpdiscovery": self._cmd_udp_discovery,
            "cidr": self._cmd_cidr,
            "gateway": self._cmd_gateway,
            "interfaces": self._cmd_interfaces,
            "mac": self._cmd_mac,
            "vendor": self._cmd_vendor,

            # --- Enumeracao ---
            "dns": self._cmd_dns,
            "whois": self._cmd_whois,
            "asn": self._cmd_asn,
            "geo": self._cmd_geo,
            "subdomains": self._cmd_subdomains,
            "dnssec": self._cmd_dnssec,
            "zonetransfer": self._cmd_zone_transfer,
            "cdn": self._cmd_cdn,

            # --- Port Scanning ---
            "scan": self._cmd_scan,
            "fullscan": self._cmd_fullscan,
            "cscan": self._cmd_cscan,
            "tcpscan": self._cmd_tcpscan,
            "udpscan": self._cmd_udpscan,
            "synscan": self._cmd_synscan,
            "ackscan": self._cmd_ackscan,
            "finscan": self._cmd_finscan,
            "nullscan": self._cmd_nullscan,
            "xmasscan": self._cmd_xmasscan,
            "winscan": self._cmd_winscan,
            "idlescan": self._cmd_idlescan,
            "fragscan": self._cmd_fragscan,
            "adaptive": self._cmd_adaptive,

            # --- Identificacao de Servicos ---
            "banner": self._cmd_banner_grab,
            "svcdetect": self._cmd_service_detect,
            "version": self._cmd_version_detect,
            "httpdetect": self._cmd_http_detect,
            "sshdetect": self._cmd_ssh_detect,
            "ftpdetect": self._cmd_ftp_detect,
            "smtpdetect": self._cmd_smtp_detect,
            "smbdetect": self._cmd_smb_detect,
            "snmpdetect": self._cmd_snmp_detect,
            "dbdetect": self._cmd_db_detect,
            "mqttdetect": self._cmd_mqtt_detect,
            "redisdetect": self._cmd_redis_detect,

            # --- Fingerprinting ---
            "osdetect": self._cmd_os_detect,
            "devicetype": self._cmd_device_type,
            "tcpstack": self._cmd_tcp_stack,
            "ttl": self._cmd_ttl,
            "mss": self._cmd_mss,
            "winsize": self._cmd_winsize,

            # --- SSL/TLS ---
            "cert": self._cmd_cert,
            "certval": self._cmd_certval,
            "ciphers": self._cmd_ciphers,
            "tlsver": self._cmd_tlsver,
            "hsts": self._cmd_hsts,
            "alpn": self._cmd_alpn,
            "weakciphers": self._cmd_weak_ciphers,
            "certexpiry": self._cmd_cert_expiry,

            # --- HTTP Analysis ---
            "headers": self._cmd_headers,
            "secheaders": self._cmd_sec_headers,
            "cookies": self._cmd_cookies,
            "redirects": self._cmd_redirects,
            "compression": self._cmd_compression,
            "httpmethods": self._cmd_http_methods,
            "http2": self._cmd_http2,
            "http3": self._cmd_http3,
            "robots": self._cmd_robots,
            "sitemap": self._cmd_sitemap,
            "webtech": self._cmd_webtech,

            # --- Packet Analysis ---
            "capture": self._cmd_capture,
            "pcap": self._cmd_pcap,
            "protostats": self._cmd_proto_stats,
            "tcpstream": self._cmd_tcp_stream,
            "dnsanalysis": self._cmd_dns_analysis,
            "httpanalysis": self._cmd_http_analysis,
            "tlshandshake": self._cmd_tls_handshake,
            "icmp": self._cmd_icmp,
            "bandwidth": self._cmd_bandwidth,

            # --- Performance ---
            "latency": self._cmd_latency,
            "packetloss": self._cmd_packet_loss,
            "jitter": self._cmd_jitter,
            "mtudisc": self._cmd_mtu,
            "pathmtu": self._cmd_path_mtu,
            "throughput": self._cmd_throughput,

            # --- Relatorios ---
            "exportjson": self._cmd_export_json,
            "exporthtml": self._cmd_export_html,
            "exportcsv": self._cmd_export_csv,
            "exportxml": self._cmd_export_xml,
            "exportpdf": self._cmd_export_pdf,
            "compare": self._cmd_compare,

            # --- Sistema ---
            "trace": self._cmd_trace,
            "netinfo": self._cmd_netinfo,
            "target": self._cmd_target,
            "clear": self._cmd_clear,
            "splash": self._cmd_splash,
            "help": self._cmd_help,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
        }

        handler = commands.get(cmd)
        if handler:
            handler(args)
        else:
            ui.print_error(f"Comando desconhecido: '{cmd}'. Digite 'help' para ver os comandos.")

    def _get_scan_target(self):
        return self.resolved_ip or self.target

    def _store_result(self, name, data):
        self.scan_history[name] = {"data": data, "timestamp": datetime.now().isoformat()}

    # =====================================================================
    # DESCOBERTA DE REDE
    # =====================================================================

    def _cmd_resolve(self, args):
        target = args.strip() if args.strip() else self.target
        with ui.spinner(f"Resolvendo {target}..."):
            result = resolve_host(target)
        content = ui.format_resolve_result(result)
        ui.print_result_panel("RESOLVER HOST", content, "success" if result["success"] else "error")
        self._store_result("resolve", result)

    def _cmd_rdns(self, args):
        target = args.strip() if args.strip() else self._get_scan_target()
        with ui.spinner(f"Reverse DNS para {target}..."):
            result = reverse_dns(target)
        content = ui.format_generic_result(result, "Reverse DNS")
        ui.print_result_panel("REVERSE DNS", content, "success" if result["success"] else "error")

    def _cmd_ping(self, args):
        count = 4
        if args.strip().isdigit():
            count = int(args.strip())
        target = self._get_scan_target()
        with ui.spinner(f"Ping para {target} ({count} pacotes)..."):
            result = ping_single(target, count=count)
        content = ui.format_ping_result(result)
        ui.print_result_panel("PING", content, "success" if result["success"] else "error")

    def _cmd_sweep(self, args):
        parts = args.strip().split()
        if not parts:
            ip = self._get_scan_target()
            base = ".".join(ip.split(".")[:3])
            start, end = 1, 254
        else:
            base = parts[0]
            if len(parts) > 1 and "-" in parts[1]:
                rp = parts[1].split("-")
                start, end = int(rp[0]), int(rp[1])
            else:
                start, end = 1, 254
        with ui.spinner(f"Varrendo {base}.{start}-{end}..."):
            result = ping_sweep(base, start=start, end=end)
        content = ui.format_sweep_result(result)
        ui.print_result_panel("VARREDURA DE PING", content, "success" if result.get("success") else "error")

    def _cmd_arp(self, args):
        with ui.spinner("Escaneamento ARP..."):
            result = arp_scan(interface=args.strip() or None)
        content = ui.format_arp_result(result)
        ui.print_result_panel("ARP SCAN", content, "success" if result["success"] else "error")

    def _cmd_tcp_discovery(self, args):
        target = args.strip() if args.strip() else self._get_scan_target()
        with ui.spinner(f"TCP Host Discovery em {target}..."):
            result = tcp_host_discovery(target)
        content = ui.format_generic_result(result, "TCP Host Discovery")
        ui.print_result_panel("TCP HOST DISCOVERY", content, "success" if result["success"] else "error")

    def _cmd_udp_discovery(self, args):
        target = args.strip() if args.strip() else self._get_scan_target()
        with ui.spinner(f"UDP Host Discovery em {target}..."):
            result = udp_host_discovery(target)
        content = ui.format_generic_result(result, "UDP Host Discovery")
        ui.print_result_panel("UDP HOST DISCOVERY", content, "success" if result["success"] else "error")

    def _cmd_cidr(self, args):
        cidr = args.strip()
        if not cidr:
            ip = self._get_scan_target()
            cidr = ".".join(ip.split(".")[:3]) + ".0/24"
        with ui.spinner(f"Escaneando CIDR {cidr}..."):
            result = cidr_scan(cidr)
        content = ui.format_cidr_result(result)
        ui.print_result_panel("CIDR SCANNER", content, "success" if result.get("success") else "error")

    def _cmd_gateway(self, args):
        with ui.spinner("Detectando gateway..."):
            result = gateway_detection()
        content = ui.format_generic_result(result, "Gateway Detection")
        ui.print_result_panel("GATEWAY DETECTION", content, "success" if result["success"] else "error")

    def _cmd_interfaces(self, args):
        with ui.spinner("Descobrindo interfaces de rede..."):
            result = network_interface_discovery()
        content = ui.format_interfaces_result(result)
        ui.print_result_panel("NETWORK INTERFACES", content, "success" if result["success"] else "error")

    def _cmd_mac(self, args):
        target = args.strip() if args.strip() else self._get_scan_target()
        with ui.spinner(f"Descobrindo MAC de {target}..."):
            result = mac_address_discovery(target)
        content = ui.format_generic_result(result, "MAC Address Discovery")
        ui.print_result_panel("MAC ADDRESS", content, "success" if result["success"] else "error")

    def _cmd_vendor(self, args):
        mac = args.strip()
        if not mac:
            ui.print_error("Uso: vendor <mac_address>  (ex: vendor 00:50:56:xx:xx:xx)")
            return
        vendor = identify_vendor(mac)
        ui.print_result_panel("VENDOR (OUI)", ui.format_text(f"MAC: {mac}\nVendor: {vendor}"))

    # =====================================================================
    # ENUMERACAO
    # =====================================================================

    def _cmd_dns(self, args):
        target = args.strip() if args.strip() else self.target
        with ui.spinner(f"Consultando registros DNS de {target}..."):
            result = get_dns_records(target)
        content = ui.format_dns_result(result)
        ui.print_result_panel("REGISTROS DNS", content)
        self._store_result("dns", result)

    def _cmd_whois(self, args):
        target = args.strip() if args.strip() else self.target
        with ui.spinner(f"Consultando WHOIS de {target}..."):
            result = whois_lookup(target)
        content = ui.format_whois_result(result)
        ui.print_result_panel("CONSULTA WHOIS", content, "success" if result["success"] else "error")
        self._store_result("whois", result)

    def _cmd_asn(self, args):
        target = args.strip() if args.strip() else self.target
        with ui.spinner(f"ASN Lookup para {target}..."):
            result = asn_lookup(target)
        content = ui.format_generic_result(result, "ASN Lookup")
        ui.print_result_panel("ASN LOOKUP", content, "success" if result["success"] else "error")

    def _cmd_geo(self, args):
        target = args.strip() if args.strip() else self._get_scan_target()
        with ui.spinner(f"Geolocalizando {target}..."):
            result = geolocate_ip(target)
        content = ui.format_geo_result(result)
        ui.print_result_panel("GEOLOCALIZACAO", content, "success" if result["success"] else "error")
        self._store_result("geo", result)

    def _cmd_subdomains(self, args):
        target = args.strip() if args.strip() else self.target
        with ui.spinner(f"Enumerando subdominos de {target}..."):
            result = subdomain_enumeration(target)
        content = ui.format_subdomain_result(result)
        ui.print_result_panel("SUBDOMAIN ENUMERATION", content, "success" if result["success"] else "error")

    def _cmd_dnssec(self, args):
        target = args.strip() if args.strip() else self.target
        with ui.spinner(f"Verificando DNSSEC de {target}..."):
            result = dnssec_detection(target)
        content = ui.format_generic_result(result, "DNSSEC Detection")
        ui.print_result_panel("DNSSEC DETECTION", content, "success" if result["success"] else "error")

    def _cmd_zone_transfer(self, args):
        target = args.strip() if args.strip() else self.target
        with ui.spinner(f"Verificando Zone Transfer de {target}..."):
            result = zone_transfer_check(target)
        content = ui.format_generic_result(result, "Zone Transfer Check")
        ui.print_result_panel("ZONE TRANSFER CHECK", content, "success" if result["success"] else "error")

    def _cmd_cdn(self, args):
        target = args.strip() if args.strip() else self.target
        with ui.spinner(f"Detectando CDN de {target}..."):
            result = cdn_detection(target)
        content = ui.format_generic_result(result, "CDN Detection")
        ui.print_result_panel("CDN DETECTION", content, "success" if result["success"] else "error")

    # =====================================================================
    # PORT SCANNING
    # =====================================================================

    def _cmd_scan(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"Escaneando portas comuns em {target}..."):
            result = scan_common_ports(target)
        content = ui.format_port_scan_result(result)
        ui.print_result_panel("ESCANEAMENTO DE PORTAS", content, "success" if result.get("success") else "error")
        self._store_result("scan", result)

    def _cmd_fullscan(self, args):
        target = self._get_scan_target()
        ui.print_warning("Escaneamento completo (1-65535). Isso pode demorar...")
        with ui.spinner(f"Full scan em {target}..."):
            result = scan_full_ports(target)
        content = ui.format_port_scan_result(result)
        ui.print_result_panel("FULL PORT SCAN", content, "success" if result.get("success") else "error")
        self._store_result("fullscan", result)

    def _cmd_cscan(self, args):
        if not args.strip():
            ui.print_error("Uso: cscan <portas>  (ex: cscan 1-1024 ou cscan 22,80,443)")
            return
        target = self._get_scan_target()
        with ui.spinner(f"Custom scan {args.strip()} em {target}..."):
            result = scan_custom_ports(target, args.strip())
        content = ui.format_port_scan_result(result)
        ui.print_result_panel("CUSTOM PORT SCAN", content, "success" if result.get("success") else "error")

    def _cmd_tcpscan(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"TCP Scan em {target}..."):
            result = tcp_scan(target)
        content = ui.format_port_scan_result(result)
        ui.print_result_panel("TCP SCAN", content, "success" if result.get("success") else "error")

    def _cmd_udpscan(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"UDP Scan em {target}..."):
            result = udp_scan(target)
        content = ui.format_udp_scan_result(result)
        ui.print_result_panel("UDP SCAN", content, "success" if result.get("success") else "error")

    def _cmd_synscan(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"SYN Scan em {target}..."):
            result = syn_scan(target, ports=args.strip() or None)
        content = ui.format_nmap_scan_result(result)
        ui.print_result_panel("SYN SCAN", content, "success" if result.get("success") else "error")

    def _cmd_ackscan(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"ACK Scan em {target}..."):
            result = ack_scan(target, ports=args.strip() or None)
        content = ui.format_nmap_scan_result(result)
        ui.print_result_panel("ACK SCAN", content, "success" if result.get("success") else "error")

    def _cmd_finscan(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"FIN Scan em {target}..."):
            result = fin_scan(target, ports=args.strip() or None)
        content = ui.format_nmap_scan_result(result)
        ui.print_result_panel("FIN SCAN", content, "success" if result.get("success") else "error")

    def _cmd_nullscan(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"NULL Scan em {target}..."):
            result = null_scan(target, ports=args.strip() or None)
        content = ui.format_nmap_scan_result(result)
        ui.print_result_panel("NULL SCAN", content, "success" if result.get("success") else "error")

    def _cmd_xmasscan(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"XMAS Scan em {target}..."):
            result = xmas_scan(target, ports=args.strip() or None)
        content = ui.format_nmap_scan_result(result)
        ui.print_result_panel("XMAS SCAN", content, "success" if result.get("success") else "error")

    def _cmd_winscan(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"Window Scan em {target}..."):
            result = window_scan(target, ports=args.strip() or None)
        content = ui.format_nmap_scan_result(result)
        ui.print_result_panel("WINDOW SCAN", content, "success" if result.get("success") else "error")

    def _cmd_idlescan(self, args):
        parts = args.strip().split()
        zombie = parts[0] if parts else None
        ports = parts[1] if len(parts) > 1 else None
        target = self._get_scan_target()
        with ui.spinner(f"Idle Scan em {target}..."):
            result = idle_scan(target, zombie_host=zombie, ports=ports)
        content = ui.format_nmap_scan_result(result)
        ui.print_result_panel("IDLE SCAN", content, "success" if result.get("success") else "error")

    def _cmd_fragscan(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"Fragment Scan em {target}..."):
            result = fragment_scan(target, ports=args.strip() or None)
        content = ui.format_nmap_scan_result(result)
        ui.print_result_panel("FRAGMENT SCAN", content, "success" if result.get("success") else "error")

    def _cmd_adaptive(self, args):
        timing = 4
        if args.strip().isdigit():
            timing = int(args.strip())
        target = self._get_scan_target()
        with ui.spinner(f"Adaptive Timing Scan (T{timing}) em {target}..."):
            result = adaptive_timing_scan(target, timing=timing)
        content = ui.format_nmap_scan_result(result)
        ui.print_result_panel("ADAPTIVE TIMING SCAN", content, "success" if result.get("success") else "error")

    # =====================================================================
    # IDENTIFICACAO DE SERVICOS
    # =====================================================================

    def _cmd_banner_grab(self, args):
        parts = args.strip().split()
        if not parts or not parts[0].isdigit():
            ui.print_error("Uso: banner <porta>  (ex: banner 80)")
            return
        port = int(parts[0])
        target = self._get_scan_target()
        with ui.spinner(f"Banner grabbing {target}:{port}..."):
            result = banner_grab(target, port)
        content = ui.format_generic_result(result, "Banner Grabbing")
        ui.print_result_panel("BANNER GRABBING", content, "success" if result["success"] else "error")

    def _cmd_service_detect(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"Detectando servicos em {target}..."):
            result = service_detection(target)
        content = ui.format_service_result(result)
        ui.print_result_panel("SERVICE DETECTION", content, "success" if result["success"] else "error")

    def _cmd_version_detect(self, args):
        parts = args.strip().split()
        if not parts or not parts[0].isdigit():
            ui.print_error("Uso: version <porta>  (ex: version 22)")
            return
        port = int(parts[0])
        target = self._get_scan_target()
        with ui.spinner(f"Version detection {target}:{port}..."):
            result = version_detection(target, port)
        content = ui.format_generic_result(result, "Version Detection")
        ui.print_result_panel("VERSION DETECTION", content, "success" if result["success"] else "error")

    def _cmd_http_detect(self, args):
        target = self._get_scan_target()
        port = int(args.strip()) if args.strip().isdigit() else 80
        with ui.spinner(f"HTTP Detection {target}:{port}..."):
            result = http_detection(target, port)
        content = ui.format_generic_result(result, "HTTP Detection")
        ui.print_result_panel("HTTP DETECTION", content, "success" if result["success"] else "error")

    def _cmd_ssh_detect(self, args):
        target = self._get_scan_target()
        port = int(args.strip()) if args.strip().isdigit() else 22
        with ui.spinner(f"SSH Detection {target}:{port}..."):
            result = ssh_detection(target, port)
        content = ui.format_generic_result(result, "SSH Detection")
        ui.print_result_panel("SSH DETECTION", content, "success" if result["success"] else "error")

    def _cmd_ftp_detect(self, args):
        target = self._get_scan_target()
        port = int(args.strip()) if args.strip().isdigit() else 21
        with ui.spinner(f"FTP Detection {target}:{port}..."):
            result = ftp_detection(target, port)
        content = ui.format_generic_result(result, "FTP Detection")
        ui.print_result_panel("FTP DETECTION", content, "success" if result["success"] else "error")

    def _cmd_smtp_detect(self, args):
        target = self._get_scan_target()
        port = int(args.strip()) if args.strip().isdigit() else 25
        with ui.spinner(f"SMTP Detection {target}:{port}..."):
            result = smtp_detection(target, port)
        content = ui.format_generic_result(result, "SMTP Detection")
        ui.print_result_panel("SMTP DETECTION", content, "success" if result["success"] else "error")

    def _cmd_smb_detect(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"SMB Detection em {target}..."):
            result = smb_detection(target)
        content = ui.format_generic_result(result, "SMB Detection")
        ui.print_result_panel("SMB DETECTION", content, "success" if result["success"] else "error")

    def _cmd_snmp_detect(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"SNMP Detection em {target}..."):
            result = snmp_detection(target)
        content = ui.format_generic_result(result, "SNMP Detection")
        ui.print_result_panel("SNMP DETECTION", content, "success" if result["success"] else "error")

    def _cmd_db_detect(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"Database Detection em {target}..."):
            result = database_detection(target)
        content = ui.format_service_result(result)
        ui.print_result_panel("DATABASE DETECTION", content, "success" if result["success"] else "error")

    def _cmd_mqtt_detect(self, args):
        target = self._get_scan_target()
        port = int(args.strip()) if args.strip().isdigit() else 1883
        with ui.spinner(f"MQTT Detection {target}:{port}..."):
            result = mqtt_detection(target, port)
        content = ui.format_generic_result(result, "MQTT Detection")
        ui.print_result_panel("MQTT DETECTION", content, "success" if result["success"] else "error")

    def _cmd_redis_detect(self, args):
        target = self._get_scan_target()
        port = int(args.strip()) if args.strip().isdigit() else 6379
        with ui.spinner(f"Redis Detection {target}:{port}..."):
            result = redis_detection(target, port)
        content = ui.format_generic_result(result, "Redis Detection")
        ui.print_result_panel("REDIS DETECTION", content, "success" if result["success"] else "error")

    # =====================================================================
    # FINGERPRINTING
    # =====================================================================

    def _cmd_os_detect(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"OS Detection em {target}..."):
            result = os_detection(target)
        content = ui.format_generic_result(result, "OS Detection")
        ui.print_result_panel("OS DETECTION", content, "success" if result["success"] else "error")

    def _cmd_device_type(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"Device Type Detection em {target}..."):
            result = device_type_detection(target)
        content = ui.format_generic_result(result, "Device Type Detection")
        ui.print_result_panel("DEVICE TYPE", content, "success" if result["success"] else "error")

    def _cmd_tcp_stack(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"TCP/IP Stack Analysis em {target}..."):
            result = tcp_stack_analysis(target)
        content = ui.format_generic_result(result, "TCP/IP Stack Analysis")
        ui.print_result_panel("TCP/IP STACK ANALYSIS", content, "success" if result["success"] else "error")

    def _cmd_ttl(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"TTL Analysis em {target}..."):
            result = ttl_analysis(target)
        content = ui.format_generic_result(result, "TTL Analysis")
        ui.print_result_panel("TTL ANALYSIS", content, "success" if result["success"] else "error")

    def _cmd_mss(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"MSS Analysis em {target}..."):
            result = mss_analysis(target)
        content = ui.format_generic_result(result, "MSS Analysis")
        ui.print_result_panel("MSS ANALYSIS", content, "success" if result["success"] else "error")

    def _cmd_winsize(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"Window Size Analysis em {target}..."):
            result = window_size_analysis(target)
        content = ui.format_generic_result(result, "Window Size Analysis")
        ui.print_result_panel("WINDOW SIZE ANALYSIS", content, "success" if result["success"] else "error")

    # =====================================================================
    # SSL / TLS
    # =====================================================================

    def _cmd_cert(self, args):
        target = self.target
        with ui.spinner(f"Visualizando certificado de {target}..."):
            result = certificate_viewer(target)
        content = ui.format_cert_result(result)
        ui.print_result_panel("CERTIFICATE VIEWER", content, "success" if result["success"] else "error")
        self._store_result("cert", result)

    def _cmd_certval(self, args):
        target = self.target
        with ui.spinner(f"Validando certificado de {target}..."):
            result = certificate_validation(target)
        content = ui.format_generic_result(result, "Certificate Validation")
        ui.print_result_panel("CERTIFICATE VALIDATION", content, "success" if result["success"] else "error")

    def _cmd_ciphers(self, args):
        target = self.target
        with ui.spinner(f"Enumerando ciphers de {target}..."):
            result = cipher_enumeration(target)
        content = ui.format_generic_result(result, "Cipher Enumeration")
        ui.print_result_panel("CIPHER ENUMERATION", content, "success" if result["success"] else "error")

    def _cmd_tlsver(self, args):
        target = self.target
        with ui.spinner(f"Detectando versoes TLS de {target}..."):
            result = tls_version_detection(target)
        content = ui.format_tls_version_result(result)
        ui.print_result_panel("TLS VERSION DETECTION", content, "success" if result["success"] else "error")

    def _cmd_hsts(self, args):
        target = self.target
        with ui.spinner(f"Detectando HSTS de {target}..."):
            result = hsts_detection(target)
        content = ui.format_generic_result(result, "HSTS Detection")
        ui.print_result_panel("HSTS DETECTION", content, "success" if result["success"] else "error")

    def _cmd_alpn(self, args):
        target = self.target
        with ui.spinner(f"Detectando ALPN de {target}..."):
            result = alpn_detection(target)
        content = ui.format_generic_result(result, "ALPN Detection")
        ui.print_result_panel("ALPN DETECTION", content, "success" if result["success"] else "error")

    def _cmd_weak_ciphers(self, args):
        target = self.target
        with ui.spinner(f"Verificando weak ciphers de {target}..."):
            result = weak_cipher_detection(target)
        content = ui.format_generic_result(result, "Weak Cipher Detection")
        ui.print_result_panel("WEAK CIPHER DETECTION", content, "success" if result["success"] else "error")

    def _cmd_cert_expiry(self, args):
        target = self.target
        with ui.spinner(f"Verificando expiracao do certificado de {target}..."):
            result = expiration_checker(target)
        content = ui.format_cert_expiry_result(result)
        ui.print_result_panel("CERTIFICATE EXPIRATION", content, "success" if result["success"] else "error")

    # =====================================================================
    # HTTP ANALYSIS
    # =====================================================================

    def _cmd_headers(self, args):
        target = self.target
        with ui.spinner(f"Buscando cabecalhos HTTP de {target}..."):
            result = get_http_headers(target)
        content = ui.format_headers_result(result)
        ui.print_result_panel("CABECALHOS HTTP", content, "success" if result["success"] else "error")
        self._store_result("headers", result)

    def _cmd_sec_headers(self, args):
        target = self.target
        with ui.spinner(f"Verificando security headers de {target}..."):
            result = security_headers_check(target)
        content = ui.format_sec_headers_result(result)
        ui.print_result_panel("SECURITY HEADERS", content, "success" if result["success"] else "error")

    def _cmd_cookies(self, args):
        target = self.target
        with ui.spinner(f"Analisando cookies de {target}..."):
            result = cookie_analysis(target)
        content = ui.format_generic_result(result, "Cookie Analysis")
        ui.print_result_panel("COOKIE ANALYSIS", content, "success" if result["success"] else "error")

    def _cmd_redirects(self, args):
        target = self.target
        with ui.spinner(f"Detectando redirects de {target}..."):
            result = redirect_detection(target)
        content = ui.format_redirect_result(result)
        ui.print_result_panel("REDIRECT DETECTION", content, "success" if result["success"] else "error")

    def _cmd_compression(self, args):
        target = self.target
        with ui.spinner(f"Detectando compressao de {target}..."):
            result = compression_detection(target)
        content = ui.format_generic_result(result, "Compression Detection")
        ui.print_result_panel("COMPRESSION DETECTION", content, "success" if result["success"] else "error")

    def _cmd_http_methods(self, args):
        target = self.target
        with ui.spinner(f"Detectando metodos HTTP de {target}..."):
            result = http_methods_detection(target)
        content = ui.format_generic_result(result, "HTTP Methods")
        ui.print_result_panel("HTTP METHODS", content, "success" if result["success"] else "error")

    def _cmd_http2(self, args):
        target = self.target
        with ui.spinner(f"Detectando HTTP/2 em {target}..."):
            result = http2_detection(target)
        content = ui.format_generic_result(result, "HTTP/2 Detection")
        ui.print_result_panel("HTTP/2 DETECTION", content, "success" if result["success"] else "error")

    def _cmd_http3(self, args):
        target = self.target
        with ui.spinner(f"Detectando HTTP/3 em {target}..."):
            result = http3_detection(target)
        content = ui.format_generic_result(result, "HTTP/3 Detection")
        ui.print_result_panel("HTTP/3 DETECTION", content, "success" if result["success"] else "error")

    def _cmd_robots(self, args):
        target = self.target
        with ui.spinner(f"Buscando robots.txt de {target}..."):
            result = robots_txt(target)
        content = ui.format_robots_result(result)
        ui.print_result_panel("ROBOTS.TXT", content, "success" if result["success"] else "error")

    def _cmd_sitemap(self, args):
        target = self.target
        with ui.spinner(f"Buscando sitemap.xml de {target}..."):
            result = sitemap_xml(target)
        content = ui.format_generic_result(result, "Sitemap.xml")
        ui.print_result_panel("SITEMAP.XML", content, "success" if result["success"] else "error")

    def _cmd_webtech(self, args):
        target = self.target
        with ui.spinner(f"Detectando tecnologias web de {target}..."):
            result = web_technology_detection(target)
        content = ui.format_webtech_result(result)
        ui.print_result_panel("WEB TECHNOLOGY DETECTION", content, "success" if result["success"] else "error")

    # =====================================================================
    # PACKET ANALYSIS
    # =====================================================================

    def _cmd_capture(self, args):
        count = 20
        if args.strip().isdigit():
            count = int(args.strip())
        with ui.spinner(f"Capturando {count} pacotes..."):
            result = live_packet_capture(count=count)
        content = ui.format_capture_result(result)
        ui.print_result_panel("LIVE PACKET CAPTURE", content, "success" if result["success"] else "error")

    def _cmd_pcap(self, args):
        if not args.strip():
            ui.print_error("Uso: pcap <caminho_do_arquivo>")
            return
        with ui.spinner(f"Lendo PCAP {args.strip()}..."):
            result = pcap_reader(args.strip())
        content = ui.format_capture_result(result)
        ui.print_result_panel("PCAP READER", content, "success" if result["success"] else "error")

    def _cmd_proto_stats(self, args):
        with ui.spinner("Coletando estatisticas de protocolo..."):
            result = protocol_statistics(count=50)
        content = ui.format_generic_result(result, "Protocol Statistics")
        ui.print_result_panel("PROTOCOL STATISTICS", content, "success" if result["success"] else "error")

    def _cmd_tcp_stream(self, args):
        target = self._get_scan_target()
        port = int(args.strip()) if args.strip().isdigit() else 80
        with ui.spinner(f"Analisando TCP stream {target}:{port}..."):
            result = tcp_stream_analysis(target, port)
        content = ui.format_generic_result(result, "TCP Stream Analysis")
        ui.print_result_panel("TCP STREAM ANALYSIS", content, "success" if result["success"] else "error")

    def _cmd_dns_analysis(self, args):
        with ui.spinner("Analisando pacotes DNS..."):
            result = dns_packet_analysis()
        content = ui.format_generic_result(result, "DNS Packet Analysis")
        ui.print_result_panel("DNS PACKET ANALYSIS", content, "success" if result["success"] else "error")

    def _cmd_http_analysis(self, args):
        target = args.strip() if args.strip() else None
        with ui.spinner("Analisando pacotes HTTP..."):
            result = http_packet_analysis(target=target)
        content = ui.format_generic_result(result, "HTTP Packet Analysis")
        ui.print_result_panel("HTTP PACKET ANALYSIS", content, "success" if result["success"] else "error")

    def _cmd_tls_handshake(self, args):
        target = self.target
        with ui.spinner(f"Analisando TLS handshake de {target}..."):
            result = tls_handshake_analysis(target)
        content = ui.format_generic_result(result, "TLS Handshake Analysis")
        ui.print_result_panel("TLS HANDSHAKE ANALYSIS", content, "success" if result["success"] else "error")

    def _cmd_icmp(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"Analisando ICMP para {target}..."):
            result = icmp_analysis(target)
        content = ui.format_generic_result(result, "ICMP Analysis")
        ui.print_result_panel("ICMP ANALYSIS", content, "success" if result["success"] else "error")

    def _cmd_bandwidth(self, args):
        with ui.spinner("Medindo bandwidth..."):
            result = bandwidth_statistics(duration=3)
        content = ui.format_generic_result(result, "Bandwidth Statistics")
        ui.print_result_panel("BANDWIDTH STATISTICS", content, "success" if result["success"] else "error")

    # =====================================================================
    # PERFORMANCE
    # =====================================================================

    def _cmd_latency(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"Testando latencia para {target}..."):
            result = latency_test(target)
        content = ui.format_performance_result(result, "Latency Test")
        ui.print_result_panel("LATENCY TEST", content, "success" if result["success"] else "error")

    def _cmd_packet_loss(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"Testando packet loss para {target}..."):
            result = packet_loss_test(target)
        content = ui.format_performance_result(result, "Packet Loss Test")
        ui.print_result_panel("PACKET LOSS TEST", content, "success" if result["success"] else "error")

    def _cmd_jitter(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"Testando jitter para {target}..."):
            result = jitter_test(target)
        content = ui.format_performance_result(result, "Jitter Test")
        ui.print_result_panel("JITTER TEST", content, "success" if result["success"] else "error")

    def _cmd_mtu(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"MTU Discovery para {target}..."):
            result = mtu_discovery(target)
        content = ui.format_generic_result(result, "MTU Discovery")
        ui.print_result_panel("MTU DISCOVERY", content, "success" if result["success"] else "error")

    def _cmd_path_mtu(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"Path MTU Discovery para {target}..."):
            result = path_mtu_discovery(target)
        content = ui.format_generic_result(result, "Path MTU Discovery")
        ui.print_result_panel("PATH MTU DISCOVERY", content, "success" if result["success"] else "error")

    def _cmd_throughput(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"Estimando throughput para {target}..."):
            result = throughput_estimation(target)
        content = ui.format_performance_result(result, "Throughput Estimation")
        ui.print_result_panel("THROUGHPUT ESTIMATION", content, "success" if result["success"] else "error")

    # =====================================================================
    # RELATORIOS
    # =====================================================================

    def _cmd_export_json(self, args):
        if not self.scan_history:
            ui.print_warning("Nenhum scan realizado. Execute scans antes de exportar.")
            return
        filename = args.strip() if args.strip() else None
        with ui.spinner("Exportando para JSON..."):
            result = json_export(self.scan_history, filename=filename)
        content = ui.format_export_result(result)
        ui.print_result_panel("JSON EXPORT", content, "success" if result["success"] else "error")

    def _cmd_export_html(self, args):
        if not self.scan_history:
            ui.print_warning("Nenhum scan realizado. Execute scans antes de exportar.")
            return
        filename = args.strip() if args.strip() else None
        with ui.spinner("Gerando relatorio HTML..."):
            result = html_report(self.scan_history, filename=filename)
        content = ui.format_export_result(result)
        ui.print_result_panel("HTML REPORT", content, "success" if result["success"] else "error")

    def _cmd_export_csv(self, args):
        if not self.scan_history:
            ui.print_warning("Nenhum scan realizado. Execute scans antes de exportar.")
            return
        filename = args.strip() if args.strip() else None
        with ui.spinner("Exportando para CSV..."):
            result = csv_export(self.scan_history, filename=filename)
        content = ui.format_export_result(result)
        ui.print_result_panel("CSV EXPORT", content, "success" if result["success"] else "error")

    def _cmd_export_xml(self, args):
        if not self.scan_history:
            ui.print_warning("Nenhum scan realizado. Execute scans antes de exportar.")
            return
        filename = args.strip() if args.strip() else None
        with ui.spinner("Exportando para XML..."):
            result = xml_export(self.scan_history, filename=filename)
        content = ui.format_export_result(result)
        ui.print_result_panel("XML EXPORT", content, "success" if result["success"] else "error")

    def _cmd_export_pdf(self, args):
        if not self.scan_history:
            ui.print_warning("Nenhum scan realizado. Execute scans antes de exportar.")
            return
        filename = args.strip() if args.strip() else None
        with ui.spinner("Gerando relatorio PDF..."):
            result = pdf_report(self.scan_history, filename=filename)
        content = ui.format_export_result(result)
        ui.print_result_panel("PDF REPORT", content, "success" if result["success"] else "error")

    def _cmd_compare(self, args):
        keys = list(self.scan_history.keys())
        if len(keys) < 2:
            ui.print_warning("Necessario pelo menos 2 scans para comparar. Execute mais scans.")
            return
        scan1 = self.scan_history[keys[-2]]["data"]
        scan2 = self.scan_history[keys[-1]]["data"]
        with ui.spinner("Comparando scans..."):
            result = scan_comparison(scan1, scan2, label1=keys[-2], label2=keys[-1])
        content = ui.format_generic_result(result, "Scan Comparison")
        ui.print_result_panel("SCAN COMPARISON", content, "success" if result["success"] else "error")

    # =====================================================================
    # SISTEMA
    # =====================================================================

    def _cmd_trace(self, args):
        target = self._get_scan_target()
        with ui.spinner(f"Traceroute ate {target}..."):
            result = traceroute(target)
        content = ui.format_traceroute_result(result)
        ui.print_result_panel("TRACEROUTE", content, "success" if result["success"] else "error")

    def _cmd_netinfo(self, args):
        with ui.spinner("Coletando informacoes da rede local..."):
            result = get_local_network_info()
        content = ui.format_netinfo_result(result)
        ui.print_result_panel("INFORMACOES DE REDE LOCAL", content)

    def _cmd_target(self, args):
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
            ui.print_warning(f"Nao foi possivel resolver: {result.get('error', 'desconhecido')}")

    def _cmd_clear(self, args):
        ui.clear_screen()

    def _cmd_splash(self, args):
        datetime_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ui.render_splash_screen(
            target=self.target,
            target_type=self.target_type,
            username=self.username,
            resolved_ip=self.resolved_ip,
            datetime_str=datetime_str,
        )

    def _cmd_help(self, args):
        ui.print_help()

    def _cmd_exit(self, args):
        ui.console.print()
        ui.print_info("Encerrando o Shockwave...")
        ui.print_success("Sessao encerrada. Ate a proxima!")
        ui.console.print()
        self.running = False
