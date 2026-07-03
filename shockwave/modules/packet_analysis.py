"""Packet Analysis - Live packet capture, PCAP reader, protocol statistics,
TCP stream analysis, DNS/HTTP/TLS/ICMP analysis, bandwidth statistics."""

import os
import re
import socket
import struct
import subprocess
import time
from collections import Counter, defaultdict


def live_packet_capture(interface=None, count=50, timeout=30, filter_expr=None):
    """Capture live packets using tcpdump."""
    result = {"success": False, "packets": [], "total": 0}

    cmd = ["tcpdump", "-c", str(count), "-nn", "-l"]

    if interface:
        cmd.extend(["-i", interface])
    else:
        cmd.extend(["-i", "any"])

    if filter_expr:
        cmd.extend(filter_expr.split())

    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, text=True)

        for line in proc.stdout.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("tcpdump:") and not line.startswith("listening"):
                result["packets"].append(line)

        result["total"] = len(result["packets"])
        result["success"] = True

        if proc.stderr:
            stats_match = re.search(r"(\d+) packets captured", proc.stderr)
            if stats_match:
                result["captured"] = int(stats_match.group(1))

            dropped_match = re.search(r"(\d+) packets dropped", proc.stderr)
            if dropped_match:
                result["dropped"] = int(dropped_match.group(1))

    except subprocess.TimeoutExpired:
        result["error"] = "Capture timed out"
        result["success"] = True
    except FileNotFoundError:
        result["error"] = "tcpdump not found (install with: apt install tcpdump)"
    except PermissionError:
        result["error"] = "Permission denied (run with sudo)"

    return result


def pcap_reader(filepath):
    """Read and analyze a PCAP file using tcpdump."""
    result = {"success": False, "file": filepath, "packets": [], "summary": {}}

    if not os.path.exists(filepath):
        result["error"] = f"File not found: {filepath}"
        return result

    try:
        proc = subprocess.run(
            ["tcpdump", "-nn", "-r", filepath, "-c", "200"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, text=True)

        for line in proc.stdout.strip().split("\n"):
            line = line.strip()
            if line:
                result["packets"].append(line)

        result["total_packets"] = len(result["packets"])

        proc2 = subprocess.run(
            ["tcpdump", "-nn", "-r", filepath, "-q"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, text=True)

        stats_match = re.search(r"(\d+) packets", proc2.stderr)
        if stats_match:
            result["summary"]["total"] = int(stats_match.group(1))

        result["success"] = True

    except subprocess.TimeoutExpired:
        result["error"] = "PCAP reading timed out"
    except FileNotFoundError:
        result["error"] = "tcpdump not found"

    return result


def protocol_statistics(interface=None, count=100, timeout=30):
    """Gather protocol distribution statistics from captured packets."""
    result = {"success": False, "protocols": {}, "total": 0}

    cmd = ["tcpdump", "-c", str(count), "-nn", "-q", "-l"]

    if interface:
        cmd.extend(["-i", interface])
    else:
        cmd.extend(["-i", "any"])

    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, text=True)

        proto_count = Counter()
        for line in proc.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            if "TCP" in line.upper() or "Flags" in line:
                proto_count["TCP"] += 1
            elif "UDP" in line.upper():
                proto_count["UDP"] += 1
            elif "ICMP" in line.upper():
                proto_count["ICMP"] += 1
            elif "ARP" in line.upper():
                proto_count["ARP"] += 1
            elif "DNS" in line.upper():
                proto_count["DNS"] += 1
            else:
                proto_count["Other"] += 1

        result["protocols"] = dict(proto_count)
        result["total"] = sum(proto_count.values())
        result["success"] = True

    except subprocess.TimeoutExpired:
        result["error"] = "Capture timed out"
        result["success"] = True
    except FileNotFoundError:
        result["error"] = "tcpdump not found"
    except PermissionError:
        result["error"] = "Permission denied"

    return result


def tcp_stream_analysis(target, port=80, duration=10):
    """Analyze TCP stream to a specific target."""
    result = {"success": False, "target": target, "port": port, "packets": []}

    cmd = [
        "tcpdump", "-c", "50", "-nn", "-l",
        "-i", "any",
        f"host {target} and port {port}",
    ]

    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=duration, text=True)

        syn_count = 0
        ack_count = 0
        fin_count = 0
        rst_count = 0

        for line in proc.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            result["packets"].append(line)

            if "[S]" in line:
                syn_count += 1
            if "[.]" in line or "[A]" in line:
                ack_count += 1
            if "[F]" in line:
                fin_count += 1
            if "[R]" in line:
                rst_count += 1

        result["statistics"] = {
            "total_packets": len(result["packets"]),
            "syn": syn_count,
            "ack": ack_count,
            "fin": fin_count,
            "rst": rst_count,
        }
        result["success"] = True

    except subprocess.TimeoutExpired:
        result["success"] = True
    except FileNotFoundError:
        result["error"] = "tcpdump not found"
    except PermissionError:
        result["error"] = "Permission denied"

    return result


def dns_packet_analysis(interface=None, count=20, timeout=15):
    """Capture and analyze DNS packets."""
    result = {"success": False, "queries": [], "responses": []}

    cmd = ["tcpdump", "-c", str(count), "-nn", "-l", "-i"]
    cmd.append(interface if interface else "any")
    cmd.append("port 53")

    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, text=True)

        for line in proc.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            if "A?" in line or "AAAA?" in line or "MX?" in line:
                result["queries"].append(line)
            elif "A " in line and ">" in line:
                result["responses"].append(line)
            else:
                result["queries"].append(line)

        result["total_queries"] = len(result["queries"])
        result["total_responses"] = len(result["responses"])
        result["success"] = True

    except subprocess.TimeoutExpired:
        result["success"] = True
    except FileNotFoundError:
        result["error"] = "tcpdump not found"
    except PermissionError:
        result["error"] = "Permission denied"

    return result


def http_packet_analysis(target=None, interface=None, count=30, timeout=15):
    """Capture and analyze HTTP packets."""
    result = {"success": False, "requests": [], "responses": []}

    cmd = ["tcpdump", "-c", str(count), "-nn", "-A", "-l", "-i"]
    cmd.append(interface if interface else "any")
    cmd.append("port 80 or port 443 or port 8080")

    if target:
        cmd[-1] = f"host {target} and (port 80 or port 443 or port 8080)"

    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, text=True)

        current_block = []
        for line in proc.stdout.split("\n"):
            if re.match(r"\d{2}:\d{2}:\d{2}", line.strip()):
                if current_block:
                    block_text = "\n".join(current_block)
                    if any(m in block_text for m in ["GET ", "POST ", "PUT ", "DELETE ", "HEAD "]):
                        result["requests"].append(block_text[:500])
                    elif "HTTP/" in block_text:
                        result["responses"].append(block_text[:500])
                current_block = [line.strip()]
            else:
                current_block.append(line)

        result["total_requests"] = len(result["requests"])
        result["total_responses"] = len(result["responses"])
        result["success"] = True

    except subprocess.TimeoutExpired:
        result["success"] = True
    except FileNotFoundError:
        result["error"] = "tcpdump not found"
    except PermissionError:
        result["error"] = "Permission denied"

    return result


def tls_handshake_analysis(target, port=443, timeout=10):
    """Analyze TLS handshake."""
    result = {"success": False, "target": target, "port": port}

    try:
        import ssl as ssl_mod

        start = time.time()

        ctx = ssl_mod.SSLContext(ssl_mod.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl_mod.CERT_NONE

        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=target)
        conn.settimeout(timeout)
        conn.connect((target, port))

        elapsed = time.time() - start

        result["handshake_time_ms"] = round(elapsed * 1000, 2)
        result["protocol_version"] = conn.version()
        result["cipher"] = conn.cipher()
        result["compression"] = conn.compression()

        if result["cipher"]:
            result["cipher_name"] = result["cipher"][0]
            result["cipher_bits"] = result["cipher"][2]

        try:
            alpn = conn.selected_alpn_protocol()
            result["alpn"] = alpn
        except AttributeError:
            pass

        conn.close()
        result["success"] = True

    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result


def icmp_analysis(target, count=5, timeout=10):
    """Analyze ICMP packets to/from a target."""
    result = {"success": False, "target": target, "packets": []}

    try:
        proc = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), target],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=count * timeout + 5, text=True)

        for line in proc.stdout.strip().split("\n"):
            line = line.strip()
            if line:
                result["packets"].append(line)

        stats_match = re.search(
            r"(\d+) packets transmitted, (\d+) received.*?(\d+(?:\.\d+)?)% packet loss",
            proc.stdout)
        if stats_match:
            result["transmitted"] = int(stats_match.group(1))
            result["received"] = int(stats_match.group(2))
            result["packet_loss"] = float(stats_match.group(3))

        rtt_match = re.search(
            r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)",
            proc.stdout)
        if rtt_match:
            result["rtt_min"] = float(rtt_match.group(1))
            result["rtt_avg"] = float(rtt_match.group(2))
            result["rtt_max"] = float(rtt_match.group(3))
            result["rtt_mdev"] = float(rtt_match.group(4))

        ttl_values = [int(m) for m in re.findall(r"ttl=(\d+)", proc.stdout, re.IGNORECASE)]
        if ttl_values:
            result["ttl_values"] = ttl_values

        result["success"] = True

    except subprocess.TimeoutExpired:
        result["error"] = "ICMP analysis timed out"
    except FileNotFoundError:
        result["error"] = "ping not found"

    return result


def bandwidth_statistics(interface=None, duration=5):
    """Gather bandwidth statistics for a network interface."""
    result = {"success": False, "interface": interface}

    if not interface:
        try:
            proc = subprocess.run(
                ["ip", "route", "show", "default"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=5, text=True)
            match = re.search(r"dev\s+(\S+)", proc.stdout)
            if match:
                interface = match.group(1)
                result["interface"] = interface
        except (subprocess.TimeoutExpired, FileNotFoundError):
            interface = "eth0"
            result["interface"] = interface

    rx_path = f"/sys/class/net/{interface}/statistics/rx_bytes"
    tx_path = f"/sys/class/net/{interface}/statistics/tx_bytes"

    try:
        with open(rx_path) as f:
            rx_start = int(f.read().strip())
        with open(tx_path) as f:
            tx_start = int(f.read().strip())

        time.sleep(duration)

        with open(rx_path) as f:
            rx_end = int(f.read().strip())
        with open(tx_path) as f:
            tx_end = int(f.read().strip())

        rx_bytes = rx_end - rx_start
        tx_bytes = tx_end - tx_start

        result.update({
            "success": True,
            "duration_seconds": duration,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "rx_rate_bps": round(rx_bytes * 8 / duration, 2),
            "tx_rate_bps": round(tx_bytes * 8 / duration, 2),
            "rx_rate_kbps": round(rx_bytes * 8 / duration / 1000, 2),
            "tx_rate_kbps": round(tx_bytes * 8 / duration / 1000, 2),
            "rx_rate_mbps": round(rx_bytes * 8 / duration / 1000000, 4),
            "tx_rate_mbps": round(tx_bytes * 8 / duration / 1000000, 4),
            "total_bytes": rx_bytes + tx_bytes,
        })

    except FileNotFoundError:
        result["error"] = f"Interface statistics not found for {interface}"
    except (ValueError, PermissionError) as e:
        result["error"] = str(e)

    return result
