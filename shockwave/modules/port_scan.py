"""Port Scanner - common, full, custom, TCP, UDP, SYN, ACK, FIN, NULL, XMAS,
Window, Idle, Fragment scans and adaptive timing."""

import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def _scan_port(target, port, timeout=1.5):
    """Scan a single TCP port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex((target, port))
        sock.close()

        service = COMMON_PORTS.get(port, "Unknown")
        if code == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = COMMON_PORTS.get(port, "Unknown")

        return {"port": port, "open": code == 0, "service": service}
    except (socket.timeout, socket.error):
        return {"port": port, "open": False, "service": COMMON_PORTS.get(port, "Unknown")}


def _run_scan(target, ports, max_threads=50, timeout=1.5):
    """Run a threaded scan on a list of ports."""
    results = {"open": [], "closed": [], "target": target, "total": len(ports)}

    with ThreadPoolExecutor(max_workers=min(max_threads, max(1, len(ports)))) as executor:
        futures = {executor.submit(_scan_port, target, p, timeout): p for p in ports}
        for future in as_completed(futures):
            r = future.result()
            (results["open"] if r["open"] else results["closed"]).append(r)

    results["open"].sort(key=lambda x: x["port"])
    results["success"] = True
    return results


def scan_common_ports(target, max_threads=50, timeout=1.5):
    """Scan common ports on the target."""
    return _run_scan(target, list(COMMON_PORTS.keys()), max_threads, timeout)


def scan_full_ports(target, max_threads=200, timeout=1.0):
    """Full port scan (1-65535)."""
    return _run_scan(target, list(range(1, 65536)), max_threads, timeout)


def scan_custom_ports(target, port_spec, max_threads=100, timeout=1.5):
    """Scan custom port range."""
    ports = _parse_port_spec(port_spec)
    if not ports:
        return {"success": False, "error": f"Invalid port specification: {port_spec}"}
    return _run_scan(target, ports, max_threads, timeout)


def tcp_scan(target, ports=None, timeout=1.5, max_threads=50):
    """Standard TCP connect scan."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    result = _run_scan(target, ports, max_threads, timeout)
    result["scan_type"] = "TCP Connect"
    return result


def udp_scan(target, ports=None, timeout=3, max_threads=20):
    """UDP scan using socket."""
    if ports is None:
        ports = [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162,
                 445, 500, 514, 520, 631, 1434, 1900, 4500, 5353]

    results = {"open": [], "closed": [], "filtered": [], "target": target,
               "total": len(ports), "scan_type": "UDP"}

    def _scan_udp(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b"\x00", (target, port))
            try:
                data, _ = sock.recvfrom(1024)
                sock.close()
                return {"port": port, "state": "open", "service": COMMON_PORTS.get(port, "Unknown")}
            except socket.timeout:
                sock.close()
                return {"port": port, "state": "open|filtered", "service": COMMON_PORTS.get(port, "Unknown")}
        except (socket.error, OSError):
            return {"port": port, "state": "closed", "service": COMMON_PORTS.get(port, "Unknown")}

    with ThreadPoolExecutor(max_workers=min(max_threads, len(ports))) as executor:
        futures = {executor.submit(_scan_udp, p): p for p in ports}
        for future in as_completed(futures):
            r = future.result()
            if r["state"] == "open":
                results["open"].append(r)
            elif r["state"] == "open|filtered":
                results["filtered"].append(r)
            else:
                results["closed"].append(r)

    results["open"].sort(key=lambda x: x["port"])
    results["filtered"].sort(key=lambda x: x["port"])
    results["success"] = True
    return results


def _nmap_scan(target, scan_flag, ports=None, extra_args=None, timeout=120):
    """Generic nmap scan wrapper."""
    cmd = ["nmap", scan_flag, "-T4", "--open"]
    if ports:
        cmd.extend(["-p", ports])
    else:
        cmd.extend(["-p", "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,8080"])
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(target)

    result = {"success": False, "target": target, "scan_type": scan_flag,
              "open": [], "closed": [], "filtered": []}

    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, text=True)

        for line in proc.stdout.split("\n"):
            match = re.match(r"(\d+)/(\w+)\s+(\w+)\s+(.*)", line.strip())
            if match:
                port = int(match.group(1))
                proto = match.group(2)
                state = match.group(3)
                service = match.group(4).strip()

                entry = {"port": port, "protocol": proto, "service": service}
                if state == "open":
                    result["open"].append(entry)
                elif state == "filtered":
                    result["filtered"].append(entry)
                else:
                    result["closed"].append(entry)

        result["raw_output"] = proc.stdout
        result["success"] = True

    except FileNotFoundError:
        result = tcp_scan(target)
        result["scan_type"] = f"{scan_flag} (fallback to TCP connect)"
        result["note"] = "nmap not found, using TCP connect scan as fallback"
    except subprocess.TimeoutExpired:
        result["error"] = "Scan timed out"
    except PermissionError:
        result["error"] = "Permission denied (some scans require root)"

    return result


def syn_scan(target, ports=None):
    """SYN (half-open) scan using nmap."""
    port_str = ports if ports else None
    return _nmap_scan(target, "-sS", ports=port_str)


def ack_scan(target, ports=None):
    """ACK scan to detect filtered/unfiltered ports."""
    port_str = ports if ports else None
    return _nmap_scan(target, "-sA", ports=port_str)


def fin_scan(target, ports=None):
    """FIN scan."""
    port_str = ports if ports else None
    return _nmap_scan(target, "-sF", ports=port_str)


def null_scan(target, ports=None):
    """NULL scan (no flags set)."""
    port_str = ports if ports else None
    return _nmap_scan(target, "-sN", ports=port_str)


def xmas_scan(target, ports=None):
    """XMAS scan (FIN+PSH+URG)."""
    port_str = ports if ports else None
    return _nmap_scan(target, "-sX", ports=port_str)


def window_scan(target, ports=None):
    """Window scan."""
    port_str = ports if ports else None
    return _nmap_scan(target, "-sW", ports=port_str)


def idle_scan(target, zombie_host=None, ports=None):
    """Idle (zombie) scan."""
    if not zombie_host:
        return {"success": False, "error": "Idle scan requires a zombie host. Usage: idle <zombie_ip> [ports]"}
    extra = ["-sI", zombie_host]
    return _nmap_scan(target, "-Pn", ports=ports, extra_args=extra)


def fragment_scan(target, ports=None):
    """Fragment scan (split packets)."""
    port_str = ports if ports else None
    return _nmap_scan(target, "-sS", ports=port_str, extra_args=["-f"])


def adaptive_timing_scan(target, ports=None, timing=4):
    """Scan with adaptive timing (T0-T5)."""
    timing = max(0, min(5, timing))
    port_str = ports if ports else None
    return _nmap_scan(target, "-sS", ports=port_str,
                      extra_args=[f"-T{timing}", "--max-retries", "2"])


def _parse_port_spec(spec):
    """Parse port specification string into list of ports."""
    ports = set()
    try:
        parts = spec.replace(" ", "").split(",")
        for part in parts:
            if "-" in part:
                start, end = part.split("-", 1)
                start, end = int(start), int(end)
                if start < 1 or end > 65535 or start > end:
                    return []
                ports.update(range(start, end + 1))
            else:
                port = int(part)
                if port < 1 or port > 65535:
                    return []
                ports.add(port)
    except (ValueError, TypeError):
        return []
    return sorted(ports)
