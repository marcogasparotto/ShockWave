"""Port Scanner - scan common and custom port ranges with threads."""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def _scan_port(target, port, timeout=1.5):
    """Scan a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()

        service = COMMON_PORTS.get(port, "Unknown")
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = COMMON_PORTS.get(port, "Unknown")

        return {
            "port": port,
            "open": result == 0,
            "service": service,
        }
    except (socket.timeout, socket.error):
        return {"port": port, "open": False, "service": COMMON_PORTS.get(port, "Unknown")}


def scan_common_ports(target, max_threads=50, timeout=1.5):
    """Scan common ports on the target."""
    results = {"open": [], "closed": [], "target": target, "total": len(COMMON_PORTS)}

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(_scan_port, target, port, timeout): port
            for port in COMMON_PORTS
        }
        for future in as_completed(futures):
            result = future.result()
            if result["open"]:
                results["open"].append(result)
            else:
                results["closed"].append(result)

    results["open"].sort(key=lambda x: x["port"])
    results["success"] = True
    return results


def scan_custom_ports(target, port_spec, max_threads=100, timeout=1.5):
    """Scan custom port range.

    Args:
        target: Host to scan
        port_spec: Port specification (e.g., '1-1024', '22,80,443', '1-100,443,8080')
    """
    ports = _parse_port_spec(port_spec)
    if not ports:
        return {"success": False, "error": f"Invalid port specification: {port_spec}"}

    results = {"open": [], "closed": [], "target": target, "total": len(ports)}

    with ThreadPoolExecutor(max_workers=min(max_threads, len(ports))) as executor:
        futures = {
            executor.submit(_scan_port, target, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            result = future.result()
            if result["open"]:
                results["open"].append(result)
            else:
                results["closed"].append(result)

    results["open"].sort(key=lambda x: x["port"])
    results["success"] = True
    return results


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
