"""Local Network Info - local IP and public IP."""

import socket
import http.client
import json


def get_local_network_info():
    """Get local and public network information."""
    result = {
        "success": True,
        "local_ip": _get_local_ip(),
        "public_ip": _get_public_ip(),
        "hostname": _get_hostname(),
        "interfaces": _get_interfaces(),
    }
    return result


def _get_local_ip():
    """Get the local IP address."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except (socket.error, OSError):
        return "127.0.0.1"


def _get_public_ip():
    """Get the public IP address."""
    services = [
        ("api.ipify.org", "/"),
        ("ifconfig.me", "/ip"),
        ("icanhazip.com", "/"),
    ]

    for host, path in services:
        try:
            conn = http.client.HTTPSConnection(host, timeout=5)
            conn.request("GET", path, headers={"User-Agent": "Shockwave/0.1.0"})
            response = conn.getresponse()
            if response.status == 200:
                ip = response.read().decode().strip()
                conn.close()
                return ip
            conn.close()
        except (socket.error, OSError):
            continue

    return "N/A"


def _get_hostname():
    """Get the local hostname."""
    try:
        return socket.gethostname()
    except Exception:
        return "N/A"


def _get_interfaces():
    """Get network interface information."""
    interfaces = []
    try:
        import subprocess
        result = subprocess.run(
            ["ip", "addr", "show"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            text=True,
        )
        if result.returncode == 0:
            current_iface = None
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line and line[0].isdigit() and ":" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        current_iface = parts[1].strip()
                elif "inet " in line and current_iface:
                    ip_part = line.split("inet ")[1].split()[0]
                    interfaces.append({
                        "interface": current_iface,
                        "ip": ip_part,
                    })
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return interfaces
