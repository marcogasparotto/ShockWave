"""Fingerprinting - OS detection, device type, TCP/IP stack analysis,
TTL analysis, MSS analysis, window size analysis."""

import re
import socket
import struct
import subprocess


TTL_SIGNATURES = {
    (60, 64): "Linux/Unix/macOS",
    (120, 128): "Windows",
    (250, 255): "Cisco/Network Device",
    (30, 32): "Embedded/IoT",
}


def os_detection(target, timeout=5):
    """Detect operating system via TTL and TCP characteristics."""
    result = {"success": False, "target": target, "os_guess": None, "confidence": "low"}

    ttl_info = ttl_analysis(target, timeout=timeout)
    if ttl_info["success"]:
        result["ttl"] = ttl_info["ttl"]
        result["os_guess"] = ttl_info["os_guess"]
        result["confidence"] = ttl_info["confidence"]

    tcp_info = tcp_stack_analysis(target, timeout=timeout)
    if tcp_info["success"]:
        result["tcp_details"] = tcp_info

        if tcp_info.get("os_hints"):
            if result["os_guess"] and tcp_info["os_hints"][0] in result["os_guess"]:
                result["confidence"] = "high"
            elif not result["os_guess"]:
                result["os_guess"] = tcp_info["os_hints"][0]
                result["confidence"] = "medium"

    mss_info = mss_analysis(target, timeout=timeout)
    if mss_info["success"]:
        result["mss"] = mss_info.get("mss")

    result["success"] = bool(result["os_guess"])
    return result


def device_type_detection(target, timeout=5):
    """Attempt to detect the device type."""
    result = {"success": False, "target": target, "device_type": "Unknown"}

    ttl_info = ttl_analysis(target, timeout=timeout)
    os_guess = ttl_info.get("os_guess", "") if ttl_info["success"] else ""

    common_ports = {}
    check_ports = [22, 23, 80, 443, 8080, 161, 179, 1883, 8443, 9100, 3389, 5900]

    for port in check_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            code = sock.connect_ex((target, port))
            common_ports[port] = (code == 0)
            sock.close()
        except (socket.error, OSError):
            common_ports[port] = False

    if common_ports.get(179):
        result["device_type"] = "Router"
        result["confidence"] = "high"
    elif common_ports.get(161) and common_ports.get(23) and not common_ports.get(22):
        result["device_type"] = "Network Switch"
        result["confidence"] = "medium"
    elif common_ports.get(9100):
        result["device_type"] = "Printer"
        result["confidence"] = "high"
    elif common_ports.get(1883):
        result["device_type"] = "IoT Device"
        result["confidence"] = "medium"
    elif common_ports.get(3389) and "Windows" in os_guess:
        result["device_type"] = "Windows Server/Desktop"
        result["confidence"] = "high"
    elif common_ports.get(22) and common_ports.get(80):
        if "Linux" in os_guess:
            result["device_type"] = "Linux Server"
            result["confidence"] = "high"
        else:
            result["device_type"] = "Server"
            result["confidence"] = "medium"
    elif common_ports.get(80) or common_ports.get(443):
        result["device_type"] = "Web Server"
        result["confidence"] = "medium"
    elif common_ports.get(22):
        result["device_type"] = "Server/Appliance"
        result["confidence"] = "low"
    else:
        result["device_type"] = "Unknown"
        result["confidence"] = "low"

    result["os_guess"] = os_guess
    result["open_ports"] = [p for p, o in common_ports.items() if o]
    result["success"] = True
    return result


def tcp_stack_analysis(target, port=80, timeout=5):
    """Analyze TCP/IP stack characteristics."""
    result = {"success": False, "target": target, "os_hints": []}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex((target, port))

        if code != 0:
            for alt_port in [443, 22, 8080]:
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(timeout)
                code = sock2.connect_ex((target, alt_port))
                if code == 0:
                    sock = sock2
                    port = alt_port
                    break
                sock2.close()

        if code == 0:
            result["port"] = port
            result["connection_established"] = True

            try:
                proc = subprocess.run(
                    ["ping", "-c", "1", "-W", str(timeout), target],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=timeout + 2, text=True)

                ttl_match = re.search(r"ttl=(\d+)", proc.stdout, re.IGNORECASE)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    result["ttl"] = ttl

                    if 60 <= ttl <= 64:
                        result["os_hints"].append("Linux/Unix/macOS")
                    elif 120 <= ttl <= 128:
                        result["os_hints"].append("Windows")
                    elif 250 <= ttl <= 255:
                        result["os_hints"].append("Network Device")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            result["success"] = True

        sock.close()

    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result


def ttl_analysis(target, count=3, timeout=5):
    """Analyze TTL values from ping responses."""
    result = {"success": False, "target": target, "ttl": None, "os_guess": None}

    try:
        proc = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), target],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=count * timeout + 5, text=True)

        ttl_values = [int(m) for m in re.findall(r"ttl=(\d+)", proc.stdout, re.IGNORECASE)]

        if ttl_values:
            avg_ttl = sum(ttl_values) / len(ttl_values)
            result["ttl"] = int(avg_ttl)
            result["ttl_values"] = ttl_values
            result["ttl_consistent"] = len(set(ttl_values)) == 1

            initial_ttl = None
            if avg_ttl <= 64:
                initial_ttl = 64
            elif avg_ttl <= 128:
                initial_ttl = 128
            elif avg_ttl <= 255:
                initial_ttl = 255

            result["estimated_initial_ttl"] = initial_ttl
            result["estimated_hops"] = initial_ttl - int(avg_ttl) if initial_ttl else None

            for (low, high), os_name in TTL_SIGNATURES.items():
                if low <= avg_ttl <= high:
                    result["os_guess"] = os_name
                    result["confidence"] = "high"
                    break

            if not result["os_guess"]:
                if avg_ttl <= 64:
                    result["os_guess"] = "Linux/Unix/macOS"
                    result["confidence"] = "medium"
                elif avg_ttl <= 128:
                    result["os_guess"] = "Windows"
                    result["confidence"] = "medium"
                else:
                    result["os_guess"] = "Network Device/Unknown"
                    result["confidence"] = "low"

            result["success"] = True
        else:
            result["error"] = "No TTL values in ping response"

    except subprocess.TimeoutExpired:
        result["error"] = "Ping timed out"
    except FileNotFoundError:
        result["error"] = "ping command not found"

    return result


def mss_analysis(target, port=80, timeout=5):
    """Analyze Maximum Segment Size."""
    result = {"success": False, "target": target}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex((target, port))

        if code == 0:
            try:
                mss = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
                result["mss"] = mss
                result["port"] = port

                if mss == 1460:
                    result["notes"] = "Standard Ethernet MSS (MTU 1500)"
                elif mss == 1220:
                    result["notes"] = "IPv6 typical MSS"
                elif mss == 536:
                    result["notes"] = "Minimum MSS (RFC 791)"
                elif mss == 1380:
                    result["notes"] = "VPN/Tunnel overhead likely"
                elif mss < 536:
                    result["notes"] = "Unusual MSS - possible tunneling"
                else:
                    result["notes"] = f"MSS {mss} bytes"

                result["success"] = True
            except (socket.error, OSError):
                result["error"] = "Cannot read MSS from socket"
        else:
            result["error"] = f"Port {port} closed"

        sock.close()

    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result


def window_size_analysis(target, port=80, timeout=5):
    """Analyze TCP window size for OS fingerprinting."""
    result = {"success": False, "target": target, "window_size": None}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex((target, port))

        if code == 0:
            try:
                rcvbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                sndbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)

                result["recv_buffer"] = rcvbuf
                result["send_buffer"] = sndbuf

                if rcvbuf == 65535:
                    result["os_hint"] = "Windows (default)"
                elif rcvbuf == 87380:
                    result["os_hint"] = "Linux (older kernel)"
                elif rcvbuf >= 131072:
                    result["os_hint"] = "Linux (modern kernel with auto-tuning)"
                elif rcvbuf == 32768:
                    result["os_hint"] = "FreeBSD/OpenBSD"
                else:
                    result["os_hint"] = "Unknown"

                result["success"] = True
            except (socket.error, OSError):
                result["error"] = "Cannot read window size"
        else:
            result["error"] = f"Port {port} closed"

        sock.close()

    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result
