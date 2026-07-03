"""Network Discovery - ARP scan, TCP/UDP host discovery, CIDR scanner,
gateway detection, MAC address discovery, vendor identification, reverse DNS."""

import re
import socket
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed


# ---- OUI vendor database (common prefixes) --------------------------------

OUI_DATABASE = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1C:42": "Parallels",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:16:3E": "Xen",
    "00:15:5D": "Microsoft Hyper-V",
    "00:03:FF": "Microsoft Hyper-V",
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:1E:06": "Wibrain",
    "FC:F5:28": "ZyXEL",
    "00:23:24": "Cisco",
    "00:25:45": "Cisco",
    "00:1B:2A": "Cisco",
    "00:0A:F7": "Broadcom",
    "00:10:18": "Broadcom",
    "14:CC:20": "TP-Link",
    "50:C7:BF": "TP-Link",
    "AC:84:C6": "TP-Link",
    "00:14:6C": "Netgear",
    "C0:3F:0E": "Netgear",
    "28:80:23": "Netgear",
    "00:24:B2": "Netgear",
    "F0:9F:C2": "Ubiquiti",
    "68:D7:9A": "Ubiquiti",
    "24:5A:4C": "Ubiquiti",
    "00:1F:33": "Netgear",
    "00:17:88": "Philips Hue",
    "B0:CE:18": "Intel",
    "00:1B:21": "Intel",
    "3C:97:0E": "Intel",
    "F4:8E:38": "Intel",
    "3C:22:FB": "Apple",
    "A4:83:E7": "Apple",
    "AC:DE:48": "Apple",
    "00:CD:FE": "Apple",
    "F0:18:98": "Apple",
    "7C:D1:C3": "Apple",
    "00:1A:2B": "Ayecom",
    "00:25:00": "Apple",
    "D8:BB:C1": "Samsung",
    "BC:14:01": "Samsung",
    "00:21:19": "Samsung",
    "F8:04:2E": "Samsung",
    "44:65:0D": "Amazon",
    "74:C2:46": "Amazon",
    "A0:02:DC": "Amazon",
    "40:B4:CD": "Amazon",
    "18:FE:34": "Espressif (ESP8266/ESP32)",
    "24:0A:C4": "Espressif (ESP8266/ESP32)",
    "30:AE:A4": "Espressif (ESP8266/ESP32)",
    "AC:67:B2": "Espressif (ESP8266/ESP32)",
    "84:CC:A8": "Espressif (ESP8266/ESP32)",
}


def reverse_dns(ip):
    """Perform reverse DNS lookup on an IP address."""
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        return {
            "success": True,
            "ip": ip,
            "hostname": hostname,
            "aliases": aliases,
        }
    except socket.herror as e:
        return {"success": False, "ip": ip, "error": str(e)}
    except socket.gaierror as e:
        return {"success": False, "ip": ip, "error": str(e)}


def arp_scan(interface=None):
    """Perform ARP scan on the local network."""
    result = {"success": False, "hosts": [], "interface": interface}

    try:
        cmd = ["arp", "-a"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=15, text=True)
        if proc.returncode == 0:
            for line in proc.stdout.strip().split("\n"):
                match = re.search(
                    r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)", line)
                if match:
                    ip_addr = match.group(1)
                    mac = match.group(2).upper()
                    hostname_m = re.match(r"(\S+)\s+\(", line)
                    hostname = hostname_m.group(1) if hostname_m else ""
                    vendor = identify_vendor(mac)
                    result["hosts"].append({
                        "ip": ip_addr,
                        "mac": mac,
                        "hostname": hostname,
                        "vendor": vendor,
                    })
            result["success"] = True
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        result["error"] = str(e)

    return result


def tcp_host_discovery(target, ports=None, timeout=2, max_threads=50):
    """Discover live hosts by attempting TCP connections on common ports."""
    if ports is None:
        ports = [80, 443, 22, 21, 25, 8080, 3389]

    result = {"success": False, "target": target, "alive": False, "open_ports": []}

    def _try_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            code = sock.connect_ex((target, port))
            sock.close()
            return port if code == 0 else None
        except (socket.error, OSError):
            return None

    with ThreadPoolExecutor(max_workers=min(max_threads, len(ports))) as executor:
        futures = {executor.submit(_try_port, p): p for p in ports}
        for future in as_completed(futures):
            port = future.result()
            if port is not None:
                result["open_ports"].append(port)

    result["open_ports"].sort()
    result["alive"] = len(result["open_ports"]) > 0
    result["success"] = True
    return result


def udp_host_discovery(target, ports=None, timeout=3):
    """Discover hosts via UDP probes (ICMP unreachable = alive)."""
    if ports is None:
        ports = [53, 123, 161, 500, 514, 1900]

    result = {"success": False, "target": target, "alive": False, "responded_ports": []}

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b"\x00", (target, port))
            try:
                data, addr = sock.recvfrom(1024)
                result["responded_ports"].append(port)
            except socket.timeout:
                pass
            sock.close()
        except (socket.error, OSError):
            pass

    result["alive"] = len(result["responded_ports"]) > 0
    result["success"] = True
    return result


def cidr_scan(cidr, timeout=1, max_threads=100):
    """Scan a CIDR range for live hosts using ping."""
    result = {"success": False, "cidr": cidr, "alive": [], "total": 0}

    try:
        network, prefix_len = cidr.rsplit("/", 1)
        prefix_len = int(prefix_len)
        if prefix_len < 16 or prefix_len > 32:
            result["error"] = "Prefix length must be between /16 and /32"
            return result

        parts = list(map(int, network.split(".")))
        ip_int = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        network_addr = ip_int & mask
        broadcast = network_addr | (~mask & 0xFFFFFFFF)

        ips = []
        for addr in range(network_addr + 1, broadcast):
            ip_str = f"{(addr >> 24) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 8) & 0xFF}.{addr & 0xFF}"
            ips.append(ip_str)

        if len(ips) > 1024:
            ips = ips[:1024]

        result["total"] = len(ips)

        def _ping_ip(ip):
            try:
                proc = subprocess.run(
                    ["ping", "-c", "1", "-W", str(timeout), ip],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=timeout + 2)
                return ip if proc.returncode == 0 else None
            except (subprocess.TimeoutExpired, Exception):
                return None

        with ThreadPoolExecutor(max_workers=min(max_threads, len(ips))) as executor:
            futures = {executor.submit(_ping_ip, ip): ip for ip in ips}
            for future in as_completed(futures):
                ip = future.result()
                if ip:
                    result["alive"].append(ip)

        result["alive"].sort(key=lambda x: list(map(int, x.split("."))))
        result["success"] = True
    except (ValueError, IndexError) as e:
        result["error"] = f"Invalid CIDR notation: {e}"

    return result


def gateway_detection():
    """Detect the default gateway."""
    result = {"success": False, "gateways": []}
    try:
        proc = subprocess.run(
            ["ip", "route", "show", "default"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=5, text=True)
        if proc.returncode == 0:
            for line in proc.stdout.strip().split("\n"):
                match = re.search(r"default via (\S+) dev (\S+)", line)
                if match:
                    result["gateways"].append({
                        "gateway": match.group(1),
                        "interface": match.group(2),
                    })
            result["success"] = True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        try:
            proc = subprocess.run(
                ["route", "-n"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=5, text=True)
            if proc.returncode == 0:
                for line in proc.stdout.strip().split("\n"):
                    parts = line.split()
                    if len(parts) >= 8 and parts[0] == "0.0.0.0":
                        result["gateways"].append({
                            "gateway": parts[1],
                            "interface": parts[7],
                        })
                result["success"] = True
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            result["error"] = str(e)

    return result


def network_interface_discovery():
    """Discover all network interfaces and their configuration."""
    result = {"success": False, "interfaces": []}
    try:
        proc = subprocess.run(
            ["ip", "-o", "addr", "show"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=5, text=True)
        if proc.returncode == 0:
            for line in proc.stdout.strip().split("\n"):
                match = re.match(
                    r"\d+:\s+(\S+)\s+inet6?\s+(\S+)", line)
                if match:
                    iface = match.group(1)
                    addr = match.group(2)
                    result["interfaces"].append({
                        "interface": iface,
                        "address": addr,
                    })
            result["success"] = True
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        result["error"] = str(e)

    return result


def mac_address_discovery(target):
    """Discover MAC address for a target IP via ARP table."""
    result = {"success": False, "target": target, "mac": None, "vendor": None}

    try:
        proc = subprocess.run(
            ["arp", "-n", target],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=5, text=True)
        if proc.returncode == 0:
            match = re.search(r"([0-9a-fA-F:]{17})", proc.stdout)
            if match:
                mac = match.group(1).upper()
                result["mac"] = mac
                result["vendor"] = identify_vendor(mac)
                result["success"] = True
            else:
                result["error"] = "MAC address not found in ARP table"
        else:
            result["error"] = "ARP lookup failed"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        try:
            subprocess.run(
                ["ping", "-c", "1", "-W", "1", target],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=3)
            proc = subprocess.run(
                ["arp", "-n", target],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=5, text=True)
            match = re.search(r"([0-9a-fA-F:]{17})", proc.stdout)
            if match:
                mac = match.group(1).upper()
                result["mac"] = mac
                result["vendor"] = identify_vendor(mac)
                result["success"] = True
            else:
                result["error"] = "MAC not found after ping"
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            result["error"] = str(e)

    return result


def identify_vendor(mac_address):
    """Identify vendor from MAC address using OUI prefix."""
    mac_clean = mac_address.upper().replace("-", ":")
    prefix = mac_clean[:8]
    return OUI_DATABASE.get(prefix, "Unknown")
