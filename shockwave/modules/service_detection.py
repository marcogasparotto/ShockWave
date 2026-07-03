"""Service Detection - Banner grabbing, service/version detection,
protocol-specific detectors (HTTP, SSH, FTP, SMTP, SMB, SNMP, DB, MQTT, Redis)."""

import re
import socket
import struct


def banner_grab(target, port, timeout=5):
    """Grab the banner from a service."""
    result = {"success": False, "target": target, "port": port, "banner": None}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        try:
            banner = sock.recv(4096).decode("utf-8", errors="replace").strip()
        except socket.timeout:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n".format(target.encode()))
            try:
                banner = sock.recv(4096).decode("utf-8", errors="replace").strip()
            except socket.timeout:
                banner = ""

        sock.close()

        if banner:
            result["banner"] = banner
            result["success"] = True
        else:
            result["error"] = "No banner received"

    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result


def service_detection(target, ports=None, timeout=3):
    """Detect services running on specified ports."""
    if ports is None:
        ports = [21, 22, 25, 53, 80, 110, 143, 443, 993, 995,
                 3306, 5432, 6379, 8080, 8443, 27017]

    result = {"success": False, "target": target, "services": []}

    for port in ports:
        svc = _detect_service_on_port(target, port, timeout)
        if svc:
            result["services"].append(svc)

    result["success"] = True
    result["total_detected"] = len(result["services"])
    return result


def _detect_service_on_port(target, port, timeout=3):
    """Detect the service running on a specific port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex((target, port))
        if code != 0:
            sock.close()
            return None

        banner = ""
        try:
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        except socket.timeout:
            pass

        sock.close()

        service = _identify_service(port, banner)
        return {
            "port": port,
            "service": service["name"],
            "version": service.get("version", ""),
            "banner": banner[:200] if banner else "",
        }
    except (socket.error, OSError):
        return None


def _identify_service(port, banner):
    """Identify service from port number and banner."""
    banner_lower = banner.lower() if banner else ""

    if "ssh" in banner_lower:
        version = re.search(r"SSH-[\d.]+-(\S+)", banner)
        return {"name": "SSH", "version": version.group(1) if version else ""}
    if "ftp" in banner_lower:
        return {"name": "FTP", "version": banner.split("\n")[0] if banner else ""}
    if "smtp" in banner_lower or "mail" in banner_lower:
        return {"name": "SMTP", "version": banner.split("\n")[0] if banner else ""}
    if "http" in banner_lower:
        server = re.search(r"Server:\s*(.+)", banner, re.IGNORECASE)
        return {"name": "HTTP", "version": server.group(1).strip() if server else ""}
    if "mysql" in banner_lower:
        return {"name": "MySQL", "version": ""}
    if "redis" in banner_lower or banner.startswith("-") or banner.startswith("+"):
        return {"name": "Redis", "version": ""}
    if "postgresql" in banner_lower:
        return {"name": "PostgreSQL", "version": ""}
    if "mongodb" in banner_lower:
        return {"name": "MongoDB", "version": ""}

    known_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
        27017: "MongoDB", 1883: "MQTT", 8883: "MQTTS",
    }

    return {"name": known_ports.get(port, "Unknown"), "version": ""}


def version_detection(target, port, timeout=5):
    """Attempt detailed version detection for a service."""
    result = {"success": False, "target": target, "port": port, "service": None, "version": None}

    probes = [
        b"",
        b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
        b"EHLO shockwave\r\n",
        b"USER anonymous\r\n",
        b"HELP\r\n",
    ]

    for probe in probes:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))

            if probe:
                sock.send(probe.replace(b"target", target.encode()))

            banner = sock.recv(4096).decode("utf-8", errors="replace").strip()
            sock.close()

            if banner:
                svc = _identify_service(port, banner)
                result["service"] = svc["name"]
                result["version"] = svc.get("version", banner[:100])
                result["banner"] = banner[:500]
                result["success"] = True
                return result
        except (socket.error, OSError):
            pass

    return result


def http_detection(target, port=80, timeout=5):
    """Detect HTTP service details."""
    result = {"success": False, "target": target, "port": port}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        sock.send(request.encode())
        response = sock.recv(4096).decode("utf-8", errors="replace")
        sock.close()

        status_match = re.match(r"HTTP/(\S+)\s+(\d+)\s+(.*)", response)
        if status_match:
            result["http_version"] = status_match.group(1)
            result["status_code"] = int(status_match.group(2))
            result["status_text"] = status_match.group(3).strip()

        headers = {}
        for line in response.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        result["headers"] = headers
        result["server"] = headers.get("Server", "Unknown")
        result["success"] = True

    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result


def ssh_detection(target, port=22, timeout=5):
    """Detect SSH service and version."""
    result = {"success": False, "target": target, "port": port}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        sock.close()

        if banner.startswith("SSH-"):
            parts = banner.split("-", 2)
            result["protocol_version"] = parts[1] if len(parts) > 1 else ""
            result["software"] = parts[2] if len(parts) > 2 else ""
            result["banner"] = banner
            result["success"] = True
        else:
            result["error"] = "Not an SSH service"

    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result


def ftp_detection(target, port=21, timeout=5):
    """Detect FTP service and version."""
    result = {"success": False, "target": target, "port": port}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        sock.close()

        if banner:
            result["banner"] = banner
            result["anonymous_possible"] = "anonymous" in banner.lower()
            result["success"] = True
        else:
            result["error"] = "No FTP banner received"

    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result


def smtp_detection(target, port=25, timeout=5):
    """Detect SMTP service and capabilities."""
    result = {"success": False, "target": target, "port": port, "capabilities": []}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()

        result["banner"] = banner

        sock.send(b"EHLO shockwave.local\r\n")
        ehlo_response = sock.recv(4096).decode("utf-8", errors="replace").strip()

        for line in ehlo_response.split("\n"):
            line = line.strip()
            if line.startswith("250-") or line.startswith("250 "):
                cap = line[4:].strip()
                if cap:
                    result["capabilities"].append(cap)

        result["supports_starttls"] = any("STARTTLS" in c for c in result["capabilities"])
        result["supports_auth"] = any("AUTH" in c for c in result["capabilities"])

        sock.send(b"QUIT\r\n")
        sock.close()

        result["success"] = True

    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result


def smb_detection(target, port=445, timeout=5):
    """Detect SMB service."""
    result = {"success": False, "target": target, "port": port}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex((target, port))

        if code == 0:
            result["port_open"] = True
            result["service"] = "SMB"

            try:
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(timeout)
                sock2.connect_ex((target, 139))
                result["netbios_port_open"] = True
                sock2.close()
            except (socket.error, OSError):
                result["netbios_port_open"] = False

            result["success"] = True
        else:
            result["error"] = "Port closed"

        sock.close()

    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result


def snmp_detection(target, port=161, community="public", timeout=3):
    """Detect SNMP service with a simple GET request."""
    result = {"success": False, "target": target, "port": port}

    snmp_get = bytes([
        0x30, 0x29,
        0x02, 0x01, 0x01,
        0x04, len(community),
    ]) + community.encode() + bytes([
        0xa0, 0x1c,
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x01, 0x00,
        0x02, 0x01, 0x00,
        0x30, 0x0e,
        0x30, 0x0c,
        0x06, 0x08,
        0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
        0x05, 0x00,
    ])

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(snmp_get, (target, port))

        data, addr = sock.recvfrom(4096)
        sock.close()

        if data:
            result["response_size"] = len(data)
            result["community_accepted"] = True
            result["success"] = True

    except socket.timeout:
        result["error"] = "No SNMP response (timeout)"
    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result


def database_detection(target, timeout=3):
    """Detect common database services."""
    result = {"success": False, "target": target, "databases": []}

    db_ports = {
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        1521: "Oracle",
        27017: "MongoDB",
        6379: "Redis",
        9042: "Cassandra",
        5984: "CouchDB",
        7474: "Neo4j",
        9200: "Elasticsearch",
        8529: "ArangoDB",
    }

    for port, name in db_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            code = sock.connect_ex((target, port))
            if code == 0:
                banner = ""
                try:
                    banner = sock.recv(512).decode("utf-8", errors="replace").strip()
                except socket.timeout:
                    pass
                result["databases"].append({
                    "port": port,
                    "service": name,
                    "banner": banner[:100] if banner else "",
                })
            sock.close()
        except (socket.error, OSError):
            pass

    result["success"] = True
    result["found"] = len(result["databases"])
    return result


def mqtt_detection(target, port=1883, timeout=5):
    """Detect MQTT service."""
    result = {"success": False, "target": target, "port": port}

    connect_packet = bytes([
        0x10,
        0x10,
        0x00, 0x04,
    ]) + b"MQTT" + bytes([
        0x04,
        0x02,
        0x00, 0x3c,
        0x00, 0x06,
    ]) + b"shockw"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        sock.send(connect_packet)

        response = sock.recv(4096)
        sock.close()

        if response and len(response) >= 4:
            if response[0] == 0x20:
                return_code = response[3] if len(response) > 3 else -1
                result["connack_received"] = True
                result["return_code"] = return_code
                result["accepted"] = return_code == 0
                result["success"] = True
            else:
                result["error"] = "Unexpected response"
        else:
            result["error"] = "No valid MQTT response"

    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result


def redis_detection(target, port=6379, timeout=3):
    """Detect Redis service."""
    result = {"success": False, "target": target, "port": port}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        sock.send(b"PING\r\n")
        response = sock.recv(1024).decode("utf-8", errors="replace").strip()

        if "+PONG" in response:
            result["authenticated"] = False
            result["response"] = "PONG"
            result["success"] = True

            sock.send(b"INFO server\r\n")
            info = sock.recv(4096).decode("utf-8", errors="replace")

            version_match = re.search(r"redis_version:(\S+)", info)
            if version_match:
                result["version"] = version_match.group(1)

            mode_match = re.search(r"redis_mode:(\S+)", info)
            if mode_match:
                result["mode"] = mode_match.group(1)

        elif "-NOAUTH" in response or "-ERR" in response:
            result["authenticated"] = True
            result["requires_auth"] = True
            result["success"] = True

        sock.send(b"QUIT\r\n")
        sock.close()

    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result
