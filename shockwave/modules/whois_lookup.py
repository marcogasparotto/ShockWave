"""WHOIS Lookup - query via socket on port 43."""

import socket


WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "us": "whois.nic.us",
    "uk": "whois.nic.uk",
    "br": "whois.registro.br",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "eu": "whois.eu",
    "ru": "whois.tcinet.ru",
    "jp": "whois.jprs.jp",
    "cn": "whois.cnnic.cn",
    "in": "whois.registry.in",
}

DEFAULT_WHOIS_SERVER = "whois.iana.org"


def whois_lookup(target):
    """Perform a WHOIS lookup using raw socket on port 43."""
    tld = target.rsplit(".", 1)[-1].lower() if "." in target else ""
    whois_server = WHOIS_SERVERS.get(tld, DEFAULT_WHOIS_SERVER)

    result = {
        "success": False,
        "target": target,
        "whois_server": whois_server,
        "raw": "",
        "parsed": {},
    }

    try:
        raw_data = _query_whois(whois_server, target)
        result["raw"] = raw_data
        result["parsed"] = _parse_whois(raw_data)

        if result["parsed"].get("refer") or result["parsed"].get("whois"):
            referral_server = result["parsed"].get("refer") or result["parsed"].get("whois")
            referral_server = referral_server.strip()
            if referral_server != whois_server:
                try:
                    raw_data2 = _query_whois(referral_server, target)
                    result["raw"] = raw_data2
                    result["parsed"] = _parse_whois(raw_data2)
                    result["whois_server"] = referral_server
                except (socket.error, socket.timeout):
                    pass

        result["success"] = True
    except socket.timeout:
        result["error"] = "Connection timed out"
    except socket.error as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)

    return result


def _query_whois(server, query, port=43, timeout=10):
    """Send a WHOIS query to a server on port 43."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((server, port))
    sock.send((query + "\r\n").encode())

    response = b""
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        except socket.timeout:
            break

    sock.close()
    return response.decode("utf-8", errors="replace")


def _parse_whois(raw):
    """Parse WHOIS raw response into key-value pairs."""
    parsed = {}
    for line in raw.split("\n"):
        line = line.strip()
        if ":" in line and not line.startswith("%") and not line.startswith("#"):
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key and value:
                if key in parsed:
                    if isinstance(parsed[key], list):
                        parsed[key].append(value)
                    else:
                        parsed[key] = [parsed[key], value]
                else:
                    parsed[key] = value
    return parsed
