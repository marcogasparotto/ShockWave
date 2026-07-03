"""SSL/TLS - Certificate viewer, validation, cipher enumeration,
TLS version detection, HSTS, ALPN, weak cipher detection, expiration checker."""

import re
import socket
import ssl
import subprocess
from datetime import datetime


def certificate_viewer(target, port=443, timeout=10):
    """View SSL/TLS certificate details."""
    result = {"success": False, "target": target, "port": port}

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=target)
        conn.settimeout(timeout)
        conn.connect((target, port))

        cert = conn.getpeercert(binary_form=False)
        cert_der = conn.getpeercert(binary_form=True)
        conn.close()

        if not cert:
            ctx2 = ssl.create_default_context()
            conn2 = ctx2.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=target)
            conn2.settimeout(timeout)
            try:
                conn2.connect((target, port))
                cert = conn2.getpeercert()
                conn2.close()
            except ssl.SSLError:
                conn2.close()

        if cert:
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))

            san = []
            for ext_type, ext_val in cert.get("subjectAltName", []):
                san.append(f"{ext_type}: {ext_val}")

            result.update({
                "success": True,
                "subject": subject,
                "issuer": issuer,
                "common_name": subject.get("commonName", "N/A"),
                "issuer_cn": issuer.get("commonName", "N/A"),
                "issuer_org": issuer.get("organizationName", "N/A"),
                "serial_number": cert.get("serialNumber", "N/A"),
                "version": cert.get("version", "N/A"),
                "not_before": cert.get("notBefore", "N/A"),
                "not_after": cert.get("notAfter", "N/A"),
                "san": san,
                "signature_algorithm": cert.get("signatureAlgorithm", "N/A"),
            })
        else:
            result["error"] = "Could not retrieve certificate"

    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except (socket.error, OSError) as e:
        result["error"] = f"Connection error: {e}"

    return result


def certificate_validation(target, port=443, timeout=10):
    """Validate SSL/TLS certificate."""
    result = {"success": False, "target": target, "port": port, "valid": False, "issues": []}

    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=target)
        conn.settimeout(timeout)
        conn.connect((target, port))

        cert = conn.getpeercert()
        conn.close()

        result["valid"] = True

        if cert:
            not_after = cert.get("notAfter", "")
            if not_after:
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.utcnow()).days
                    result["days_until_expiry"] = days_left
                    if days_left < 0:
                        result["issues"].append("Certificate has expired")
                        result["valid"] = False
                    elif days_left < 30:
                        result["issues"].append(f"Certificate expires in {days_left} days")
                except ValueError:
                    pass

            subject = dict(x[0] for x in cert.get("subject", []))
            cn = subject.get("commonName", "")
            if cn and cn != target and not cn.startswith("*."):
                san_names = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                if target not in san_names:
                    wildcard_match = False
                    for san in san_names:
                        if san.startswith("*.") and target.endswith(san[1:]):
                            wildcard_match = True
                            break
                    if not wildcard_match:
                        result["issues"].append(f"Hostname mismatch: CN={cn}")

        result["success"] = True

    except ssl.SSLCertVerificationError as e:
        result["error"] = str(e)
        result["issues"].append(str(e))
        result["success"] = True
    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result


def cipher_enumeration(target, port=443, timeout=10):
    """Enumerate supported SSL/TLS ciphers."""
    result = {"success": False, "target": target, "port": port, "ciphers": []}

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=target)
        conn.settimeout(timeout)
        conn.connect((target, port))

        negotiated = conn.cipher()
        if negotiated:
            result["negotiated_cipher"] = {
                "name": negotiated[0],
                "protocol": negotiated[1],
                "bits": negotiated[2],
            }

        result["ciphers"].append({
            "name": negotiated[0] if negotiated else "Unknown",
            "protocol": negotiated[1] if negotiated else "Unknown",
            "bits": negotiated[2] if negotiated else 0,
        })

        conn.close()

        try:
            proc = subprocess.run(
                ["openssl", "s_client", "-connect", f"{target}:{port}",
                 "-cipher", "ALL", "-brief"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=15, text=True,
                input="")
            if proc.stdout:
                cipher_match = re.search(r"Ciphersuite:\s*(\S+)", proc.stdout)
                if cipher_match:
                    result["openssl_cipher"] = cipher_match.group(1)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        result["success"] = True

    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result


def tls_version_detection(target, port=443, timeout=10):
    """Detect supported TLS versions."""
    result = {"success": False, "target": target, "port": port, "versions": {}}

    protocols = {
        "TLSv1.0": ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2 if hasattr(ssl.TLSVersion, "TLSv1_2") else None,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None,
    }

    for version_name, version_const in protocols.items():
        if version_const is None:
            result["versions"][version_name] = "Not available in Python SSL"
            continue

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version_const
            ctx.maximum_version = version_const

            conn = ctx.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=target)
            conn.settimeout(timeout)
            conn.connect((target, port))
            actual = conn.version()
            conn.close()
            result["versions"][version_name] = f"Supported ({actual})"
        except ssl.SSLError:
            result["versions"][version_name] = "Not supported"
        except (socket.error, OSError):
            result["versions"][version_name] = "Connection failed"

    result["success"] = True
    return result


def hsts_detection(target, port=443, timeout=10):
    """Detect HSTS (HTTP Strict Transport Security) header."""
    result = {"success": False, "target": target, "hsts_enabled": False}

    try:
        import http.client

        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(target, port, timeout=timeout, context=ctx)
        conn.request("HEAD", "/", headers={"Host": target})
        resp = conn.getresponse()

        headers = {k.lower(): v for k, v in resp.getheaders()}
        hsts = headers.get("strict-transport-security", "")

        if hsts:
            result["hsts_enabled"] = True
            result["hsts_header"] = hsts

            max_age_match = re.search(r"max-age=(\d+)", hsts)
            if max_age_match:
                result["max_age"] = int(max_age_match.group(1))
                result["max_age_days"] = int(max_age_match.group(1)) // 86400

            result["include_subdomains"] = "includesubdomains" in hsts.lower()
            result["preload"] = "preload" in hsts.lower()

        result["success"] = True
        conn.close()

    except (ssl.SSLError, socket.error, OSError) as e:
        result["error"] = str(e)

    return result


def alpn_detection(target, port=443, timeout=10):
    """Detect ALPN (Application-Layer Protocol Negotiation) support."""
    result = {"success": False, "target": target, "port": port, "alpn_protocols": []}

    alpn_list = ["h2", "http/1.1", "h2c", "spdy/3.1", "spdy/3"]

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(alpn_list)

        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=target)
        conn.settimeout(timeout)
        conn.connect((target, port))

        selected = conn.selected_alpn_protocol()
        if selected:
            result["selected_protocol"] = selected
            result["alpn_protocols"].append(selected)

        result["http2_supported"] = selected == "h2"
        result["success"] = True
        conn.close()

    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result


WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "RC2", "IDEA", "SEED", "CAMELLIA128",
]


def weak_cipher_detection(target, port=443, timeout=10):
    """Check for weak ciphers."""
    result = {"success": False, "target": target, "port": port,
              "weak_ciphers_found": [], "is_secure": True}

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=target)
        conn.settimeout(timeout)
        conn.connect((target, port))

        cipher = conn.cipher()
        conn.close()

        if cipher:
            cipher_name = cipher[0]
            bits = cipher[2]

            for weak in WEAK_CIPHERS:
                if weak.upper() in cipher_name.upper():
                    result["weak_ciphers_found"].append({
                        "cipher": cipher_name,
                        "reason": f"Uses {weak}",
                    })
                    result["is_secure"] = False

            if bits < 128:
                result["weak_ciphers_found"].append({
                    "cipher": cipher_name,
                    "reason": f"Key length too short: {bits} bits",
                })
                result["is_secure"] = False

            result["current_cipher"] = cipher_name
            result["current_bits"] = bits
            result["current_protocol"] = cipher[1]

        result["success"] = True

    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result


def expiration_checker(target, port=443, timeout=10):
    """Check certificate expiration status."""
    result = {"success": False, "target": target, "port": port}

    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=target)
        conn.settimeout(timeout)
        conn.connect((target, port))

        cert = conn.getpeercert()
        conn.close()

        if cert:
            not_before = cert.get("notBefore", "")
            not_after = cert.get("notAfter", "")

            result["not_before"] = not_before
            result["not_after"] = not_after

            if not_after:
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.utcnow()
                    delta = expiry - now
                    result["days_remaining"] = delta.days
                    result["expired"] = delta.days < 0

                    if delta.days < 0:
                        result["status"] = "EXPIRED"
                    elif delta.days < 7:
                        result["status"] = "CRITICAL"
                    elif delta.days < 30:
                        result["status"] = "WARNING"
                    elif delta.days < 90:
                        result["status"] = "ATTENTION"
                    else:
                        result["status"] = "OK"

                    result["expiry_date"] = expiry.strftime("%Y-%m-%d %H:%M:%S UTC")
                except ValueError:
                    result["status"] = "PARSE_ERROR"

            subject = dict(x[0] for x in cert.get("subject", []))
            result["common_name"] = subject.get("commonName", "N/A")
            result["success"] = True
        else:
            result["error"] = "No certificate found"

    except ssl.SSLCertVerificationError as e:
        result["error"] = str(e)
        result["status"] = "VALIDATION_ERROR"
        result["success"] = True
    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result
