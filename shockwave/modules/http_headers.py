"""HTTP Headers - server fingerprinting via response headers."""

import http.client
import ssl
import socket


def get_http_headers(target, port=None, use_https=True):
    """Get HTTP response headers from a target.

    Args:
        target: Hostname or IP to query
        port: Port number (default: 443 for HTTPS, 80 for HTTP)
        use_https: Whether to use HTTPS (default: True)
    """
    results = {"success": False, "target": target, "headers": {}, "status": None}

    if use_https:
        actual_port = port or 443
        try:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(target, actual_port, timeout=10, context=ctx)
            conn.request("HEAD", "/")
            response = conn.getresponse()
            results["headers"] = dict(response.getheaders())
            results["status"] = response.status
            results["status_reason"] = response.reason
            results["protocol"] = "HTTPS"
            results["port"] = actual_port
            results["success"] = True
            conn.close()
            return results
        except (ssl.SSLError, socket.error, OSError):
            pass

    actual_port = port or 80
    try:
        conn = http.client.HTTPConnection(target, actual_port, timeout=10)
        conn.request("HEAD", "/")
        response = conn.getresponse()
        results["headers"] = dict(response.getheaders())
        results["status"] = response.status
        results["status_reason"] = response.reason
        results["protocol"] = "HTTP"
        results["port"] = actual_port
        results["success"] = True
        conn.close()
    except (socket.error, OSError) as e:
        results["error"] = str(e)

    return results
