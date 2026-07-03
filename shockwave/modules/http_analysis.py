"""HTTP Analysis - Security headers, cookie analysis, redirect detection,
compression, HTTP methods, HTTP/2-3 detection, robots.txt, sitemap.xml,
web technology detection."""

import http.client
import json
import re
import socket
import ssl


SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "description": "HTTP Strict Transport Security",
        "severity": "high",
    },
    "content-security-policy": {
        "name": "CSP",
        "description": "Content Security Policy",
        "severity": "high",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "description": "Prevents MIME type sniffing",
        "severity": "medium",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "description": "Clickjacking protection",
        "severity": "medium",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "description": "XSS Filter",
        "severity": "low",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "description": "Controls referrer information",
        "severity": "medium",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "description": "Controls browser features",
        "severity": "medium",
    },
    "x-permitted-cross-domain-policies": {
        "name": "X-Permitted-Cross-Domain-Policies",
        "description": "Controls Flash/PDF cross-domain access",
        "severity": "low",
    },
    "cross-origin-embedder-policy": {
        "name": "COEP",
        "description": "Cross-Origin Embedder Policy",
        "severity": "medium",
    },
    "cross-origin-opener-policy": {
        "name": "COOP",
        "description": "Cross-Origin Opener Policy",
        "severity": "medium",
    },
    "cross-origin-resource-policy": {
        "name": "CORP",
        "description": "Cross-Origin Resource Policy",
        "severity": "medium",
    },
}


def security_headers_check(target, port=443, timeout=10):
    """Check for security-related HTTP headers."""
    result = {"success": False, "target": target, "present": [], "missing": [], "score": 0}

    try:
        headers = _get_headers(target, port, timeout)
        if headers is None:
            result["error"] = "Could not retrieve headers"
            return result

        headers_lower = {k.lower(): v for k, v in headers.items()}
        total = len(SECURITY_HEADERS)
        found = 0

        for header_key, info in SECURITY_HEADERS.items():
            if header_key in headers_lower:
                found += 1
                result["present"].append({
                    "header": info["name"],
                    "value": headers_lower[header_key],
                    "description": info["description"],
                })
            else:
                result["missing"].append({
                    "header": info["name"],
                    "severity": info["severity"],
                    "description": info["description"],
                })

        result["score"] = round((found / total) * 100, 1) if total > 0 else 0
        result["total_checked"] = total
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def cookie_analysis(target, port=443, timeout=10):
    """Analyze cookies set by the server."""
    result = {"success": False, "target": target, "cookies": []}

    try:
        headers = _get_headers(target, port, timeout, method="GET")
        if headers is None:
            result["error"] = "Could not retrieve headers"
            return result

        for key, value in headers.items():
            if key.lower() == "set-cookie":
                cookie_parts = value.split(";")
                name_value = cookie_parts[0].strip()

                cookie_info = {
                    "raw": value,
                    "name_value": name_value,
                    "secure": False,
                    "httponly": False,
                    "samesite": None,
                    "path": None,
                    "domain": None,
                    "expires": None,
                    "max_age": None,
                    "issues": [],
                }

                for part in cookie_parts[1:]:
                    part = part.strip().lower()
                    if part == "secure":
                        cookie_info["secure"] = True
                    elif part == "httponly":
                        cookie_info["httponly"] = True
                    elif part.startswith("samesite="):
                        cookie_info["samesite"] = part.split("=", 1)[1]
                    elif part.startswith("path="):
                        cookie_info["path"] = part.split("=", 1)[1]
                    elif part.startswith("domain="):
                        cookie_info["domain"] = part.split("=", 1)[1]
                    elif part.startswith("expires="):
                        cookie_info["expires"] = part.split("=", 1)[1]
                    elif part.startswith("max-age="):
                        cookie_info["max_age"] = part.split("=", 1)[1]

                if not cookie_info["secure"]:
                    cookie_info["issues"].append("Missing Secure flag")
                if not cookie_info["httponly"]:
                    cookie_info["issues"].append("Missing HttpOnly flag")
                if not cookie_info["samesite"]:
                    cookie_info["issues"].append("Missing SameSite attribute")

                result["cookies"].append(cookie_info)

        result["success"] = True
        result["total_cookies"] = len(result["cookies"])

    except Exception as e:
        result["error"] = str(e)

    return result


def redirect_detection(target, port=443, timeout=10, max_redirects=10):
    """Detect HTTP redirects and follow redirect chain."""
    result = {"success": False, "target": target, "redirects": [], "final_url": None}

    current_target = target
    current_port = port
    use_https = port == 443

    for i in range(max_redirects):
        try:
            if use_https:
                ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection(current_target, current_port,
                                                    timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(current_target, current_port,
                                                   timeout=timeout)

            conn.request("HEAD", "/", headers={"Host": current_target})
            resp = conn.getresponse()
            conn.close()

            if resp.status in (301, 302, 303, 307, 308):
                location = resp.getheader("Location", "")
                result["redirects"].append({
                    "step": i + 1,
                    "url": f"{'https' if use_https else 'http'}://{current_target}:{current_port}/",
                    "status": resp.status,
                    "location": location,
                })

                if location.startswith("https://"):
                    use_https = True
                    parsed = location.replace("https://", "").split("/", 1)
                    host_port = parsed[0].split(":")
                    current_target = host_port[0]
                    current_port = int(host_port[1]) if len(host_port) > 1 else 443
                elif location.startswith("http://"):
                    use_https = False
                    parsed = location.replace("http://", "").split("/", 1)
                    host_port = parsed[0].split(":")
                    current_target = host_port[0]
                    current_port = int(host_port[1]) if len(host_port) > 1 else 80
                elif location.startswith("/"):
                    pass
                else:
                    break
            else:
                result["final_url"] = f"{'https' if use_https else 'http'}://{current_target}/"
                result["final_status"] = resp.status
                break

        except (socket.error, OSError, ssl.SSLError) as e:
            result["redirects"].append({
                "step": i + 1,
                "url": f"{'https' if use_https else 'http'}://{current_target}:{current_port}/",
                "error": str(e),
            })
            break

    result["total_redirects"] = len(result["redirects"])
    result["success"] = True
    return result


def compression_detection(target, port=443, timeout=10):
    """Detect supported HTTP compression methods."""
    result = {"success": False, "target": target, "compression": []}

    encodings = ["gzip", "deflate", "br", "zstd", "compress", "identity"]

    try:
        for encoding in encodings:
            try:
                if port == 443:
                    ctx = ssl.create_default_context()
                    conn = http.client.HTTPSConnection(target, port, timeout=timeout, context=ctx)
                else:
                    conn = http.client.HTTPConnection(target, port, timeout=timeout)

                conn.request("GET", "/", headers={
                    "Host": target,
                    "Accept-Encoding": encoding,
                    "User-Agent": "Shockwave/1.0",
                })
                resp = conn.getresponse()
                content_encoding = resp.getheader("Content-Encoding", "")
                conn.close()

                if encoding.lower() in content_encoding.lower():
                    result["compression"].append(encoding)

            except (socket.error, OSError, ssl.SSLError):
                pass

        result["success"] = True
        result["supported_count"] = len(result["compression"])

    except Exception as e:
        result["error"] = str(e)

    return result


def http_methods_detection(target, port=443, timeout=10):
    """Detect allowed HTTP methods."""
    result = {"success": False, "target": target, "allowed_methods": [], "risky_methods": []}

    methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE"]
    risky = {"PUT", "DELETE", "TRACE", "PATCH"}

    try:
        try:
            if port == 443:
                ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection(target, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(target, port, timeout=timeout)

            conn.request("OPTIONS", "/", headers={"Host": target})
            resp = conn.getresponse()
            allow = resp.getheader("Allow", "")
            conn.close()

            if allow:
                result["allowed_methods"] = [m.strip() for m in allow.split(",")]
                result["risky_methods"] = [m for m in result["allowed_methods"] if m in risky]
                result["success"] = True
                return result
        except (socket.error, OSError, ssl.SSLError):
            pass

        for method in methods:
            try:
                if port == 443:
                    ctx = ssl.create_default_context()
                    conn = http.client.HTTPSConnection(target, port, timeout=timeout, context=ctx)
                else:
                    conn = http.client.HTTPConnection(target, port, timeout=timeout)

                conn.request(method, "/", headers={"Host": target})
                resp = conn.getresponse()
                conn.close()

                if resp.status != 405:
                    result["allowed_methods"].append(method)
                    if method in risky:
                        result["risky_methods"].append(method)
            except (socket.error, OSError, ssl.SSLError):
                pass

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def http2_detection(target, port=443, timeout=10):
    """Detect HTTP/2 support."""
    result = {"success": False, "target": target, "http2_supported": False}

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])

        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=target)
        conn.settimeout(timeout)
        conn.connect((target, port))

        selected = conn.selected_alpn_protocol()
        conn.close()

        result["http2_supported"] = selected == "h2"
        result["selected_protocol"] = selected or "http/1.1"
        result["success"] = True

    except (ssl.SSLError, socket.error, OSError) as e:
        result["error"] = str(e)

    return result


def http3_detection(target, port=443, timeout=10):
    """Detect HTTP/3 support via Alt-Svc header."""
    result = {"success": False, "target": target, "http3_supported": False}

    try:
        headers = _get_headers(target, port, timeout)
        if headers:
            alt_svc = None
            for k, v in headers.items():
                if k.lower() == "alt-svc":
                    alt_svc = v
                    break

            if alt_svc and ("h3" in alt_svc or "quic" in alt_svc.lower()):
                result["http3_supported"] = True
                result["alt_svc"] = alt_svc

            result["success"] = True
        else:
            result["error"] = "Could not retrieve headers"

    except Exception as e:
        result["error"] = str(e)

    return result


def robots_txt(target, port=443, timeout=10):
    """Fetch and parse robots.txt."""
    result = {"success": False, "target": target, "exists": False, "rules": []}

    try:
        if port == 443:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(target, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(target, port, timeout=timeout)

        conn.request("GET", "/robots.txt", headers={
            "Host": target,
            "User-Agent": "Shockwave/1.0",
        })
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        conn.close()

        if resp.status == 200 and body.strip():
            result["exists"] = True
            result["content"] = body[:5000]

            current_agent = "*"
            for line in body.split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if line.lower().startswith("user-agent:"):
                    current_agent = line.split(":", 1)[1].strip()
                elif line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    result["rules"].append({
                        "user_agent": current_agent,
                        "type": "Disallow",
                        "path": path,
                    })
                elif line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    result["rules"].append({
                        "user_agent": current_agent,
                        "type": "Allow",
                        "path": path,
                    })
                elif line.lower().startswith("sitemap:"):
                    result.setdefault("sitemaps", []).append(line.split(":", 1)[1].strip())

            result["disallowed_paths"] = [r["path"] for r in result["rules"]
                                           if r["type"] == "Disallow" and r["path"]]
        else:
            result["exists"] = False

        result["success"] = True

    except (socket.error, OSError, ssl.SSLError) as e:
        result["error"] = str(e)

    return result


def sitemap_xml(target, port=443, timeout=10):
    """Fetch and parse sitemap.xml."""
    result = {"success": False, "target": target, "exists": False, "urls": []}

    try:
        if port == 443:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(target, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(target, port, timeout=timeout)

        conn.request("GET", "/sitemap.xml", headers={
            "Host": target,
            "User-Agent": "Shockwave/1.0",
        })
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        conn.close()

        if resp.status == 200 and ("<urlset" in body or "<sitemapindex" in body):
            result["exists"] = True
            result["content_length"] = len(body)

            urls = re.findall(r"<loc>(.*?)</loc>", body)
            result["urls"] = urls[:100]
            result["total_urls"] = len(urls)

            if "<sitemapindex" in body:
                result["is_index"] = True
                sitemaps = re.findall(r"<loc>(.*?)</loc>", body)
                result["sub_sitemaps"] = sitemaps
            else:
                result["is_index"] = False
        else:
            result["exists"] = False

        result["success"] = True

    except (socket.error, OSError, ssl.SSLError) as e:
        result["error"] = str(e)

    return result


TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
    "Drupal": [r"drupal", r"sites/default", r"misc/drupal"],
    "Joomla": [r"joomla", r"/administrator", r"com_content"],
    "Django": [r"csrfmiddlewaretoken", r"django"],
    "Laravel": [r"laravel_session", r"laravel"],
    "Rails": [r"rails", r"csrf-token"],
    "Express": [r"x-powered-by.*express"],
    "ASP.NET": [r"x-aspnet-version", r"x-powered-by.*asp\.net", r"__viewstate"],
    "PHP": [r"x-powered-by.*php", r"phpsessid"],
    "Nginx": [r"server.*nginx"],
    "Apache": [r"server.*apache"],
    "Cloudflare": [r"cf-ray", r"server.*cloudflare"],
    "React": [r"react", r"__react", r"react-root"],
    "Vue.js": [r"vue", r"__vue"],
    "Angular": [r"ng-version", r"angular"],
    "jQuery": [r"jquery"],
    "Bootstrap": [r"bootstrap"],
    "Next.js": [r"__next", r"next-router", r"_next/static"],
    "Nuxt.js": [r"__nuxt", r"nuxt"],
    "Varnish": [r"x-varnish", r"via.*varnish"],
    "IIS": [r"server.*iis", r"x-powered-by.*iis"],
}


def web_technology_detection(target, port=443, timeout=10):
    """Detect web technologies used by the target."""
    result = {"success": False, "target": target, "technologies": []}

    try:
        if port == 443:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(target, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(target, port, timeout=timeout)

        conn.request("GET", "/", headers={
            "Host": target,
            "User-Agent": "Mozilla/5.0 (compatible; Shockwave/1.0)",
        })
        resp = conn.getresponse()
        body = resp.read(50000).decode("utf-8", errors="replace")
        headers_str = str(resp.getheaders()).lower()
        conn.close()

        combined = (body + "\n" + headers_str).lower()

        for tech, patterns in TECH_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    if tech not in result["technologies"]:
                        result["technologies"].append(tech)
                    break

        server = ""
        for k, v in resp.getheaders():
            if k.lower() == "server":
                server = v
                break

        if server:
            result["server"] = server

        powered_by = ""
        for k, v in resp.getheaders():
            if k.lower() == "x-powered-by":
                powered_by = v
                break

        if powered_by:
            result["powered_by"] = powered_by

        result["success"] = True

    except (socket.error, OSError, ssl.SSLError) as e:
        result["error"] = str(e)

    return result


def _get_headers(target, port=443, timeout=10, method="HEAD"):
    """Helper to fetch HTTP headers."""
    try:
        if port == 443:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(target, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(target, port, timeout=timeout)

        conn.request(method, "/", headers={"Host": target, "User-Agent": "Shockwave/1.0"})
        resp = conn.getresponse()
        headers = dict(resp.getheaders())
        conn.close()
        return headers
    except (socket.error, OSError, ssl.SSLError):
        if port == 443:
            try:
                conn = http.client.HTTPConnection(target, 80, timeout=timeout)
                conn.request(method, "/", headers={"Host": target, "User-Agent": "Shockwave/1.0"})
                resp = conn.getresponse()
                headers = dict(resp.getheaders())
                conn.close()
                return headers
            except (socket.error, OSError):
                pass
        return None
