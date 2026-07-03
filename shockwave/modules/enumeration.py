"""Enumeration - ASN lookup, subdomain enumeration, DNSSEC detection,
zone transfer check, CDN detection."""

import http.client
import json
import re
import socket
import subprocess


def asn_lookup(target):
    """Look up ASN information for a target IP or domain."""
    result = {"success": False, "target": target}

    try:
        ip = target
        if not _is_ip(target):
            ip = socket.gethostbyname(target)

        result["ip"] = ip

        try:
            conn = http.client.HTTPSConnection("ipinfo.io", timeout=10)
            conn.request("GET", f"/{ip}/json",
                         headers={"User-Agent": "Shockwave/1.0"})
            resp = conn.getresponse()
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                result.update({
                    "success": True,
                    "asn": data.get("org", "N/A"),
                    "hostname": data.get("hostname", "N/A"),
                    "city": data.get("city", "N/A"),
                    "region": data.get("region", "N/A"),
                    "country": data.get("country", "N/A"),
                })
                conn.close()
                return result
            conn.close()
        except (socket.error, OSError):
            pass

        try:
            conn = http.client.HTTPConnection("ip-api.com", timeout=10)
            conn.request("GET", f"/json/{ip}?fields=status,as,org,isp,query")
            resp = conn.getresponse()
            data = json.loads(resp.read().decode())
            conn.close()
            if data.get("status") == "success":
                result.update({
                    "success": True,
                    "asn": data.get("as", "N/A"),
                    "org": data.get("org", "N/A"),
                    "isp": data.get("isp", "N/A"),
                })
                return result
        except (socket.error, OSError):
            pass

        result["error"] = "Could not retrieve ASN information"
    except socket.gaierror as e:
        result["error"] = f"DNS resolution failed: {e}"

    return result


def subdomain_enumeration(domain, wordlist=None):
    """Enumerate subdomains for a given domain."""
    if wordlist is None:
        wordlist = [
            "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
            "ns1", "ns2", "dns", "dns1", "dns2", "mx", "mx1", "mx2",
            "api", "dev", "staging", "test", "beta", "alpha", "demo",
            "admin", "panel", "dashboard", "portal", "login", "auth",
            "app", "mobile", "m", "static", "cdn", "assets", "media",
            "img", "images", "video", "docs", "wiki", "blog", "forum",
            "shop", "store", "cart", "pay", "payment", "billing",
            "vpn", "remote", "gateway", "proxy", "firewall",
            "db", "database", "mysql", "postgres", "redis", "mongo",
            "git", "gitlab", "github", "jenkins", "ci", "cd",
            "monitor", "status", "health", "metrics", "grafana",
            "backup", "bak", "old", "new", "v2", "v3",
            "internal", "intranet", "extranet", "corp",
            "cloud", "aws", "azure", "gcp", "s3",
            "support", "help", "helpdesk", "ticket",
            "chat", "slack", "teams", "meet", "zoom",
            "cpanel", "whm", "plesk", "webmin",
            "autodiscover", "autoconfig", "wpad",
            "sip", "voip", "pbx", "asterisk",
            "owa", "exchange", "outlook",
        ]

    result = {"success": False, "domain": domain, "subdomains": [], "total_checked": len(wordlist)}

    for sub in wordlist:
        fqdn = f"{sub}.{domain}"
        try:
            answers = socket.getaddrinfo(fqdn, None, socket.AF_INET, socket.SOCK_STREAM)
            ips = list(set(a[4][0] for a in answers))
            result["subdomains"].append({
                "subdomain": fqdn,
                "ips": ips,
            })
        except (socket.gaierror, socket.herror):
            pass

    result["success"] = True
    result["found"] = len(result["subdomains"])
    return result


def dnssec_detection(domain):
    """Check if a domain has DNSSEC enabled."""
    result = {"success": False, "domain": domain, "dnssec_enabled": False, "details": {}}

    try:
        proc = subprocess.run(
            ["dig", "+dnssec", "+short", "DNSKEY", domain],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, text=True)

        has_dnskey = bool(proc.stdout.strip())

        proc2 = subprocess.run(
            ["dig", "+dnssec", "+short", "DS", domain],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, text=True)

        has_ds = bool(proc2.stdout.strip())

        proc3 = subprocess.run(
            ["dig", "+dnssec", "+short", "RRSIG", domain],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, text=True)

        has_rrsig = bool(proc3.stdout.strip())

        result.update({
            "success": True,
            "dnssec_enabled": has_dnskey or has_ds or has_rrsig,
            "details": {
                "has_dnskey": has_dnskey,
                "has_ds": has_ds,
                "has_rrsig": has_rrsig,
                "dnskey": proc.stdout.strip() if has_dnskey else None,
                "ds": proc2.stdout.strip() if has_ds else None,
            },
        })
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        result["error"] = str(e)

    return result


def zone_transfer_check(domain):
    """Attempt DNS zone transfer (AXFR) against nameservers."""
    result = {"success": False, "domain": domain, "vulnerable": False, "nameservers": [], "records": []}

    try:
        proc = subprocess.run(
            ["dig", "+short", "NS", domain],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, text=True)

        if proc.returncode == 0 and proc.stdout.strip():
            ns_servers = [ns.strip().rstrip(".")
                          for ns in proc.stdout.strip().split("\n") if ns.strip()]
            result["nameservers"] = ns_servers

            for ns in ns_servers:
                try:
                    axfr_proc = subprocess.run(
                        ["dig", "AXFR", domain, f"@{ns}"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=15, text=True)

                    if "XFR size" in axfr_proc.stdout or axfr_proc.stdout.count("\n") > 5:
                        result["vulnerable"] = True
                        for line in axfr_proc.stdout.split("\n"):
                            line = line.strip()
                            if line and not line.startswith(";"):
                                result["records"].append(line)
                except (subprocess.TimeoutExpired, Exception):
                    pass

            result["success"] = True
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        result["error"] = str(e)

    return result


CDN_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "cnames": ["cloudflare.com", "cloudflare.net", "cloudflare-dns.com"],
        "server": ["cloudflare"],
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "x-akamai-session-info"],
        "cnames": ["akamai.net", "akamaiedge.net", "akamaized.net", "edgekey.net"],
        "server": ["akamai"],
    },
    "fastly": {
        "headers": ["x-fastly-request-id", "fastly-debug-digest"],
        "cnames": ["fastly.net", "fastlylb.net"],
        "server": ["fastly"],
    },
    "cloudfront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
        "cnames": ["cloudfront.net", "amazonaws.com"],
        "server": ["cloudfront", "amazons3"],
    },
    "incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "cnames": ["incapdns.net", "imperva.com"],
        "server": ["incapsula"],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "cnames": ["sucuri.net", "sucuridns.com"],
        "server": ["sucuri"],
    },
    "maxcdn": {
        "headers": ["x-pull"],
        "cnames": ["netdna-cdn.com", "stackpathdns.com"],
        "server": ["netdna", "maxcdn"],
    },
    "google": {
        "headers": ["via"],
        "cnames": ["googleusercontent.com", "googlevideo.com", "googleapis.com"],
        "server": ["gws", "gse"],
    },
}


def cdn_detection(target):
    """Detect if a target is behind a CDN."""
    result = {"success": False, "target": target, "cdn_detected": False, "cdn_provider": None, "evidence": []}

    try:
        import http.client
        import ssl

        headers_data = {}
        server_header = ""

        for scheme in ["https", "http"]:
            try:
                if scheme == "https":
                    ctx = ssl.create_default_context()
                    conn = http.client.HTTPSConnection(target, 443, timeout=10, context=ctx)
                else:
                    conn = http.client.HTTPConnection(target, 80, timeout=10)

                conn.request("HEAD", "/", headers={"Host": target, "User-Agent": "Shockwave/1.0"})
                resp = conn.getresponse()
                headers_data = {k.lower(): v for k, v in resp.getheaders()}
                server_header = headers_data.get("server", "").lower()
                conn.close()
                break
            except (socket.error, OSError, ssl.SSLError):
                continue

        cname_records = []
        try:
            proc = subprocess.run(
                ["dig", "+short", "CNAME", target],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=10, text=True)
            if proc.returncode == 0 and proc.stdout.strip():
                cname_records = [c.strip().lower() for c in proc.stdout.strip().split("\n")]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        for cdn_name, sigs in CDN_SIGNATURES.items():
            for hdr in sigs.get("headers", []):
                if hdr in headers_data:
                    result["cdn_detected"] = True
                    result["cdn_provider"] = cdn_name
                    result["evidence"].append(f"Header: {hdr}")

            for srv in sigs.get("server", []):
                if srv in server_header:
                    result["cdn_detected"] = True
                    result["cdn_provider"] = cdn_name
                    result["evidence"].append(f"Server: {server_header}")

            for cname in cname_records:
                for cname_sig in sigs.get("cnames", []):
                    if cname_sig in cname:
                        result["cdn_detected"] = True
                        result["cdn_provider"] = cdn_name
                        result["evidence"].append(f"CNAME: {cname}")

            if result["cdn_detected"]:
                break

        result["success"] = True
        result["headers_checked"] = len(headers_data)
        result["cnames_found"] = cname_records

    except Exception as e:
        result["error"] = str(e)

    return result


def _is_ip(target):
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False
