"""DNS Records - query A, CNAME, PTR records."""

import socket
import subprocess
import re


def get_dns_records(target):
    """Get DNS records for a target."""
    records = {
        "success": True,
        "target": target,
        "A": [],
        "CNAME": [],
        "PTR": [],
        "MX": [],
        "NS": [],
    }

    records["A"] = _get_a_records(target)
    records["CNAME"] = _get_cname_records(target)
    records["MX"] = _get_mx_records(target)
    records["NS"] = _get_ns_records(target)

    for a_record in records["A"]:
        ptr = _get_ptr_records(a_record)
        if ptr:
            records["PTR"].extend(ptr)

    return records


def _get_a_records(target):
    """Get A records using socket."""
    try:
        results = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = list(set(r[4][0] for r in results))
        return sorted(ips)
    except socket.gaierror:
        return []


def _get_cname_records(target):
    """Get CNAME records using dig."""
    try:
        result = subprocess.run(
            ["dig", "+short", "CNAME", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return [line.strip().rstrip(".") for line in result.stdout.strip().split("\n") if line.strip()]
        return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        try:
            result = subprocess.run(
                ["nslookup", "-type=CNAME", target],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                text=True,
            )
            cnames = re.findall(r"canonical name\s*=\s*(.+)", result.stdout, re.IGNORECASE)
            return [c.strip().rstrip(".") for c in cnames]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []


def _get_ptr_records(ip):
    """Get PTR records for an IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return [hostname]
    except (socket.herror, socket.gaierror):
        return []


def _get_mx_records(target):
    """Get MX records using dig."""
    try:
        result = subprocess.run(
            ["dig", "+short", "MX", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
        return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def _get_ns_records(target):
    """Get NS records using dig."""
    try:
        result = subprocess.run(
            ["dig", "+short", "NS", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return [line.strip().rstrip(".") for line in result.stdout.strip().split("\n") if line.strip()]
        return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
