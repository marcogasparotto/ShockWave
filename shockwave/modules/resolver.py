"""Resolve Host - DNS to IPv4 resolution."""

import socket


def resolve_host(target):
    """Resolve a hostname to its IPv4 address."""
    try:
        hostname = target
        ipv4 = socket.gethostbyname(target)
        return {
            "success": True,
            "hostname": hostname,
            "ipv4": ipv4,
        }
    except socket.gaierror as e:
        return {
            "success": False,
            "error": str(e),
        }
