"""Geolocate IP - approximate location via ip-api.com."""

import json
import http.client
import socket


def geolocate_ip(ip):
    """Get geolocation data for an IP address using ip-api.com."""
    result = {
        "success": False,
        "ip": ip,
    }

    try:
        resolved_ip = ip
        if not _is_ip(ip):
            try:
                resolved_ip = socket.gethostbyname(ip)
            except socket.gaierror:
                result["error"] = f"Cannot resolve hostname: {ip}"
                return result

        conn = http.client.HTTPConnection("ip-api.com", timeout=10)
        conn.request("GET", f"/json/{resolved_ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query")
        response = conn.getresponse()
        data = json.loads(response.read().decode())
        conn.close()

        if data.get("status") == "success":
            result.update({
                "success": True,
                "ip": data.get("query", resolved_ip),
                "country": data.get("country", "N/A"),
                "region": data.get("regionName", "N/A"),
                "city": data.get("city", "N/A"),
                "zip": data.get("zip", "N/A"),
                "latitude": data.get("lat", "N/A"),
                "longitude": data.get("lon", "N/A"),
                "timezone": data.get("timezone", "N/A"),
                "isp": data.get("isp", "N/A"),
                "org": data.get("org", "N/A"),
                "as": data.get("as", "N/A"),
            })
        else:
            result["error"] = data.get("message", "Geolocation failed")

    except (socket.error, OSError) as e:
        result["error"] = f"Connection error: {e}"
    except json.JSONDecodeError:
        result["error"] = "Invalid response from API"

    return result


def _is_ip(target):
    """Check if target is an IP address."""
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False
