"""Ping Sweep - test host reachability across a range."""

import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


def _ping_host(ip, timeout=1):
    """Ping a single host and return result."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), str(ip)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 2,
        )
        return {"ip": str(ip), "alive": result.returncode == 0}
    except (subprocess.TimeoutExpired, Exception):
        return {"ip": str(ip), "alive": False}


def ping_sweep(target, start=1, end=254, max_threads=50):
    """Perform a ping sweep on a network range.

    Args:
        target: Base network (e.g., '192.168.1') or single host
        start: Start of host range
        end: End of host range
        max_threads: Maximum concurrent threads
    """
    results = {"alive": [], "dead": [], "total": 0}

    if "." in target and target.replace(".", "").isdigit():
        parts = target.split(".")
        if len(parts) == 4:
            base = ".".join(parts[:3])
            ips = [f"{base}.{i}" for i in range(start, end + 1)]
        elif len(parts) == 3:
            base = target
            ips = [f"{base}.{i}" for i in range(start, end + 1)]
        else:
            return {"success": False, "error": "Invalid network range format"}
    else:
        ips = [target]

    results["total"] = len(ips)

    with ThreadPoolExecutor(max_workers=min(max_threads, len(ips))) as executor:
        futures = {executor.submit(_ping_host, ip): ip for ip in ips}
        for future in as_completed(futures):
            result = future.result()
            if result["alive"]:
                results["alive"].append(result["ip"])
            else:
                results["dead"].append(result["ip"])

    results["alive"].sort(key=lambda x: list(map(int, x.split("."))))
    results["success"] = True
    return results


def ping_single(target, count=4):
    """Ping a single host multiple times."""
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), str(target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=count * 3,
            text=True,
        )
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "target": target,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Ping timed out", "target": target}
    except Exception as e:
        return {"success": False, "error": str(e), "target": target}
