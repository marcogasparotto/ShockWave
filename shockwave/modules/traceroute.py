"""Traceroute - hop-by-hop path tracing."""

import subprocess
import re


def traceroute(target, max_hops=30):
    """Perform a traceroute to the target."""
    try:
        result = subprocess.run(
            ["traceroute", "-m", str(max_hops), "-w", "3", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max_hops * 5,
            text=True,
        )

        hops = _parse_traceroute(result.stdout)

        return {
            "success": True,
            "target": target,
            "hops": hops,
            "raw_output": result.stdout,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Traceroute timed out"}
    except FileNotFoundError:
        try:
            result = subprocess.run(
                ["tracepath", target],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=max_hops * 5,
                text=True,
            )
            return {
                "success": True,
                "target": target,
                "hops": [],
                "raw_output": result.stdout,
            }
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return {"success": False, "error": "traceroute/tracepath not found"}


def _parse_traceroute(output):
    """Parse traceroute output into structured hops."""
    hops = []
    for line in output.strip().split("\n")[1:]:
        line = line.strip()
        if not line:
            continue

        match = re.match(r"\s*(\d+)\s+(.+)", line)
        if match:
            hop_num = int(match.group(1))
            rest = match.group(2)

            if "* * *" in rest:
                hops.append({
                    "hop": hop_num,
                    "host": "*",
                    "ip": "*",
                    "rtt": ["*", "*", "*"],
                })
            else:
                host_match = re.match(r"(\S+)\s+\((\S+)\)\s+(.+)", rest)
                if host_match:
                    hostname = host_match.group(1)
                    ip = host_match.group(2)
                    rtt_str = host_match.group(3)
                    rtts = re.findall(r"([\d.]+)\s*ms", rtt_str)
                    hops.append({
                        "hop": hop_num,
                        "host": hostname,
                        "ip": ip,
                        "rtt": rtts if rtts else ["*"],
                    })
                else:
                    ip_match = re.match(r"(\S+)\s+(.+)", rest)
                    if ip_match:
                        ip = ip_match.group(1)
                        rtt_str = ip_match.group(2)
                        rtts = re.findall(r"([\d.]+)\s*ms", rtt_str)
                        hops.append({
                            "hop": hop_num,
                            "host": ip,
                            "ip": ip,
                            "rtt": rtts if rtts else ["*"],
                        })
    return hops
