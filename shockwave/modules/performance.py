"""Performance - Latency, packet loss, jitter, MTU discovery,
path MTU, throughput estimation."""

import re
import socket
import subprocess
import time


def latency_test(target, count=10, timeout=5):
    """Measure latency to a target."""
    result = {"success": False, "target": target}

    try:
        proc = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), target],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=count * timeout + 10, text=True)

        rtt_match = re.search(
            r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)",
            proc.stdout)

        if rtt_match:
            result.update({
                "success": True,
                "min_ms": float(rtt_match.group(1)),
                "avg_ms": float(rtt_match.group(2)),
                "max_ms": float(rtt_match.group(3)),
                "mdev_ms": float(rtt_match.group(4)),
            })

            rtts = re.findall(r"time=([\d.]+)", proc.stdout)
            result["individual_rtts"] = [float(r) for r in rtts]

            if result["avg_ms"] < 1:
                result["quality"] = "Excellent (< 1ms)"
            elif result["avg_ms"] < 10:
                result["quality"] = "Very Good (< 10ms)"
            elif result["avg_ms"] < 50:
                result["quality"] = "Good (< 50ms)"
            elif result["avg_ms"] < 100:
                result["quality"] = "Fair (< 100ms)"
            elif result["avg_ms"] < 200:
                result["quality"] = "Poor (< 200ms)"
            else:
                result["quality"] = "Bad (> 200ms)"
        else:
            result["error"] = "No RTT data in ping output"

        stats_match = re.search(
            r"(\d+) packets transmitted, (\d+) received",
            proc.stdout)
        if stats_match:
            result["packets_sent"] = int(stats_match.group(1))
            result["packets_received"] = int(stats_match.group(2))

    except subprocess.TimeoutExpired:
        result["error"] = "Latency test timed out"
    except FileNotFoundError:
        result["error"] = "ping not found"

    return result


def packet_loss_test(target, count=20, timeout=5):
    """Measure packet loss to a target."""
    result = {"success": False, "target": target}

    try:
        proc = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), "-i", "0.5", target],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=count * timeout + 15, text=True)

        stats_match = re.search(
            r"(\d+) packets transmitted, (\d+) received.*?(\d+(?:\.\d+)?)% packet loss",
            proc.stdout)

        if stats_match:
            sent = int(stats_match.group(1))
            received = int(stats_match.group(2))
            loss_pct = float(stats_match.group(3))

            result.update({
                "success": True,
                "packets_sent": sent,
                "packets_received": received,
                "packets_lost": sent - received,
                "loss_percentage": loss_pct,
            })

            if loss_pct == 0:
                result["quality"] = "No packet loss"
            elif loss_pct < 1:
                result["quality"] = "Minimal loss (< 1%)"
            elif loss_pct < 5:
                result["quality"] = "Acceptable (< 5%)"
            elif loss_pct < 10:
                result["quality"] = "Degraded (< 10%)"
            else:
                result["quality"] = f"Severe loss ({loss_pct}%)"
        else:
            result["error"] = "Could not parse ping statistics"

    except subprocess.TimeoutExpired:
        result["error"] = "Packet loss test timed out"
    except FileNotFoundError:
        result["error"] = "ping not found"

    return result


def jitter_test(target, count=20, timeout=5):
    """Measure jitter (variation in latency)."""
    result = {"success": False, "target": target}

    try:
        proc = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), "-i", "0.5", target],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=count * timeout + 15, text=True)

        rtts = [float(r) for r in re.findall(r"time=([\d.]+)", proc.stdout)]

        if len(rtts) >= 2:
            differences = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
            avg_jitter = sum(differences) / len(differences)
            max_jitter = max(differences)
            min_jitter = min(differences)

            result.update({
                "success": True,
                "avg_jitter_ms": round(avg_jitter, 3),
                "max_jitter_ms": round(max_jitter, 3),
                "min_jitter_ms": round(min_jitter, 3),
                "samples": len(rtts),
                "rtts": rtts,
            })

            if avg_jitter < 1:
                result["quality"] = "Excellent (< 1ms)"
            elif avg_jitter < 5:
                result["quality"] = "Good (< 5ms)"
            elif avg_jitter < 20:
                result["quality"] = "Fair (< 20ms)"
            elif avg_jitter < 50:
                result["quality"] = "Poor (< 50ms)"
            else:
                result["quality"] = "Bad (> 50ms)"
        else:
            result["error"] = "Insufficient RTT samples"

    except subprocess.TimeoutExpired:
        result["error"] = "Jitter test timed out"
    except FileNotFoundError:
        result["error"] = "ping not found"

    return result


def mtu_discovery(target, timeout=5):
    """Discover the MTU to a target."""
    result = {"success": False, "target": target, "mtu": None}

    low = 68
    high = 1500
    found_mtu = low

    while low <= high:
        mid = (low + high) // 2
        try:
            proc = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout), "-M", "do",
                 "-s", str(mid), target],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout + 2, text=True)

            if proc.returncode == 0:
                found_mtu = mid + 28
                low = mid + 1
            else:
                high = mid - 1

        except (subprocess.TimeoutExpired, Exception):
            high = mid - 1

    if found_mtu > 68:
        result["mtu"] = found_mtu
        result["payload_size"] = found_mtu - 28

        if found_mtu == 1500:
            result["notes"] = "Standard Ethernet MTU"
        elif found_mtu == 1492:
            result["notes"] = "PPPoE MTU"
        elif found_mtu == 1480:
            result["notes"] = "IPsec/VPN tunnel MTU"
        elif found_mtu == 1400:
            result["notes"] = "Common tunnel MTU"
        elif found_mtu < 576:
            result["notes"] = "Unusually low MTU"
        else:
            result["notes"] = f"MTU: {found_mtu} bytes"

        result["success"] = True
    else:
        result["error"] = "Could not determine MTU"

    return result


def path_mtu_discovery(target, timeout=10):
    """Discover path MTU using tracepath."""
    result = {"success": False, "target": target, "path_mtu": None, "hops": []}

    try:
        proc = subprocess.run(
            ["tracepath", "-n", target],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, text=True)

        for line in proc.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            hop_match = re.match(r"\s*(\d+):\s+(\S+)\s+(.*)", line)
            if hop_match:
                result["hops"].append({
                    "hop": int(hop_match.group(1)),
                    "host": hop_match.group(2),
                    "info": hop_match.group(3).strip(),
                })

            pmtu_match = re.search(r"pmtu\s+(\d+)", line)
            if pmtu_match:
                result["path_mtu"] = int(pmtu_match.group(1))

        if "Resume: pmtu" in proc.stdout:
            resume_match = re.search(r"Resume: pmtu (\d+)", proc.stdout)
            if resume_match:
                result["path_mtu"] = int(resume_match.group(1))

        result["success"] = True

    except subprocess.TimeoutExpired:
        result["error"] = "Path MTU discovery timed out"
    except FileNotFoundError:
        result = mtu_discovery(target, timeout=timeout)
        result["method"] = "binary_search_fallback"

    return result


def throughput_estimation(target, port=80, duration=5, timeout=10):
    """Estimate throughput to a target."""
    result = {"success": False, "target": target, "port": port}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex((target, port))

        if code != 0:
            for alt_port in [443, 8080, 22]:
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(timeout)
                code = sock2.connect_ex((target, alt_port))
                if code == 0:
                    sock = sock2
                    port = alt_port
                    result["port"] = port
                    break
                sock2.close()

        if code == 0:
            request = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            start = time.time()
            sock.send(request.encode())

            total_bytes = 0
            while True:
                elapsed = time.time() - start
                if elapsed >= duration:
                    break
                try:
                    data = sock.recv(8192)
                    if not data:
                        break
                    total_bytes += len(data)
                except socket.timeout:
                    break

            elapsed = time.time() - start
            sock.close()

            if elapsed > 0 and total_bytes > 0:
                bps = total_bytes * 8 / elapsed
                result.update({
                    "success": True,
                    "bytes_received": total_bytes,
                    "duration_seconds": round(elapsed, 3),
                    "throughput_bps": round(bps, 2),
                    "throughput_kbps": round(bps / 1000, 2),
                    "throughput_mbps": round(bps / 1000000, 4),
                })
            else:
                result["error"] = "No data received"
        else:
            result["error"] = f"Could not connect to {target}:{port}"

    except (socket.error, OSError) as e:
        result["error"] = str(e)

    return result
