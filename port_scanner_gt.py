#!/usr/bin/env python3
"""
TCP Port Scanner V3 (with Banner Grabbing + JSON/CSV export)
Author: GhostTech Enterprise LLC

What it does:
- Scans TCP ports on a target (default: 1–1024) using threads.
- For each open port, optionally grabs a short banner (HTTP/HTTPS aware).
- Prints results and can export to JSON and/or CSV.

Usage examples:
  python3 port_scanner.py scanme.nmap.org
  python3 port_scanner.py 192.168.1.10 --ports 20-1024 --json-out result.json --csv-out result.csv
  python3 port_scanner.py target.com --ports 22,80,443 --threads 200 --timeout 0.7

Legal note:
- Only scan systems you own or have explicit permission to test.
"""

import argparse
import concurrent.futures
import csv
import json
import socket
import ssl
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

# Ports where we attempt a tiny protocol-aware probe to get useful banners
HTTP_PORTS = {80, 8080, 8000, 8008, 8888}
HTTPS_PORTS = {443, 8443, 9443}
# "Read-only" style services that often send a greeting first
READONLY_BANNER_PORTS = {21, 22, 25, 110, 143, 993, 995, 587, 3306, 3389}


def parse_ports(spec: str) -> List[int]:
    """
    Parse a port spec like '80,443,8080' or '1-1024' into a sorted list of ints.
    """
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def try_recv(sock: socket.socket, nbytes: int, timeout: float) -> bytes:
    """
    Receive up to nbytes with a timeout. Returns bytes (possibly empty).
    """
    sock.settimeout(timeout)
    try:
        return sock.recv(nbytes)
    except Exception:
        return b""


def http_probe(host: str, port: int, timeout: float, is_tls: bool) -> Optional[str]:
    """
    Send a minimal HTTP HEAD request and return first status line + Server header (if any).
    If TLS, wrap the socket with SNI using the given host.
    """
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        try:
            s = raw
            if is_tls:
                ctx = ssl.create_default_context()
                s = ctx.wrap_socket(raw, server_hostname=host)
            req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: mini-scan/3.0\r\n\r\n"
            s.settimeout(timeout)
            s.sendall(req.encode("ascii", errors="ignore"))
            data = s.recv(2048)
            if not data:
                return None
            text = data.decode("iso-8859-1", errors="ignore")
            lines = text.split("\r\n")
            first = lines[0] if lines else ""
            server = next((ln.split(":", 1)[1].strip() for ln in lines if ln.lower().startswith("server:")), None)
            return f"{first}" + (f" | Server: {server}" if server else "")
        finally:
            try:
                s.close()
            except Exception:
                pass
    except Exception:
        return None


def banner_grab(host: str, port: int, timeout: float) -> Optional[str]:
    """
    Generic banner grab: connect and read the first few bytes shown by the service (if any).
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            data = try_recv(s, 1024, timeout)
            if data:
                return data.decode("utf-8", errors="ignore").strip().replace("\r", " ").replace("\n", " ")[:160]
    except Exception:
        pass
    return None


def scan_port(host: str, port: int, timeout: float, grab_banners: bool = True) -> Optional[Tuple[int, str, Optional[str]]]:
    """
    Attempt to connect to a host:port.
    If open, return (port, service_name, banner_or_None).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"

                banner = None
                if grab_banners:
                    if port in HTTP_PORTS:
                        banner = http_probe(host, port, timeout, is_tls=False)
                    elif port in HTTPS_PORTS:
                        banner = http_probe(host, port, timeout, is_tls=True)
                    elif port in READONLY_BANNER_PORTS:
                        banner = banner_grab(host, port, timeout)

                return (port, service, banner)
    except Exception:
        pass
    return None


def save_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[+] JSON saved to {path}")


def save_csv(path: str, rows: List[Dict[str, Any]]) -> None:
    """
    rows: list of dicts with keys:
      target, resolved_ip, port, service, banner (optional), scan_started, scan_duration_sec
    """
    fieldnames = ["target", "resolved_ip", "port", "service", "banner", "scan_started", "scan_duration_sec"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})
    print(f"[+] CSV saved to {path}")


def main():
    parser = argparse.ArgumentParser(description="TCP Port Scanner (banners + JSON/CSV export)")
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("--ports", default="1-1024", help="Ports to scan (e.g., '80,443' or '1-1024')")
    parser.add_argument("--timeout", type=float, default=0.5, help="Timeout per connection in seconds (default: 0.5)")
    parser.add_argument("--threads", type=int, default=100, help="Number of concurrent threads (default: 100)")
    parser.add_argument("--json-out", default=None, help="Path to write JSON results (e.g., results.json)")
    parser.add_argument("--csv-out", default=None, help="Path to write CSV results (e.g., results.csv)")
    parser.add_argument("--no-banners", action="store_true", help="Disable banner grabbing")
    args = parser.parse_args()

    target = args.target
    ports = parse_ports(args.ports)

    # Resolve hostname → IP for metadata (doesn't change scan target; connect_ex handles hostnames)
    try:
        resolved_ip = socket.gethostbyname(target)
    except Exception:
        resolved_ip = "unresolved"

    started_iso = datetime.utcnow().isoformat() + "Z"
    print(f"[+] Scanning {target} ({resolved_ip}) | ports: {args.ports} | threads: {args.threads} | timeout: {args.timeout}s")
    start_time = time.time()

    open_ports: List[Tuple[int, str, Optional[str]]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = [ex.submit(scan_port, target, p, args.timeout, not args.no_banners) for p in ports]
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                open_ports.append(res)

    duration = round(time.time() - start_time, 3)

    # Print to console
    if open_ports:
        print("\n[+] Open ports:")
        for port, service, banner in sorted(open_ports):
            line = f"    {port:<5} {service:<10}"
            if (banner is not None) and not args.no_banners:
                line += f" {banner}"
            print(line)
    else:
        print("\n[-] No open ports found.")

    print(f"\n[+] Scan completed in {duration:.2f} seconds.")

    # Prepare structured output
    rows = [{
        "target": target,
        "resolved_ip": resolved_ip,
        "port": port,
        "service": service,
        "banner": (banner if (banner and not args.no_banners) else ""),
        "scan_started": started_iso,
        "scan_duration_sec": duration
    } for port, service, banner in sorted(open_ports)]

    result_json = {
        "target": target,
        "resolved_ip": resolved_ip,
        "ports_spec": args.ports,
        "open_ports": [
            {"port": port, "service": service, "banner": (banner if (banner and not args.no_banners) else "")}
            for port, service, banner in sorted(open_ports)
        ],
        "scan_started": started_iso,
        "scan_duration_sec": duration,
        "count_open": len(open_ports),
    }

    # Default filenames if none provided: use target + timestamp
    if not args.json_out and not args.csv_out:
        stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        args.json_out = f"scan_{target}_{stamp}.json"

    if args.json_out:
        save_json(args.json_out, result_json)
    if args.csv_out:
        save_csv(args.csv_out, rows)


if __name__ == "__main__":
    main()
