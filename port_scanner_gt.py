#!/usr/bin/env python3
"""
Port Scanner V2 (with Banner Grabbing)
Author: GhostTech Enterprise LLC

What it does:
- Scans TCP ports on a target (default: 1–1024).
- For each open port, tries to grab a short "banner" (the greeting/first bytes).
- Prints open ports with best-guess service names and any banner snippet.

Usage:
  python3 port_scanner.py scanme.nmap.org
  python3 port_scanner.py 192.168.1.10 --ports 20-1024
  python3 port_scanner.py target.com --ports 22,80,443,3389 --threads 200

Notes:
- Only scan systems you own or have explicit permission to test.
"""

import argparse
import concurrent.futures
import socket
import ssl
import time

# Common ports where we try protocol-specific probes
HTTP_PORTS = {80, 8080, 8000, 8008, 8888}
HTTPS_PORTS = {443, 8443, 9443}
READONLY_BANNER_PORTS = {21, 22, 25, 110, 143, 993, 995, 587, 3306, 3389}

def parse_ports(port_str: str):
    """Parse '80,443,8080' or '1-1024' into a sorted list of ints."""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            if part:
                ports.add(int(part))
    return sorted(ports)

def try_recv(sock, nbytes: int, timeout: float):
    """Receive up to nbytes with timeout; return bytes (possibly empty)."""
    sock.settimeout(timeout)
    try:
        return sock.recv(nbytes)
    except Exception:
        return b""

def http_probe(host: str, port: int, timeout: float, is_tls: bool):
    """Send HTTP HEAD request; return first line + Server header."""
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        try:
            s = raw
            if is_tls:
                ctx = ssl.create_default_context()
                s = ctx.wrap_socket(raw, server_hostname=host)
            req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: mini-scan/2.0\r\n\r\n"
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
            try: s.close()
            except: pass
    except Exception:
        return None

def banner_grab(host: str, port: int, timeout: float):
    """Generic banner grab: connect and read first few bytes."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            data = try_recv(s, 1024, timeout)
            if data:
                return data.decode("utf-8", errors="ignore").strip().replace("\n", " ")[:120]
    except Exception:
        pass
    return None

def scan_port(host: str, port: int, timeout: float):
    """Check if port is open, then try grabbing a banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"

                banner = None
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

def main():
    parser = argparse.ArgumentParser(description="TCP Port Scanner with Banner Grabbing")
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("--ports", default="1-1024", help="Ports to scan (e.g., '80,443' or '1-1024')")
    parser.add_argument("--timeout", type=float, default=0.5, help="Timeout per connection (seconds)")
    parser.add_argument("--threads", type=int, default=100, help="Number of concurrent threads")
    args = parser.parse_args()

    target = args.target
    ports = parse_ports(args.ports)

    print(f"[+] Scanning {target} ({len(ports)} ports) with {args.threads} threads...")
    start_time = time.time()

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_port, target, port, args.timeout) for port in ports]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)

    elapsed = time.time() - start_time

    if open_ports:
        print("\n[+] Open ports:")
        for port, service, banner in sorted(open_ports):
            if banner:
                print(f"    {port:<5} {service:<10} {banner}")
            else:
                print(f"    {port:<5} {service}")
    else:
        print("\n[-] No open ports found.")

    print(f"\n[+] Scan completed in {elapsed:.2f} seconds.")

if __name__ == "__main__":
    main()
