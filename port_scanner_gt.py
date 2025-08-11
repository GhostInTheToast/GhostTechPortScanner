"""
Simple TCP Port Scanner
Creator: GhostTech Enterprise LLC
Description:
    - Takes a hostname or IP address and scans for open TCP ports.
    - Uses multithreading for speed.
    - Optionally accepts a custom port range.
    - Outputs open ports and their common service names.
Usage:
    python3 port_scanner.py 192.168.1.10
    python3 port_scanner.py scanme.nmap.org --ports 20-1024
"""

import argparse
import socket
import concurrent.futures
import time

# -------------------------
# Function: scan_port
# -------------------------
def scan_port(target: str, port: int, timeout: float = 0.5):
    """
    Attempt to connect to a target IP/hostname on a specific port.
    If successful, return a tuple (port, service_name).
    If not, return None.
    """
    try:
        # Create TCP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)  # avoid waiting too long
            result = s.connect_ex((target, port))  # 0 means success
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                return (port, service)
    except Exception:
        pass
    return None

# -------------------------
# Function: parse_ports
# -------------------------
def parse_ports(port_str: str):
    """
    Convert a string like '80,443,8080' or '1-1024' into a list of ints.
    """
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

# -------------------------
# Main entry point
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Simple TCP Port Scanner")
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "--ports",
        default="1-1024",
        help="Ports to scan (e.g., '80,443' or '1-1024'). Default=1-1024",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Timeout for each connection attempt (seconds). Default=0.5",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of threads to use for scanning. Default=100",
    )

    args = parser.parse_args()

    target = args.target
    ports = parse_ports(args.ports)

    print(f"[+] Starting scan on {target}")
    print(f"[+] Ports to scan: {len(ports)} ports ({args.ports})")
    print(f"[+] Threads: {args.threads}")
    print(f"[+] Timeout per port: {args.timeout}s\n")

    start_time = time.time()

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_port = {
            executor.submit(scan_port, target, port, args.timeout): port for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)

    elapsed = time.time() - start_time

    if open_ports:
        print("\n[+] Open ports found:")
        for port, service in sorted(open_ports):
            print(f"    {port:<5} {service}")
    else:
        print("\n[-] No open ports found.")

    print(f"\n[+] Scan completed in {elapsed:.2f} seconds.")

if __name__ == "__main__":
    main()
