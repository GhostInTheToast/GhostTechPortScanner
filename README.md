# TCP Port Scanner V3 (with Banner Grabbing + JSON/CSV Export)

**Author:** GhostTech Enterprise LLC

A fast multithreaded TCP port scanner written in Python.  
Scans a target for open ports, optionally grabs service banners, and can export results in JSON and CSV formats.

---

## Features

- **Threaded scanning** for speed
- **Custom port ranges** (single ports, comma-separated, or ranges)
- **Banner grabbing** for HTTP/HTTPS and other common services
- **JSON & CSV export** for integration with SIEMs or further analysis
- **Standard library only** — no dependencies

---

## Usage

### Basic scan
```bash
python3 port_scanner.py scanme.nmap.org
