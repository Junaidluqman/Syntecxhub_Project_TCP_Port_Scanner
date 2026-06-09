#!/usr/bin/env python3
"""
TCP Port Scanner
Author: Cybersecurity Intern Project
Description: A concurrent TCP port scanner with logging, exception handling,
             single-host or port-range scanning, and detailed result output.
"""

import socket
import threading
import argparse
import logging
import ipaddress
import queue
import sys
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
#  Logging Setup
# ─────────────────────────────────────────────
def setup_logger(log_file: str = "scan_results.log") -> logging.Logger:
    logger = logging.getLogger("PortScanner")
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger


# ─────────────────────────────────────────────
#  Common Service Names
# ─────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB"
}

def get_service(port: int) -> str:
    """Return known service name or try socket lookup."""
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


# ─────────────────────────────────────────────
#  Core Scanner
# ─────────────────────────────────────────────
class PortScanner:
    def __init__(self, timeout: float = 1.0, max_threads: int = 100,
                 log_file: str = "scan_results.log"):
        self.timeout = timeout
        self.max_threads = max_threads
        self.logger = setup_logger(log_file)
        self.results = {
            "open": [],
            "closed": [],
            "timeout": [],
            "error": []
        }
        self._lock = threading.Lock()

    def resolve_host(self, host: str) -> str:
        """Resolve hostname to IP address."""
        try:
            ip = socket.gethostbyname(host)
            self.logger.info(f"Resolved {host} → {ip}")
            return ip
        except socket.gaierror as e:
            self.logger.error(f"DNS resolution failed for '{host}': {e}")
            sys.exit(1)

    def scan_port(self, ip: str, port: int) -> dict:
        """Scan a single TCP port. Returns result dict."""
        result = {"port": port, "status": None, "service": get_service(port), "banner": ""}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                code = s.connect_ex((ip, port))
                if code == 0:
                    result["status"] = "open"
                    # Try banner grab
                    try:
                        s.settimeout(0.5)
                        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s.recv(1024).decode(errors="ignore").strip()
                        result["banner"] = banner[:80] if banner else ""
                    except Exception:
                        pass
                else:
                    result["status"] = "closed"

        except socket.timeout:
            result["status"] = "timeout"
        except ConnectionRefusedError:
            result["status"] = "closed"
        except PermissionError as e:
            result["status"] = "error"
            self.logger.warning(f"Permission denied on port {port}: {e}")
        except OSError as e:
            result["status"] = "error"
            self.logger.debug(f"OS error on port {port}: {e}")

        with self._lock:
            self.results[result["status"]].append(result)

        return result

    def scan(self, host: str, ports: list[int], verbose: bool = False) -> dict:
        """Run concurrent scan across all ports."""
        ip = self.resolve_host(host)
        total = len(ports)

        self.logger.info(f"Starting scan on {ip} | Ports: {total} | "
                         f"Threads: {self.max_threads} | Timeout: {self.timeout}s")

        start = datetime.now()
        completed = 0
        open_found = 0

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.scan_port, ip, p): p for p in ports}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    completed += 1
                    if result["status"] == "open":
                        open_found += 1
                        svc = result["service"]
                        banner = f"  ↳ {result['banner']}" if result["banner"] else ""
                        self.logger.info(
                            f"[OPEN]  Port {result['port']:>5}/tcp  ({svc}){banner}"
                        )
                    elif verbose:
                        self.logger.debug(
                            f"[{result['status'].upper():<7}] Port {result['port']:>5}/tcp"
                        )
                    # Progress indicator every 10%
                    if completed % max(1, total // 10) == 0:
                        pct = (completed / total) * 100
                        print(f"  Progress: {completed}/{total} ports ({pct:.0f}%)", end="\r")
                except Exception as e:
                    self.logger.error(f"Unexpected error: {e}")

        elapsed = (datetime.now() - start).total_seconds()
        self._print_summary(ip, total, elapsed)
        return self.results

    def _print_summary(self, ip: str, total: int, elapsed: float):
        """Print and log scan summary."""
        open_count = len(self.results["open"])
        closed_count = len(self.results["closed"])
        timeout_count = len(self.results["timeout"])
        error_count = len(self.results["error"])

        summary = f"""
{'='*55}
  SCAN SUMMARY — {ip}
{'='*55}
  Total Ports Scanned : {total}
  Open                : {open_count}
  Closed              : {closed_count}
  Timeout             : {timeout_count}
  Errors              : {error_count}
  Time Elapsed        : {elapsed:.2f}s
{'='*55}"""
        print(summary)
        self.logger.info(summary)

        if self.results["open"]:
            print("\n  OPEN PORTS:")
            print(f"  {'PORT':<8} {'SERVICE':<15} {'BANNER'}")
            print(f"  {'-'*7}  {'-'*14}  {'-'*30}")
            for r in sorted(self.results["open"], key=lambda x: x["port"]):
                banner = r["banner"][:35] if r["banner"] else "-"
                print(f"  {r['port']:<8} {r['service']:<15} {banner}")


# ─────────────────────────────────────────────
#  Port Range Utilities
# ─────────────────────────────────────────────
def parse_ports(port_str: str) -> list[int]:
    """
    Parse port argument like:
      80           → [80]
      80,443,8080  → [80, 443, 8080]
      1-1024       → [1, 2, ..., 1024]
      common       → top common ports
    """
    if port_str.lower() == "common":
        return list(COMMON_PORTS.keys())
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def validate_ip_or_host(target: str) -> str:
    """Validate IP or hostname format."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        if len(target) > 0 and "." in target or target == "localhost":
            return target
        raise argparse.ArgumentTypeError(f"Invalid host: {target}")


# ─────────────────────────────────────────────
#  CLI Entry Point
# ─────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="TCP Port Scanner — Cybersecurity Intern Project",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py -t 192.168.1.1 -p 1-1024
  python port_scanner.py -t scanme.nmap.org -p 22,80,443,8080
  python port_scanner.py -t 10.0.0.1 -p common --threads 200
  python port_scanner.py -t localhost -p 1-65535 --timeout 0.5 -v
        """
    )
    parser.add_argument("-t", "--target",  required=True,
                        help="Target host (IP or hostname)")
    parser.add_argument("-p", "--ports",   default="1-1024",
                        help="Ports: single, range (1-1024), list (80,443), or 'common'")
    parser.add_argument("--timeout",       type=float, default=1.0,
                        help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--threads",       type=int,   default=100,
                        help="Max concurrent threads (default: 100)")
    parser.add_argument("--log",           default="scan_results.log",
                        help="Log file path (default: scan_results.log)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show closed/timeout ports too")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Validate ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[ERROR] Invalid port specification: {e}")
        sys.exit(1)

    if not ports:
        print("[ERROR] No valid ports specified.")
        sys.exit(1)

    # Print banner
    print(f"""
╔══════════════════════════════════════════════════╗
║           TCP PORT SCANNER  v1.0                 ║
║           Junaid Intern Project           ║
╚══════════════════════════════════════════════════╝
  Target  : {args.target}
  Ports   : {len(ports)} ({args.ports})
  Timeout : {args.timeout}s
  Threads : {args.threads}
  Log     : {args.log}
""")

    scanner = PortScanner(
        timeout=args.timeout,
        max_threads=args.threads,
        log_file=args.log
    )

    try:
        scanner.scan(args.target, ports, verbose=args.verbose)
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        scanner._print_summary(args.target, len(ports), 0)
        sys.exit(0)


if __name__ == "__main__":
    main()
