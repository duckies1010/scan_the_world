#!/usr/bin/env python3
"""Nmap scanner wrapper.

Install Nmap separately, then install Python dependencies with
``python -m pip install -r requirements.txt``.

Examples:
    python nmap_scanner2.py -t 192.168.1.1 --type service -b -p 22,80,100-110 --output both
    python nmap_scanner2.py -t 192.168.1.1 --type service --diff scan_old.json

Only scan systems you own or are explicitly authorized to assess.
"""

import argparse
import contextlib
import io
import ipaddress
import json
import logging
import os
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import ssl
import nmap
from rich import box
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (BarColumn, MofNCompleteColumn, Progress,
                           SpinnerColumn, TextColumn, TimeElapsedColumn)
from rich.table import Table
from rich.text import Text



console = Console()
log = logging.getLogger("scanner")

# Type of scan: (name, nmap arg, root need)
SCAN_TYPES = {
    "1": ("Quick scan (100 popular ports)",        "-F -T4",                      False),
    "2": ("Default scan 1000 popular ports",       "-T4",                         False),
    "3": ("Full scan (65535 ports)",               "-p- -T4",                     False),
    "4": ("Service and version detection",         "-sV -T4",                     False),
    "5": ("Operation system detection",            "-O -T4",                      True),
    "6": ("UDP scan (100 popular ports)",          "-sU --top-ports 100 -T4",     True),
    "7": ("Vulnerabilities detection (NSE vuln)",  "-sV --script vuln -T4",       False),
}

TYPE_ALIASES = {
    "quick": "1", "default": "2", "full": "3", "service": "4",
    "os": "5", "udp": "6", "vuln": "7",
}
HTTP_PORTS = {80, 8000, 8080, 8888}
HTTPS_PORTS = {443, 8443}
TLS_PORTS = HTTPS_PORTS | {465, 636, 993, 995} 

TCP_PROBES = {
    6379: b"INFO server\r\n",   # Redis
    11211: b"version\r\n",      # Memcached
}


UDP_PROBES = {
    # DNS: query CHAOS TXT version.bind
    53: (b"\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x07version\x04bind\x00\x00\x10\x00\x03"),
    # NTP: client mode (LI=0, VN=3, Mode=3), 48 byte
    123: b"\x1b" + b"\x00" * 47,
    # NetBIOS: NBSTAT query show name "*"
    137: (b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00"
          b"\x20" + b"CK" + b"A" * 30 + b"\x00" + b"\x00\x21\x00\x01"),
    # SNMPv1 GetRequest sysDescr.0, community "public"
    161: (b"\x30\x29\x02\x01\x00\x04\x06public\xa0\x1c\x02\x04\x00\x00\x00\x01"
          b"\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"),
    # SSDP / UPnP: M-SEARCH
    1900: (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'),
}
UDP_DEFAULT_PROBE = b"\r\n"  # UDP ports not in UDP_PROBES

level_risk = {
    21: "HIGH",     # FTP
    23: "HIGH",     # Telnet
    69: "HIGH",     # TFTP
    135: "HIGH",    # MSRPC
    139: "HIGH",    # NetBIOS
    445: "HIGH",    # SMB
    1433: "HIGH",   # MS SQL
    3389: "HIGH",   # RDP (Remote Desktop)

    111: "MEDIUM",  # rpcbind
    137: "MEDIUM",  # NetBIOS name service
    161: "MEDIUM",  # SNMP
    1900: "MEDIUM", # SSDP/UPnP
    3306: "MEDIUM", # MySQL
    5432: "MEDIUM", # PostgreSQL
    6379: "MEDIUM", # Redis
    27017: "MEDIUM",# MongoDB

    22: "LOW",      # SSH
    53: "LOW",      # DNS
    80: "LOW",      # HTTP
    123: "LOW",     # NTP
    443: "LOW",     # HTTPS
    8080: "LOW",    # HTTP Alternate
    8443: "LOW",    # HTTPS Alternate
}
RISK_STYLES = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "green", "UNKNOWN": ""}




def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Nmap scanner wrapper (only permitted system).",
        epilog="Example: python scanner.py -t 192.168.1.1 --type quick --output json -y",
    )
    p.add_argument("-t", "--target", required=True, help="IP / CIDR / hostname")
    p.add_argument("--type", choices=TYPE_ALIASES, default="quick", help="Scan type (default: quick)")
    p.add_argument("--output", choices=["table", "json", "both"], default="table",
                   help="table: show only | json: save file | both: both table and save file")
    p.add_argument("-b", "--banner", action="store_true", help="Banner grabbing open ports (TCP + UDP)")
    p.add_argument("-p", "--ports", help="Custom ports, e.g. 22,80,100-110 (overrides the port range of --type)")
    p.add_argument("--diff", metavar="OLD.json", help="Compare with a previous JSON scan file") 
    p.add_argument("--threads", type=positive_int, default=50, help="Banner grabbing worker count (default: 50)")
    p.add_argument("--timeout", type=positive_float, default=3.0, help="Banner read timeout in seconds (default: 3)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Confirm you have permission to scan the target (skip confirmation prompt)")
    p.add_argument("-v", "--verbose", action="store_true", help="Turn on log DEBUG")
    p.add_argument("--log-file", help="Save log to file")
    return p.parse_args(argv)


def positive_int(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("must be a positive integer")
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def positive_float(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("must be a positive number")
    if not 0 < number < float("inf"):
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return number


def setup_logging(verbose=False, log_file=None):
    handlers = [RichHandler(console=console, show_path=False, markup=False)]
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        handlers.append(fh)
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(message)s", handlers=handlers, force=True)



def valid_target(target):
    if not isinstance(target, str) or not target or target.startswith("-"):
        return False
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        if target.endswith("."):
            target = target[:-1]
        labels = target.split(".")
        return len(target) <= 253 and bool(target) and all(
            len(label) <= 63
            and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
            for label in labels
        )


def valid_port(port):
    if not port.isdigit():
        raise ValueError("Invalid port number: {}".format(port))
    port = int(port)
    if port < 1 or port > 65535:
        raise ValueError("Port number must be between 1 and 65535: {}".format(port))
    return True


def parse_ports(text):
    ports = set()
    if not text:
        raise ValueError("Input cannot be empty.")
    for part in text.split(','):
        part = part.strip()
        if "-" in part:
            if part.count('-') != 1:
                raise ValueError("Invalid port range: {}".format(part))
            start, end = part.split('-')
            valid_port(start)
            valid_port(end)
            if int(start) > int(end):
                raise ValueError("Invalid port range: {}".format(part))
            ports.update(range(int(start), int(end) + 1))
        else:
            valid_port(part)
            ports.add(int(part))
    return sorted(ports)


def format_ports(ports):
    if not ports:
        return ""
    parts = []
    start = prev = ports[0]
    for p in ports[1:] + [None]:
        if p is not None and p == prev + 1:
            prev = p
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = p
    return ",".join(parts)


def build_port_args(args, ports):
    kept, skip = [], False
    for tok in args.split():
        if skip:
            skip = False
            continue
        if tok in ("-F", "-p-"):
            continue
        if tok == "--top-ports":
            skip = True
            continue
        kept.append(tok)
    return " ".join(kept + ["-p", format_ports(ports)])


def risk_level(port):
    return level_risk.get(port, "UNKNOWN")


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def choose_scan():
    print("\n=== Choose scan type ===")
    for key, (name, _, root) in SCAN_TYPES.items():
        print(f" {key}. {name}" + ("  [need root permission]" if root else ""))
    while True:
        choice = input("Number: ").strip()
        if choice in SCAN_TYPES:
            return SCAN_TYPES[choice]
        print("Invalid choice.")



def run_scan(target, args):
    scanner = nmap.PortScanner()
    print(f"\nScanning {target} with: nmap {args} ... (Can take a few times)")
    scanner.scan(hosts=target, arguments=args)
    return scanner


def run_scan_with_progress(target, args):
    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                  TimeElapsedColumn(), console=console, transient=True) as progress:
        progress.add_task(f"nmap {args} -> {target}", total=None)
        return run_scan(target, args)



def show_results(scanner):
    results = {}
    if not scanner.all_hosts():
        print("No hosts are alive")
        return results

    for host in scanner.all_hosts():
        info = scanner[host]
        print(f"\n▶ {host} ({info.hostname() or 'no hostname'}) - {info.state()}")
        results[host] = {"hostname": info.hostname(), "state": info.state(), "ports": []}

        if info.get("osmatch"):
            best = info["osmatch"][0]
            print(f"  OS: {best['name']} ({best['accuracy']}%)")
            results[host]["os"] = best["name"]

        for proto in info.all_protocols():
            print(f"  {'PORT':<10}{'STATE':<10}{'SERVICE':<14}VERSION")
            for port in sorted(info[proto]):
                p = info[proto][port]
                if p["state"] != "open":
                    continue
                version = f"{p['product']} {p['version']}".strip()
                print(f"  {str(port) + '/' + proto:<10}{p['state']:<10}{p['name']:<14}{version}")
                results[host]["ports"].append(
                    {"port": port, "proto": proto, "service": p["name"], "version": version}
                )
    return results


def collect_results(scanner):
    with contextlib.redirect_stdout(io.StringIO()):
        return show_results(scanner)


def add_risk(results):  # NEW
    for info in results.values():
        for p in info["ports"]:
            p["risk"] = risk_level(p["port"])
    return results



def printable_lines(data): 
    """Retain only printable ASCII sequences (length >= 3). Since the banner originates from an untrusted server, 
    control and escape characters are stripped to prevent terminal escape sequence injection while keeping binary 
    service banners (such as MySQL, DNS, and SNMP) readable."""
    return [r.decode("ascii") for r in re.findall(rb"[\x20-\x7e]{3,}", data)]


def format_banner(data, header_only=False):
    lines = printable_lines(data)
    if header_only:
        lines = [l for i, l in enumerate(lines) if i == 0 or l.lower().startswith("server:")]
    if not lines and data:
        return f"<{len(data)} bytes binary>"
    return " | ".join(l.strip() for l in lines if l.strip())[:150]


def grab_banner(host, port, timeout=3.0):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in TLS_PORTS:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                s = context.wrap_socket(s, server_hostname = host)
            if port in HTTP_PORTS or port in HTTPS_PORTS:
                s.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            elif port in TCP_PROBES:
                s.sendall(TCP_PROBES[port])
            data = s.recv(1024)
            s.close()
    except OSError as e:  # Included socket.timeout, ConnectionRefused...
        log.debug("Banner %s:%s failed: %s", host, port, e)
        return ""
    return format_banner(data, header_only=(port in HTTP_PORTS or port in HTTPS_PORTS))


def grab_banner_udp(host, port, timeout=3.0):
    probe = UDP_PROBES.get(port, UDP_DEFAULT_PROBE)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.send(probe)
            data = s.recv(2048)
    except OSError as e:
        log.debug("UDP banner %s:%s failed: %s", host, port, e)
        return ""
    return format_banner(data, header_only=(port == 1900))


def grab_banners(results, timeout=3.0, workers=50):
    with ThreadPoolExecutor(max_workers=workers) as ex, \
        Progress(SpinnerColumn(), TextColumn("Banner grabbing"), BarColumn(),
                MofNCompleteColumn(), console=console, transient=True) as progress:
        task = progress.add_task("banner", total=None)
        jobs = {}
        for host, info in results.items():
            for p in info["ports"]:
                if p["proto"] == "tcp":
                    jobs[ex.submit(grab_banner, host, p["port"], timeout)] = p
                elif p["proto"] == "udp":
                    jobs[ex.submit(grab_banner_udp, host, p["port"], timeout)] = p
        progress.update(task, total=len(jobs))
        for fut in as_completed(jobs):
            jobs[fut]["banner"] = fut.result()
            progress.advance(task)
    return results



def diff_results(old_data, new_data):
    differences = {}
    all_hosts = sorted(set(old_data.keys()) | set(new_data.keys()))

    for host in all_hosts:
        old_host = old_data.get(host, {"ports": []})
        new_host = new_data.get(host, {"ports": []})

        old_ports = {(p['port'], p['proto']): p for p in old_host.get("ports", [])}
        new_ports = {(p['port'], p['proto']): p for p in new_host.get("ports", [])}

        old_keys = set(old_ports.keys())
        new_keys = set(new_ports.keys())

        opened_keys = sorted(new_keys - old_keys)
        closed_keys = sorted(old_keys - new_keys)
        common_keys = sorted(old_keys & new_keys)

        changed_ports = []
        for k in common_keys:
            old_p = old_ports[k]
            new_p = new_ports[k]
            if old_p.get("version") != new_p.get("version") or old_p.get("service") != new_p.get("service"):
                changed_ports.append({
                    "port": k[0],
                    "proto": k[1],
                    "old_service": old_p.get("service", ""),
                    "new_service": new_p.get("service", ""),
                    "old_version": old_p.get("version", ""),
                    "new_version": new_p.get("version", ""),
                })

        status = "new" if host not in old_data else "gone" if host not in new_data else "same"
        differences[host] = {
            "status": status, 
            "opened": [new_ports[k] for k in opened_keys],
            "closed": [old_ports[k] for k in closed_keys],
            "changed": changed_ports
        }
    return differences


def load_scan_file(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("hosts"), dict):
        raise ValueError(f"Not a scan file: {path}")
    for host, info in data["hosts"].items():
        if not isinstance(host, str) or not isinstance(info, dict) or not isinstance(info.get("ports", []), list):
            raise ValueError(f"Invalid host data in scan file: {path}")
        for port in info.get("ports", []):
            if (not isinstance(port, dict) or type(port.get("port")) is not int
                    or not 1 <= port["port"] <= 65535
                    or port.get("proto") not in ("tcp", "udp")):
                raise ValueError(f"Invalid port data in scan file: {path}")
    return data



def show_results_table(results):
    for host, info in results.items():
        title = f"{host} ({info['hostname'] or 'no hostname'}) - {info['state']}"
        if info.get("os"):
            title += f" | OS: {info['os']}"
        table = Table(title=title, box=box.ROUNDED, header_style="bold cyan")
        table.add_column("PORT", style="green")
        table.add_column("SERVICE", style="yellow")
        table.add_column("RISK")
        table.add_column("VERSION")
        has_banner = any("banner" in p for p in info["ports"])
        if has_banner:
            table.add_column("BANNER", style="magenta")
        for p in info["ports"]:
            risk = p.get("risk", risk_level(p["port"]))
            row = [f"{p['port']}/{p['proto']}", p["service"],
                   Text(risk, style=RISK_STYLES[risk]), Text(p["version"])]
            if has_banner:
                row.append(Text(p.get("banner", ""))) 
            table.add_row(*row)
        console.print(table)


def show_diff(differences):
    shown = False
    for host, d in differences.items():
        if d["status"] == "same" and not (d["opened"] or d["closed"] or d["changed"]):
            continue 
        shown = True
        title = host + {"new": " (NEW HOST)", "gone": " (HOST NOT RESPONDING)", "same": ""}[d["status"]]
        table = Table(title=title, box=box.ROUNDED, header_style="bold cyan")
        table.add_column("CHANGE")
        table.add_column("PORT")
        table.add_column("DETAIL")
        for p in d["opened"]:
            detail = f"{p['service']} {p['version']}".strip()
            table.add_row(Text("+ OPENED", style="bold red"), f"{p['port']}/{p['proto']}", Text(detail))
        for p in d["closed"]:
            detail = f"{p['service']} {p['version']}".strip()
            table.add_row(Text("- CLOSED", style="green"), f"{p['port']}/{p['proto']}", Text(detail))
        for c in d["changed"]:
            detail = (f"{c['old_service']} {c['old_version']}".strip() + " -> "
                      + f"{c['new_service']} {c['new_version']}".strip())
            table.add_row(Text("~ CHANGED", style="yellow"), f"{c['port']}/{c['proto']}", Text(detail))
        if table.row_count == 0:
            table.add_row(Text("(no open ports recorded)", style="dim"), "", "")
        console.print(table)
    if not shown:
        console.print("[green]No changes compared to the previous scan.[/green]")


def save_results(results, scan_name, target):
    filename = f"scan_{datetime.now():%Y%m%d_%H%M%S}.json"
    data = {"scan": scan_name, "target": target, "time": datetime.now().isoformat(), "hosts": results}
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"\n[+] Save results: {filename}")



def main():
    name, args, needs_root = choose_scan()

    target = input("Target (IP / CIDR / hostname): ").strip()
    if not valid_target(target):
        print("Invalid target.")
        sys.exit(1)

    if input("Do you have permission to scan this target? (y/n): ").strip().lower() != "y":
        print("Cancelled.")
        sys.exit(0)

    try:
        scanner = run_scan(target, args)
    except nmap.PortScannerError as e:
        hint = "  -> Need sudo permission." if needs_root else ""
        print(f"Nmap error: {e}{hint}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(130)

    results = show_results(scanner)
    if results:
        save_results(results, name, target)


def main_cli(argv=None):
    ns = parse_args(argv)
    setup_logging(ns.verbose, ns.log_file)

    name, args, needs_root = SCAN_TYPES[TYPE_ALIASES[ns.type]]

    if not valid_target(ns.target):
        log.error("Invalid target: %s", ns.target)
        return 1

    label = name 
    if ns.ports:
        try:
            ports = parse_ports(ns.ports)
        except ValueError as e:
            log.error("Invalid --ports: %s", e)
            return 1
        args = build_port_args(args, ports)
        label = f"{name} [ports: {format_ports(ports)}]"

    old_scan = None
    if ns.diff:
        try:
            old_scan = load_scan_file(ns.diff)
        except (OSError, ValueError) as e:
            log.error("Cannot read --diff file: %s", e)
            return 1
        if old_scan.get("scan") != label:
            log.warning("Previous scan type differs ('%s' vs '%s'): the diff may show false changes.",
                        old_scan.get("scan"), label)

    if not ns.yes and input("Do you have permission to scan this target? (y/n): ").strip().lower() != "y":
        log.warning("Cancelled.")
        return 0
    if needs_root and not is_root():
        log.warning("Scan type '%s' thường cần quyền root/sudo.", ns.type)

    log.info("Scan: %s | target: %s", label, ns.target)
    try:
        scanner = run_scan_with_progress(ns.target, args)
    except nmap.PortScannerError as e:
        log.error("Nmap error: %s%s", e, "  -> Need sudo permission." if needs_root else "")
        return 1
    except KeyboardInterrupt:
        log.warning("Stopped.")
        return 130

    results = collect_results(scanner)
    if not results:
        log.warning("No hosts are alive")
        if old_scan:
            show_diff(diff_results(old_scan["hosts"], {}))
        return 0

    add_risk(results)
    if ns.banner:
        grab_banners(results, ns.timeout, ns.threads)
    show_results_table(results)
    if old_scan:
        show_diff(diff_results(old_scan["hosts"], results))
    if ns.output in ("json", "both"):
        save_results(results, label, ns.target)
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(main_cli())
    main()
