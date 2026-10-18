# Nmap Scanner

A small command-line wrapper around Nmap for authorized network inventory and service inspection. It supports common scan profiles, custom ports, optional TCP/UDP banner collection, JSON output, and comparison with a previous scan.

> **Authorization:** Scan only systems you own or have explicit permission to assess. Use the tool responsibly and follow applicable laws and network policies.

## Features

- Quick, default, full TCP, service/version, OS, UDP, and NSE vulnerability scan profiles.
- IPv4/IPv6 addresses, CIDR ranges, and hostnames.
- Custom port lists and ranges (for example, `22,80,100-110`).
- Optional banner grabbing and risk labels for selected well-known ports.
- JSON output and comparison against a prior JSON scan.
- Terminal output with Rich.

## Requirements

- Python 3.9 or newer.
- Nmap installed separately and available on `PATH` (`nmap --version`).
- Administrator/root privileges may be required for OS detection, UDP scans, or certain Nmap options.

Install the Python dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

On macOS/Linux, activate the environment with `source .venv/bin/activate`.

## Usage

Run a service/version scan on an authorized host:

```powershell
python nmap_scanner2.py --target 192.168.1.10 --type service --output both
```

Scan selected ports and collect banners:

```powershell
python nmap_scanner2.py -t 192.168.1.10 --type quick --ports 22,80,443,8000-8010 --banner --output both
```

Compare a new scan to a prior result:

```powershell
python nmap_scanner2.py -t 192.168.1.10 --type service --diff scan_20260101_120000.json --output json
```

When `--yes` is omitted, the program asks you to confirm that you have permission to scan the target. `--yes` skips that prompt and should only be used when authorization is already established.

### Scan types

| Value | Alias | Description |
| --- | --- | --- |
| `1` | `quick` | Nmap fast scan of popular ports |
| `2` | `default` | Nmap default popular-port scan |
| `3` | `full` | Full TCP port range |
| `4` | `service` | Service/version detection |
| `5` | `os` | OS detection; usually requires elevated privileges |
| `6` | `udp` | UDP scan of popular ports; usually requires elevated privileges |
| `7` | `vuln` | Nmap NSE vulnerability scripts |

See all command-line options with `python nmap_scanner2.py --help`.

## Output and privacy

JSON scan reports are written to the current working directory as `scan_YYYYMMDD_HHMMSS.json`. Reports may contain target addresses, hostnames, open ports, detected services, versions, and banners. Review and sanitize them before sharing or committing them. The included `.gitignore` excludes generated scan reports by default.

Banner collection makes additional connections to discovered open ports. UDP services often do not respond to generic probes, so an empty banner does not mean that a port is closed or safe.

## Tests

Install dependencies, then run:

```powershell
python -m unittest discover -s tests -v
```

Unit tests cover input validation and result comparison. They do not perform network scans and do not replace testing against an authorized lab environment.

## Limitations

- This project wraps the local Nmap executable and depends on its behavior and version.
- Risk labels are simple port-based hints, not vulnerability findings or a substitute for security review.
- OS detection and UDP results depend on privileges, network filtering, and target responses.

## License

Distributed under the MIT License. See [LICENSE](LICENSE).
