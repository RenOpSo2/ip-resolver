# IP Cr4ck3r

Summary
Lightweight domain → IP resolver. Supports interactive + batch modes, IPv4/IPv6 resolution, and optional DNS record lookup (A/AAAA/CNAME/MX) if dnspython is installed.

Requirements

· Python 3.10.x (tested with Python 3.10.*)
· Install dependencies: pip install -r requirements.txt

Installation

1. Clone the repo:
   ```bash
   git clone https://github.com/RenOpSo2/ip-resolver
   cd ip-resolver
   ```
2. (Optional) Create a virtual environment:
   ```bash
   python3.10 -m venv .venv
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

Usage

Interactive Mode

```bash
python3.10 crack.py
```

· Enter a domain or URL (e.g., example.com or https://example.com/path)
· Type q or press Ctrl-C to exit

Batch Mode (File Input)

1. Create examples/domains.txt (one domain/URL per line)
2. Run:

```bash
python3.10 crack.py --batch examples/domains.txt --out results.json --format json
```

Features

· Supports IPv4 & IPv6 resolution (via socket.getaddrinfo)
· Optional DNS record lookup using dnspython (A/AAAA/CNAME/MX)
· Graceful Ctrl-C handling
· Interactive UI using rich (spinner + table)

Ethics & Disclaimer
This tool is intended for educational purposes and network troubleshooting only. Do not use it against systems you do not own or without explicit permission. The author is not responsible for any misuse.

Contributing

· Open an issue or submit a PR
· Tag good first issue if you want to help with features/tests

License
MIT — see LICENSE file