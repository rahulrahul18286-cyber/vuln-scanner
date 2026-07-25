# Python Vulnerability Scanner

A command-line vulnerability scanner that combines Nmap-based network
reconnaissance with automated CVE lookup (NVD API) and risk-classified
report generation.

## Features
- Host discovery and port scanning (via Nmap)
- Service and version detection
- Automated CVE lookup against the National Vulnerability Database (NVD)
- Risk classification (Critical / High / Medium / Low)
- CSV and color-coded HTML report generation

## Tech Stack
- Python 3
- Nmap (via python-nmap)
- NVD REST API (requests)

## Installation
```bash
git clone https://github.com/rahulrahul18286-cyber/vuln-scanner.git
cd vuln-scanner
python3 -m venv venv
source venv/bin/activate
pip install python-nmap requests
```

## Usage
```bash
python3 main.py -t <target_ip> -p <port_range> -o <report_name>
```

Example:
```bash
python3 main.py -t 10.10.10.10 -p 1-1024 -o scan1
```

| Flag | Description | Default |
|------|-------------|---------|
| `-t` | Target IP / domain | required |
| `-p` | Port range (e.g. `1-1024`, `22,80,443`) | `1-1024` |
| `-o` | Base filename for output reports | `vuln_report` |

## Optional: Run as a system-wide command
To run the tool from anywhere as `vulnscan` (like `nmap`), instead of
`python3 main.py`:

```bash
chmod +x main.py
sudo ln -sf $(pwd)/main.py /usr/local/bin/vulnscan
```

Make sure the first line (shebang) of `main.py` points to your venv's
Python path, e.g.:
#!/home/<your-username>/vuln-scanner/venv/bin/python3
Then run from any directory:
```bash
vulnscan -t 10.10.10.10 -p 1-1024 -o scan1
```

## Sample Output
The tool generates:
- `<name>.csv` — raw findings for spreadsheet analysis
- `<name>.html` — color-coded severity report with summary cards

## Disclaimer
This tool is intended for authorized security testing only — use it
only against systems and networks you own or have explicit permission
to test (e.g. TryHackMe, HackTheBox, personal lab VMs). Unauthorized
scanning of networks is illegal.

## Project Background
Built as a hands-on home-lab project to practice vulnerability
assessment workflows: reconnaissance → CVE correlation → risk
prioritization → reporting, aligned with SOC analyst / vulnerability
management fundamentals.
