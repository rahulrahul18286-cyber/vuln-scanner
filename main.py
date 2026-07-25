#!/home/kali/vuln-scanner/venv/bin/python3
"""
Main Vulnerability Scanner
Combines Nmap scanning + CVE lookup into one end-to-end tool.
"""
import time
import argparse
from scanner import scan_target
from cve_lookup import lookup_cve
from report import export_csv, export_html


def run_full_scan(target, ports="1-1024"):
    """
    Runs a full vulnerability scan: port/service scan + CVE lookup
    for each detected service.

    Returns:
        dict: host -> list of service findings (with CVEs attached)
    """
    print(f"\n{'='*60}")
    print(f"  VULNERABILITY SCAN REPORT - Target: {target}")
    print(f"{'='*60}\n")

    scan_data = scan_target(target, ports)
    report = {}

    for host, info in scan_data.items():
        report[host] = []

        for svc in info["services"]:
            product = svc.get("product", "") or svc.get("service", "")
            version = svc.get("version", "")

            print(f"[*] Checking CVEs for {product} {version} "
                  f"(port {svc['port']}/{svc['protocol']}) ...")

            cves = []
            if product:
                cves = lookup_cve(product, version, max_results=3)
                time.sleep(2)

            report[host].append({
                "port": svc["port"],
                "protocol": svc["protocol"],
                "service": svc["service"],
                "product": product,
                "version": version,
                "cves": cves
            })

    return report


def print_report(report):
    for host, findings in report.items():
        print(f"\nHost: {host}")
        print("-" * 60)
        for f in findings:
            print(f"  Port {f['port']}/{f['protocol']} - {f['service']} "
                  f"{f['product']} {f['version']}")
            if not f["cves"]:
                print("     No CVEs found.")
            else:
                for c in f["cves"]:
                    print(f"     -> {c['cve_id']} | {c['severity']} "
                          f"(score {c['score']})")
        print()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Python-based vulnerability scanner (Nmap + NVD CVE lookup)."
    )
    parser.add_argument("-t", "--target", help="Target IP, domain, or range")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Port range, e.g. 1-1024 or 22,80,443 (default: 1-1024)")
    parser.add_argument("-o", "--output", default="vuln_report",
                         help="Base filename for reports (default: vuln_report)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    # Fall back to interactive prompt if no -t flag was given,
    # so the tool still works the old way if run with no arguments.
    target = args.target or input("Enter target IP/domain: ")

    report = run_full_scan(target, ports=args.ports)
    print_report(report)
    export_csv(report, filename=f"{args.output}.csv")
    export_html(report, target, filename=f"{args.output}.html")
