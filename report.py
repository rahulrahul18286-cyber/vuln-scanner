"""
Report Generator Module
Exports vulnerability scan findings to CSV and HTML,
with a risk-level summary (Critical/High/Medium/Low).
"""
import csv
from datetime import datetime

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

CSS = """
body { font-family: Arial, sans-serif; background:#111; color:#eee; padding:20px; }
h1 { color:#a86efc; }
table { border-collapse: collapse; width:100%; margin-top:20px; }
th, td { border:1px solid #444; padding:8px; text-align:left; }
th { background:#222; color:#a86efc; }
.summary { display:flex; gap:20px; margin-top:15px; }
.card { background:#1e1e1e; padding:15px 20px; border-radius:8px; text-align:center; }
.card h2 { margin:0; font-size:28px; }
"""

SEVERITY_COLORS = {
    "CRITICAL": "#b30000",
    "HIGH": "#e63946",
    "MEDIUM": "#e9c46a",
    "LOW": "#2a9d8f",
    "UNKNOWN": "#888888",
    "INFO": "#457b9d"
}


def flatten_report(report):
    rows = []
    for host, findings in report.items():
        for f in findings:
            if not f["cves"]:
                rows.append({
                    "host": host, "port": f["port"], "protocol": f["protocol"],
                    "service": f["service"], "product": f["product"],
                    "version": f["version"], "cve_id": "-",
                    "severity": "INFO", "score": "-"
                })
            else:
                for c in f["cves"]:
                    rows.append({
                        "host": host, "port": f["port"], "protocol": f["protocol"],
                        "service": f["service"], "product": f["product"],
                        "version": f["version"], "cve_id": c["cve_id"],
                        "severity": (c["severity"] or "UNKNOWN").upper(),
                        "score": c["score"]
                    })
    return rows


def summarize_severity(rows):
    counts = {level: 0 for level in SEVERITY_ORDER}
    for row in rows:
        sev = row["severity"] if row["severity"] in counts else "UNKNOWN"
        counts[sev] += 1
    return counts


def export_csv(report, filename="vuln_report.csv"):
    rows = flatten_report(report)
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "host", "port", "protocol", "service",
            "product", "version", "cve_id", "severity", "score"
        ])
        writer.writeheader()
        writer.writerows(rows)
    print("[+] CSV report saved:", filename)


def build_row_html(r):
    color = SEVERITY_COLORS.get(r["severity"], "#888888")
    parts = [
        "<tr>",
        "<td>" + str(r["host"]) + "</td>",
        "<td>" + str(r["port"]) + "/" + str(r["protocol"]) + "</td>",
        "<td>" + str(r["service"]) + "</td>",
        "<td>" + str(r["product"]) + " " + str(r["version"]) + "</td>",
        "<td>" + str(r["cve_id"]) + "</td>",
        "<td style='color:" + color + "; font-weight:bold;'>" + str(r["severity"]) + "</td>",
        "<td>" + str(r["score"]) + "</td>",
        "</tr>"
    ]
    return "".join(parts)


def export_html(report, target, filename="vuln_report.html"):
    rows = flatten_report(report)
    counts = summarize_severity(rows)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows_html = ""
    for r in rows:
        rows_html += build_row_html(r)

    html_parts = []
    html_parts.append("<html><head><title>Vulnerability Scan Report</title>")
    html_parts.append("<style>" + CSS + "</style></head><body>")
    html_parts.append("<h1>Vulnerability Scan Report</h1>")
    html_parts.append("<p>Target: " + str(target) + " | Generated: " + timestamp + "</p>")
    html_parts.append("<div class='summary'>")
    html_parts.append("<div class='card'><h2 style='color:" + SEVERITY_COLORS["CRITICAL"] + "'>" + str(counts["CRITICAL"]) + "</h2>Critical</div>")
    html_parts.append("<div class='card'><h2 style='color:" + SEVERITY_COLORS["HIGH"] + "'>" + str(counts["HIGH"]) + "</h2>High</div>")
    html_parts.append("<div class='card'><h2 style='color:" + SEVERITY_COLORS["MEDIUM"] + "'>" + str(counts["MEDIUM"]) + "</h2>Medium</div>")
    html_parts.append("<div class='card'><h2 style='color:" + SEVERITY_COLORS["LOW"] + "'>" + str(counts["LOW"]) + "</h2>Low</div>")
    html_parts.append("</div>")
    html_parts.append("<table><tr><th>Host</th><th>Port</th><th>Service</th><th>Product/Version</th><th>CVE ID</th><th>Severity</th><th>Score</th></tr>")
    html_parts.append(rows_html)
    html_parts.append("</table></body></html>")

    with open(filename, "w") as f:
        f.write("".join(html_parts))
    print("[+] HTML report saved:", filename)
