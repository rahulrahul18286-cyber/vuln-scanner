"""
CVE Lookup Module
Queries the NVD (National Vulnerability Database) API for known
vulnerabilities matching a given product/service.
"""
import requests
import time

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def lookup_cve(product, version, max_results=5):
    """
    Searches NVD for CVEs matching a product.

    Args:
        product (str): service/product name (e.g. "OpenSSH")
        version (str): version string (kept for future filtering)
        max_results (int): max number of CVEs to return

    Returns:
        list of dicts: [{cve_id, severity, score, description}, ...]
    """
    if not product:
        return []

    # NVD's keywordSearch matches an exact phrase against CVE
    # descriptions. Version strings like "8.2p1" rarely appear
    # verbatim (descriptions usually say "before 8.3"), so we
    # search by product name only.
    query = product.strip()

    params = {
        "keywordSearch": query,
        "resultsPerPage": max_results
    }

    try:
        response = requests.get(NVD_API_URL, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"[!] NVD API error for '{query}': {e}")
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        severity, score = "UNKNOWN", None
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]["cvssData"]
            severity, score = m.get("baseSeverity", "UNKNOWN"), m.get("baseScore")
        elif "cvssMetricV30" in metrics:
            m = metrics["cvssMetricV30"][0]["cvssData"]
            severity, score = m.get("baseSeverity", "UNKNOWN"), m.get("baseScore")
        elif "cvssMetricV2" in metrics:
            m = metrics["cvssMetricV2"][0]
            severity, score = m.get("baseSeverity", "UNKNOWN"), m["cvssData"].get("baseScore")

        results.append({
            "cve_id": cve_id,
            "severity": severity,
            "score": score,
            "description": description[:150] + ("..." if len(description) > 150 else "")
        })

    return results


if __name__ == "__main__":
    product = input("Enter product name (e.g. OpenSSH): ")
    version = input("Enter version (e.g. 8.2p1): ")

    cves = lookup_cve(product, version)

    if not cves:
        print("No CVEs found (or API error).")
    else:
        print(f"\nFound {len(cves)} CVE(s) for {product} {version}:\n")
        for c in cves:
            print(f"  {c['cve_id']} | Severity: {c['severity']} | Score: {c['score']}")
            print(f"    {c['description']}\n")
