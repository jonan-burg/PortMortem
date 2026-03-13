import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_cves(product: str, version: str) -> list[dict]:
    """
    Queries the NVD API for CVEs matching a product and version.
    Returns a list of CVE dicts with id, description, and CVSS score.
    """

    if not product:
        return []

    # Build the search keyword e.g. "dnsmasq 2.51"
    keyword = product

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 20,
    }

    try:
        print(f"  [~] Looking up CVEs for: {keyword}")
        response = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"  [!] NVD API error for {keyword}: {e}")
        return []

    cves = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")

        # grab the english description
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d["lang"] == "en"),
            "No description available."
        )

        # grab CVSS v3 score if available, fall back to v2
        score = None
        severity = "UNKNOWN"
        metrics = cve.get("metrics", {})

        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            score = cvss_data.get("baseScore")
            severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")

        cves.append({
            "id": cve_id,
            "description": description[:200],  # trim long descriptions
            "score": score,
            "severity": severity,
        })

    # sort by score descending so worst CVEs come first
    cves.sort(key=lambda x: x["score"] or 0, reverse=True)

    # NVD rate limits: be polite with a small delay between calls
    time.sleep(0.6)

    return cves


if __name__ == "__main__":
    # Quick test using our dnsmasq result from Phase 1
    results = fetch_cves("dnsmasq", "2.51")
    print(f"\nFound {len(results)} CVEs:\n")
    for cve in results:
        print(f"  {cve['id']}  |  Score: {cve['score']}  |  {cve['severity']}")
        print(f"  {cve['description'][:120]}")
        print()