import argparse
from scanner import run_scan
from nvd_client import fetch_cves
from scorer import score_service, score_overall
from reporter import print_banner, print_results, save_html_report


def main():
    parser = argparse.ArgumentParser(
        description="PortMortem — CVE Risk Scorer"
    )
    parser.add_argument("--target", required=True, help="IP address or range to scan")
    parser.add_argument("--report", action="store_true", help="Save an HTML report")
    args = parser.parse_args()

    print_banner()

    # Phase 1 — scan
    services = run_scan(args.target)

    if not services:
        print("No open ports found. Exiting.")
        return

    # Phase 2 & 3 — CVE lookup + scoring
    enriched = []
    for svc in services:
        cves = fetch_cves(svc["product"] or svc["service"], svc["version"])
        risk = score_service(cves)
        enriched.append({**svc, "cves": cves, "risk": risk})

    # overall score
    overall = score_overall([e["risk"] for e in enriched])

    # Phase 4 — output
    print_results(enriched, args.target, overall)

    if args.report:
        save_html_report(enriched, args.target, overall)


if __name__ == "__main__":
    main()