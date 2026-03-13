def score_service(cves: list[dict]) -> dict:
    """
    Takes a list of CVEs for a service and returns
    a risk summary: score, severity label, and CVE counts.
    """

    if not cves:
        return {
            "score": 0.0,
            "severity": "NONE",
            "cve_count": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

    # count by severity bucket
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for cve in cves:
        sev = cve.get("severity", "").upper()
        if sev in counts:
            counts[sev] += 1

    # weighted score — critical CVEs drag the score up hard
    weights = {"CRITICAL": 1.0, "HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.1}
    scored_cves = [cve for cve in cves if cve.get("score") is not None]

    if not scored_cves:
        return {
            "score": 0.0,
            "severity": "UNKNOWN",
            "cve_count": len(cves),
            **counts
        }

    # weighted average of top 5 CVEs by score
    top_cves = sorted(scored_cves, key=lambda x: x["score"], reverse=True)[:5]
    total_weight = 0
    weighted_sum = 0

    for cve in top_cves:
        sev = cve.get("severity", "LOW").upper()
        w = weights.get(sev, 0.1)
        weighted_sum += cve["score"] * w
        total_weight += w

    final_score = round(weighted_sum / total_weight, 1) if total_weight else 0.0

    # overall severity label based on final score
    if final_score >= 9.0:
        severity = "CRITICAL"
    elif final_score >= 7.0:
        severity = "HIGH"
    elif final_score >= 4.0:
        severity = "MEDIUM"
    elif final_score > 0:
        severity = "LOW"
    else:
        severity = "NONE"

    return {
        "score": final_score,
        "severity": severity,
        "cve_count": len(cves),
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
    }


def score_overall(service_scores: list[dict]) -> dict:
    """
    Computes an overall risk score across all scanned services.
    """
    if not service_scores:
        return {"score": 0.0, "severity": "NONE"}

    scores = [s["score"] for s in service_scores if s["score"] > 0]

    if not scores:
        return {"score": 0.0, "severity": "NONE"}

    # overall = average of top 3 service scores
    top_scores = sorted(scores, reverse=True)[:3]
    overall = round(sum(top_scores) / len(top_scores), 1)

    if overall >= 9.0:
        severity = "CRITICAL"
    elif overall >= 7.0:
        severity = "HIGH"
    elif overall >= 4.0:
        severity = "MEDIUM"
    elif overall > 0:
        severity = "LOW"
    else:
        severity = "NONE"

    return {"score": overall, "severity": severity}


if __name__ == "__main__":
    # test with the dnsmasq CVEs from Phase 2
    from nvd_client import fetch_cves

    cves = fetch_cves("dnsmasq", "2.51")
    result = score_service(cves)

    print(f"\nService Risk Summary:")
    print(f"  Score    : {result['score']} / 10")
    print(f"  Severity : {result['severity']}")
    print(f"  CVEs     : {result['cve_count']} total")
    print(f"  Critical : {result['critical']}")
    print(f"  High     : {result['high']}")
    print(f"  Medium   : {result['medium']}")
    print(f"  Low      : {result['low']}")