from .utils import get_severity_from_score


def extract_cve_info(cve_data):
    cve_items = []
    for item in cve_data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        desc = (
            cve.get("descriptions", [{}])[0].get("value") or "No description available."
        )
        metrics = cve.get("metrics", {})
        score = "N/A"
        severity = "UNKNOWN"

        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics:
                score = metrics[key][0].get("cvssData", {}).get("baseScore", "N/A")
                severity = get_severity_from_score(score)
                break

        link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        cve_items.append(
            {
                "id": cve_id,
                "desc": desc,
                "severity": severity,
                "score": score,
                "link": link,
            }
        )

    return cve_items
