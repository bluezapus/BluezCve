import os
import time
import requests
from dotenv import load_dotenv

from .cache import init_cache, get_cache, set_cache
from .threat_intel import get_epss, is_known_exploited

# =========================
# ENV & CONFIG
# =========================
load_dotenv()

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

DEFAULT_DELAY = 1
RATE_LIMIT_SLEEP = 30


# =========================
# CORE REQUEST HANDLER
# =========================
def _request(url, params):
    api_key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}

    try:
        resp = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=30,
        )

        if resp.status_code == 429:
            time.sleep(RATE_LIMIT_SLEEP)
            return _request(url, params)

        resp.raise_for_status()
        time.sleep(DEFAULT_DELAY)
        return resp.json()

    except requests.RequestException as e:
        return {"error": str(e)}


# =========================
# CPE RESOLUTION (PRIMARY)
# =========================
def resolve_cpe(package: str, version: str, limit=20):
    data = _request(
        NVD_CPE_API,
        {
            "keywordSearch": package,
            "resultsPerPage": limit,
        },
    )

    cpes = []

    for item in data.get("products", []):
        cpe = item.get("cpe", {})
        cpe_name = cpe.get("cpeName")
        if not cpe_name:
            continue

        if version and version not in cpe_name:
            continue

        cpes.append(cpe_name)

    return list(set(cpes))


# =========================
# CVE QUERIES
# =========================
def query_cve_by_cpe(cpe_name: str):
    data = _request(
        NVD_CVE_API,
        {
            "cpeName": cpe_name,
            "resultsPerPage": 200,
        },
    )
    return data.get("vulnerabilities", [])


def query_cve_keyword(package: str, version: str):
    query = f"{package} {version}"
    data = _request(
        NVD_CVE_API,
        {
            "keywordSearch": query,
            "resultsPerPage": 100,
        },
    )
    return data.get("vulnerabilities", [])


# =========================
# PUBLIC ENTRY POINT
# =========================
def query_cve_package(package: str, version: str):
    cache_key = f"{package}:{version}"
    cached = get_cache(cache_key)
    if cached:
        return cached

    vulnerabilities = {}
    cpes = resolve_cpe(package, version)

    # --- CPE-FIRST ---
    for cpe in cpes:
        for v in query_cve_by_cpe(cpe):
            cve = v.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            v["epss"] = get_epss(cve_id)
            v["kev"] = is_known_exploited(cve_id)
            vulnerabilities[cve_id] = v

    # --- FALLBACK ---
    if not vulnerabilities:
        for v in query_cve_keyword(package, version):
            cve = v.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            v["epss"] = get_epss(cve_id)
            v["kev"] = is_known_exploited(cve_id)
            vulnerabilities[cve_id] = v

    result = {
        "vulnerabilities": list(vulnerabilities.values()),
        "meta": {
            "package": package,
            "version": version,
            "cpe_count": len(cpes),
            "mode": "CPE" if cpes else "KEYWORD",
            "api_used": bool(os.getenv("NVD_API_KEY")),
        },
    }

    set_cache(cache_key, result)
    return result


# init cache once
init_cache()
