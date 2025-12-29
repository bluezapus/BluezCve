import requests
import time

EPSS_API = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_epss_cache = {}
_kev_cache = None


def get_epss(cve_id):
    if cve_id in _epss_cache:
        return _epss_cache[cve_id]

    try:
        r = requests.get(EPSS_API, params={"cve": cve_id}, timeout=15)
        data = r.json().get("data", [])
        if data:
            score = float(data[0].get("epss", 0))
            _epss_cache[cve_id] = score
            return score
    except Exception:
        pass

    return 0.0


def load_kev():
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache

    try:
        r = requests.get(CISA_KEV_URL, timeout=30)
        vulns = r.json().get("vulnerabilities", [])
        _kev_cache = {v["cveID"] for v in vulns}
    except Exception:
        _kev_cache = set()

    return _kev_cache


def is_known_exploited(cve_id):
    kev = load_kev()
    return cve_id in kev
