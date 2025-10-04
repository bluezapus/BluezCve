import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("0da7574d-b35a-400c-aa5a-e1e1f29490c9")

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _safe_get_json(resp):
    try:
        return resp.json()
    except ValueError:
        return {}

def _merge_vulnerabilities(list_of_lists):
    merged = {}
    for lst in list_of_lists:
        for item in lst:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                key = str(item)
            else:
                key = cve_id
            if key not in merged:
                merged[key] = item
    return list(merged.values())

def _perform_request(params, headers, delay, retries=2):
    attempt = 0
    while attempt <= retries:
        try:
            resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=30)
            if resp.status_code == 429:
                wait = 30 + attempt * 10
                print(f"[!] Rate limit from NVD (429). Sleeping {wait}s and retrying...")
                time.sleep(wait)
                attempt += 1
                continue
            resp.raise_for_status()
            time.sleep(delay)
            return _safe_get_json(resp)
        except requests.exceptions.RequestException as e:
            attempt += 1
            if attempt > retries:
                print(f"[!] Request failed for params={params}: {e}")
                return {}
            else:
                backoff = 5 * attempt
                print(f"[!] Request error, retrying in {backoff}s... ({e})")
                time.sleep(backoff)
    return {}

def query_cve(package, version=None, delay=1):
    """
    Query NVD with smarter keyword combinations.
    - Jika package bernama 'linux' atau 'kernel', buat beberapa variasi query
      (mis. "linux 5.8", "linux kernel 5.8", "linux pipe", dll) untuk menangkap CVE kernel.
    - Mengembalikan dict: {"vulnerabilities": [...]}
    """
    headers = {"apiKey": API_KEY} if API_KEY else {}

    queries = []
    base_pkg = (package or "").strip().lower()

    if base_pkg in ("linux", "kernel"):
        if version:
            queries.extend(
                [
                    f"linux {version}",
                    f"linux kernel {version}",
                    f"kernel {version}",
                ]
            )
        else:
            queries.extend(
                [
                    "linux kernel",
                ]
            )
    else:

        if version:
            queries.extend(
                [
                    f"{package} {version}",
                    f"{package} {version} vulnerability",
                    f"{package} {version} cve",
                    f"{package} {version} security",
                ]
            )
        else:
            queries.extend([f"{package}", f"{package} vulnerability", f"{package} cve"])

    seen = set()
    uniq_queries = []
    for q in queries:
        if q not in seen:
            uniq_queries.append(q)
            seen.add(q)

    all_vulns_lists = []
    for q in uniq_queries:
        params = {"keywordSearch": q, "resultsPerPage": 50}
        data = _perform_request(params, headers, delay)
        if not data:
            continue
        vulns = data.get("vulnerabilities", [])
        if vulns:
            print(f"[i] Found {len(vulns)} results for query: '{q}'")
            all_vulns_lists.append(vulns)
        else:
            pass

    merged = _merge_vulnerabilities(all_vulns_lists)
    return {"vulnerabilities": merged}


def query_cve_by_id(cve_id, delay=1):
    headers = {"apiKey": API_KEY} if API_KEY else {}
    params = {"cveId": cve_id}
    data = _perform_request(params, headers, delay)
    return data
