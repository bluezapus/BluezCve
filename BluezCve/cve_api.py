import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("0da7574d-b35a-400c-aa5a-e1e1f29490c9")

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def query_cve(package, version, delay=1):
    params = {"keywordSearch": f"{package} {version}", "resultsPerPage": 3}
    headers = {"apiKey": API_KEY} if API_KEY else {}

    try:
        response = requests.get(NVD_BASE, params=params, headers=headers)
        response.raise_for_status()
        time.sleep(delay)  # Hindari rate limit
        return response.json()
    except Exception as e:
        print(f"[!] Error querying {package}: {e}")
        return None
