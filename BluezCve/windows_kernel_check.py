import urllib.parse

def generate_windows_kernel_links(windows_version):
    """
    windows_version examples:
      10
      10.0
      10.0.19045
      11
    """

    base_queries = [
        f"windows kernel privilege escalation",
        f"windows nt kernel",
        f"win32k privilege escalation",
        f"ntoskrnl privilege escalation",
    ]

    version_queries = []
    if windows_version:
        version_queries.extend([
            f"windows {windows_version} kernel privilege escalation",
            f"windows {windows_version} win32k",
        ])

    queries = base_queries + version_queries

    links = []

    for q in queries:
        encoded = urllib.parse.quote_plus(q)

        links.append({
            "query": q,
            "nvd": (
                "https://nvd.nist.gov/vuln/search/results"
                "?form_type=Basic&results_type=overview"
                "&query=" + encoded
            ),
            "msrc": (
                "https://msrc.microsoft.com/update-guide/search"
                "?query=" + encoded
            )
        })

    return links
