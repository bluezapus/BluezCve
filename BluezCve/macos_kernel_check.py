import urllib.parse

def generate_macos_kernel_links(darwin_version):
    """
    darwin_version examples:
      21.6.0 (macOS Monterey)
      22.6.0 (Ventura)
      23.x.x (Sonoma)
    """

    base_queries = [
        "macos xnu kernel privilege escalation",
        "macos iokit privilege escalation",
        "apple xnu kernel vulnerability",
        "macos kernel local privilege escalation",
    ]

    version_queries = []
    if darwin_version:
        version_queries.extend([
            f"darwin {darwin_version} kernel exploit",
            f"macos darwin {darwin_version} privilege escalation",
            f"xnu {darwin_version} exploit",
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
            "github": (
                "https://github.com/search"
                "?q=" + encoded + "&type=repositories"
            )
        })

    return links
