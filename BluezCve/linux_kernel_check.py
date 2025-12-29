import urllib.parse


def generate_kernel_check_links(kernel_version: str):

    parts = kernel_version.split(".")
    major = parts[0]
    minor = parts[1] if len(parts) > 1 else None

    queries = [
        f"linux kernel {major}",
    ]

    if minor:
        queries.append(f"linux kernel {major}.{minor}")

    queries.append("linux kernel privilege escalation")

    links = []
    for q in queries:
        encoded = urllib.parse.quote_plus(q)
        url = (
            "https://www.exploit-db.com/search"
            "?platform=linux&type=local&text=" + encoded
        )
        links.append({
            "query": q,
            "url": url
        })

    return links
