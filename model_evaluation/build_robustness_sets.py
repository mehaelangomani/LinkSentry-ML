"""Freeze validation, test, and synthetic CSVs.

Phishing rows come from the OpenPhish feed and are not requested individually.
The split is fixed before any model runs. Re-running this file overwrites the
robustness CSVs only.
"""

from __future__ import annotations

import csv
import random
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
ORIGINAL = HERE / "evaluation_dataset.csv"
FEED_URL = "https://openphish.com/feed.txt"
SEED = 20261117

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "buff.ly",
    "rebrand.ly",
    "tiny.cc",
    "tr.ee",
    "rb.gy",
}
BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "netflix": "netflix.com",
    "amazon": "amazon.com",
    "roblox": "roblox.com",
    "binance": "binance.com",
    "whatsapp": "whatsapp.com",
    "github": "github.com",
    "adobe": "adobe.com",
    "linkedin": "linkedin.com",
    "steam": "steampowered.com",
}

# First of each pair is validation, second is test. Assigned before scoring.
LEGITIMATE_PAIRS = [
    ("login", "https://www.linkedin.com/login", "https://login.yahoo.com/"),
    ("login", "https://accounts.spotify.com/login", "https://signin.aws.amazon.com/"),
    ("login", "https://accounts.nintendo.com/", "https://login.salesforce.com/"),
    ("login", "https://auth.services.adobe.com/", "https://login.live.com/"),
    ("login", "https://www.dropbox.com/login", "https://discord.com/login"),
    ("login", "https://www.twitch.tv/login", "https://store.steampowered.com/login/"),
    ("login", "https://www.netflix.com/login", "https://www.paypal.com/signin"),
    ("login", "https://www.ebay.com/signin/", "https://www.facebook.com/login/"),
    ("subdomain", "https://docs.github.com/", "https://open.spotify.com/"),
    ("subdomain", "https://mail.google.com/", "https://translate.google.com/"),
    ("subdomain", "https://news.google.com/", "https://scholar.google.com/"),
    ("subdomain", "https://play.google.com/", "https://m.wikipedia.org/"),
    ("subdomain", "https://commons.wikimedia.org/", "https://en.wiktionary.org/"),
    ("subdomain", "https://api.weather.gov/", "https://status.aws.amazon.com/"),
    ("subdomain", "https://developer.spotify.com/", "https://music.apple.com/"),
    ("subdomain", "https://portal.azure.com/", "https://outlook.office.com/"),
    ("path", "https://www.reuters.com/world/", "https://www.theguardian.com/international"),
    ("path", "https://www.bbc.co.uk/news", "https://www.nist.gov/cybersecurity"),
    ("path", "https://csrc.nist.gov/Projects", "https://pandas.pydata.org/docs/"),
    ("path", "https://numpy.org/doc/stable/", "https://www.postgresql.org/docs/current/"),
    ("path", "https://kubernetes.io/docs/home/", "https://docs.docker.com/get-started/"),
    ("path", "https://www.debian.org/distrib/", "https://httpd.apache.org/docs/current/"),
    ("path", "https://nginx.org/en/docs/", "https://www.kernel.org/doc/html/latest/"),
    ("path", "https://react.dev/reference/react", "https://go.dev/doc/"),
    ("query", "https://www.bing.com/search?q=weather", "https://duckduckgo.com/?q=weather"),
    ("query", "https://search.brave.com/search?q=weather", "https://pubmed.ncbi.nlm.nih.gov/?term=phishing"),
    ("query", "https://archive.org/search?query=internet", "https://www.wikidata.org/w/index.php?search=URL"),
    ("query", "https://www.ebay.com/sch/i.html?_nkw=keyboard", "https://www.imdb.com/find/?q=matrix"),
    ("query", "https://openlibrary.org/search?q=internet", "https://www.gutenberg.org/ebooks/search/?query=science"),
    ("ip", "https://1.1.1.1/", "https://8.8.8.8/"),
    ("ip", "https://one.one.one.one/", "https://9.9.9.9/"),
    ("shortener", "https://bitly.com/", "https://tinyurl.com/"),
    ("long", "https://kubernetes.io/docs/concepts/overview/working-with-objects/names/", "https://docs.docker.com/engine/reference/commandline/run/"),
    ("long", "https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.html", "https://numpy.org/doc/stable/reference/generated/numpy.ndarray.html"),
    ("homepage", "https://www.cdc.gov/", "https://www.nih.gov/"),
    ("homepage", "https://www.sec.gov/", "https://www.ftc.gov/"),
    ("homepage", "https://europa.eu/", "https://commission.europa.eu/"),
    ("homepage", "https://www.icann.org/", "https://datatracker.ietf.org/"),
    ("homepage", "https://huggingface.co/docs", "https://pytorch.org/docs/stable/index.html"),
    ("homepage", "https://crates.io/", "https://docs.rs/"),
]

SYNTHETIC = [
    ("http://docs.github.com/", "legitimate", "synthetic_scheme_variant", "HTTP variant of a published docs host. Not fetched."),
    ("https://www.docs.github.com/", "legitimate", "synthetic_www_variant", "www prefix added to a real host. Not fetched."),
    ("https://paypal.example.com/login", "synthetic_lookalike", "synthetic_reserved_domain", "example.com is reserved. Not a verified phishing incident."),
    ("https://accounts.google.example.com/", "synthetic_lookalike", "synthetic_reserved_domain", "example.com is reserved. Not a verified phishing incident."),
    ("https://github.com.example.net/login", "synthetic_lookalike", "synthetic_reserved_domain", "example.net is reserved. Not a verified phishing incident."),
    ("http://192.0.2.1/login", "synthetic_ip_probe", "synthetic_documentation_range", "192.0.2.0/24 is TEST-NET. Not a verified phishing incident."),
    ("https://203.0.113.10/secure/update?redirect=account", "synthetic_ip_probe", "synthetic_documentation_range", "203.0.113.0/24 is TEST-NET. Not a verified phishing incident."),
    ("https://bitly.com/3example", "synthetic_short_link", "synthetic_unresolved_short_link", "Shortener path was constructed. Destination was not resolved and is not a verified label."),
]


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def is_ip(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def tags_for(url: str) -> list[str]:
    parts = urlsplit(url)
    host = host_of(url)
    found = []
    if parts.scheme == "https":
        found.append("https")
    if parts.scheme == "http":
        found.append("http")
    if is_ip(host):
        found.append("ip")
    if host in SHORTENERS or host.startswith("www.") and host[4:] in SHORTENERS:
        found.append("shortener")
    if len(url) >= 140:
        found.append("long")
    if parts.query:
        found.append("query")
    if parts.path not in ("", "/"):
        found.append("path")
    if not is_ip(host) and host.count(".") >= 2 and not host.startswith("www."):
        found.append("subdomain")
    for brand, domain in BRAND_DOMAINS.items():
        if brand in host and host != domain and not host.endswith("." + domain):
            found.append("lookalike")
            break
    return found


def primary_category(url: str) -> str:
    found = set(tags_for(url))
    for name in ("ip", "shortener", "long", "lookalike", "query", "path", "subdomain", "https", "http"):
        if name in found:
            return name
    return "other"


def load_original_urls() -> set[str]:
    with ORIGINAL.open(encoding="utf-8", newline="") as handle:
        return {row["url"] for row in csv.DictReader(handle)}


def download_feed() -> list[str]:
    request = urllib.request.Request(FEED_URL, headers={"User-Agent": "LinkSentry-eval/1.0 academic"})
    with urllib.request.urlopen(request, timeout=45) as response:
        text = response.read().decode("utf-8", errors="replace")
    urls = []
    seen = set()
    for line in text.splitlines():
        url = line.strip()
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def select_phishing(feed: list[str], blocked: set[str]) -> list[str]:
    pool = [url for url in feed if url not in blocked and host_of(url)]
    random.Random(SEED).shuffle(pool)
    quotas = {"ip": 99, "shortener": 6, "long": 8, "lookalike": 10, "query": 8, "https": 24, "http": 12, "subdomain": 16, "path": 16}
    picked: list[str] = []
    seen_hosts: set[str] = set()

    def take(url: str, category: str) -> None:
        host = host_of(url)
        if host in seen_hosts:
            return
        picked.append(url)
        seen_hosts.add(host)
        if category in quotas and quotas[category] > 0:
            quotas[category] -= 1

    for filling in (True, False):
        for url in pool:
            if len(picked) >= 80:
                break
            host = host_of(url)
            if host in seen_hosts:
                continue
            category = primary_category(url)
            if filling and quotas.get(category, 0) <= 0:
                continue
            take(url, category)
    if len(picked) < 80:
        raise SystemExit(f"Only found {len(picked)} new phishing URLs. Quotas left: {quotas}")
    return picked[:80]


def split_half(urls: list[str]) -> tuple[list[str], list[str]]:
    ordered = sorted(urls, key=lambda url: (primary_category(url), url))
    validation, test = [], []
    buckets: dict[str, list[str]] = {}
    for url in ordered:
        buckets.setdefault(primary_category(url), []).append(url)
    for category in sorted(buckets):
        for index, url in enumerate(buckets[category]):
            (validation if index % 2 == 0 else test).append(url)
    return validation, test


def write_rows(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["url", "expected_label", "source", "verification_status", "split", "category", "notes"],
        )
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    blocked = load_original_urls()
    feed = download_feed()
    phishing = select_phishing(feed, blocked)
    validation_phishing, test_phishing = split_half(phishing)
    validation_rows = []
    test_rows = []
    for category, left, right in LEGITIMATE_PAIRS:
        for split, url, rows in (
            ("validation", left, validation_rows),
            ("test", right, test_rows),
        ):
            if url in blocked:
                raise SystemExit(f"Legitimate URL overlaps the original set: {url}")
            rows.append(
                {
                    "url": url,
                    "expected_label": "legitimate",
                    "source": "published public web address",
                    "verification_status": "not_fetched_published_address",
                    "split": split,
                    "category": category,
                    "notes": "Page was not requested.",
                }
            )
    for split, urls, rows in (
        ("validation", validation_phishing, validation_rows),
        ("test", test_phishing, test_rows),
    ):
        for url in urls:
            rows.append(
                {
                    "url": url,
                    "expected_label": "phishing",
                    "source": "OpenPhish public feed retrieved 2026-11-17",
                    "verification_status": "vendor_feed_unvisited",
                    "split": split,
                    "category": primary_category(url),
                    "notes": "Not visited. Tags: " + ", ".join(tags_for(url)) + ".",
                }
            )
    synthetic_rows = []
    for url, label, status, note in SYNTHETIC:
        synthetic_rows.append(
            {
                "url": url,
                "expected_label": label,
                "source": "synthetic",
                "verification_status": status,
                "split": "synthetic",
                "category": primary_category(url) if label == "legitimate" else "synthetic",
                "notes": note,
            }
        )
    write_rows(HERE / "robustness_validation.csv", validation_rows)
    write_rows(HERE / "robustness_test.csv", test_rows)
    write_rows(HERE / "robustness_synthetic.csv", synthetic_rows)
    print(f"feed {len(feed)} validation {len(validation_rows)} test {len(test_rows)} synthetic {len(synthetic_rows)}")
    for name, rows in ("validation", validation_rows), ("test", test_rows):
        counts = {}
        for row in rows:
            key = (row["expected_label"], row["category"])
            counts[key] = counts.get(key, 0) + 1
        print(name)
        for key in sorted(counts):
            print(f"  {key[0]} {key[1]} {counts[key]}")


if __name__ == "__main__":
    main()
