"""
obsidian-lake breach aggregator
-------------------------------
polls a manifest of upstream rss/atom feeds, filters for us-relevant data
breaches, dedupes, and writes a merged rss 2.0 file (`breach-feed.xml`).

no llm in the loop. designed to run on github actions cron (free tier).

usage:
  pip install -r requirements.txt
  python aggregate.py
"""

from __future__ import annotations

import hashlib
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import feedparser
import yaml
from feedgen.feed import FeedGenerator

ROOT = Path(__file__).parent
SOURCES_FILE = ROOT / "sources.yml"
OUTPUT_FILE = ROOT / "breach-feed.xml"

# --------------------------------------------------------------------
# RULES — replace LLM judgement with keyword logic
# --------------------------------------------------------------------

# titles must contain at least one of these to qualify as a "breach"
BREACH_KEYWORDS = re.compile(
    r"\b(breach|leaked|exposed|exfiltrat|ransomware|stolen data|"
    r"hacked|data theft|cyberattack|disclosure|compromise|"
    r"hack|leak|spill|incident|extortion)\b",
    re.IGNORECASE,
)

# exclude obvious noise
EXCLUDE_KEYWORDS = re.compile(
    r"\b(podcast episode|webinar|whitepaper|how to prevent|"
    r"top 10|sponsored|webinar)\b",
    re.IGNORECASE,
)

# us-relevance heuristic: us state name, us company, .gov, sec/hhs/ftc filings.
# this is intentionally permissive — better to surface and let humans skip.
US_HINTS = re.compile(
    r"\b(u\.?s\.?|usa|america|"
    r"alabama|alaska|arizona|arkansas|california|colorado|connecticut|"
    r"delaware|florida|georgia|hawaii|idaho|illinois|indiana|iowa|"
    r"kansas|kentucky|louisiana|maine|maryland|massachusetts|michigan|"
    r"minnesota|mississippi|missouri|montana|nebraska|nevada|"
    r"new hampshire|new jersey|new mexico|new york|north carolina|"
    r"north dakota|ohio|oklahoma|oregon|pennsylvania|rhode island|"
    r"south carolina|south dakota|tennessee|texas|utah|vermont|"
    r"virginia|washington|west virginia|wisconsin|wyoming|"
    r"sec|hhs|ftc|cisa|fbi|hipaa|nyse|nasdaq)\b",
    re.IGNORECASE,
)

# severity buckets via record-count heuristic on title
RECORDS_RE = re.compile(r"([\d,.]+)\s*(million|m|billion|b|thousand|k)?", re.IGNORECASE)

# --------------------------------------------------------------------

def estimate_records(text: str) -> int:
    """Pull a record-count estimate out of free text. Best-effort."""
    best = 0
    for m in RECORDS_RE.finditer(text):
        try:
            n = float(m.group(1).replace(",", ""))
        except ValueError:
            continue
        unit = (m.group(2) or "").lower()
        if unit.startswith("b"):
            n *= 1_000_000_000
        elif unit.startswith("m"):
            n *= 1_000_000
        elif unit.startswith(("k", "thous")):
            n *= 1_000
        if n > best:
            best = int(n)
    return best


def severity_for(records: int, title: str) -> str:
    """Bucket by record count and signal keywords."""
    if re.search(r"\b(critical|hospital|patients|wiper|destructive)\b", title, re.I):
        return "critical"
    if records >= 5_000_000:
        return "critical"
    if records >= 500_000:
        return "high"
    if records >= 10_000:
        return "medium"
    return "info"


def is_relevant(title: str, summary: str) -> bool:
    blob = f"{title}\n{summary}"
    if not BREACH_KEYWORDS.search(blob):
        return False
    if EXCLUDE_KEYWORDS.search(blob):
        return False
    # US hint is required — bias toward false negatives over false positives
    return bool(US_HINTS.search(blob))


def stable_guid(entry) -> str:
    """Dedup key. Prefer source guid; fall back to URL or hash of title+date."""
    candidate = getattr(entry, "id", None) or getattr(entry, "link", None)
    if not candidate:
        seed = f"{entry.get('title', '')}|{entry.get('published', '')}"
        candidate = hashlib.sha1(seed.encode()).hexdigest()
    return f"obsidian-lake:breach:{hashlib.sha1(candidate.encode()).hexdigest()[:16]}"


def fetch_all(sources):
    items = {}  # guid -> normalised entry
    for src in sources:
        print(f"  ▸ {src['name']:<28}", end=" ", flush=True)
        try:
            parsed = feedparser.parse(src["url"])
            n_total = len(parsed.entries)
            n_kept = 0
            for entry in parsed.entries:
                title = entry.get("title", "").strip()
                summary = entry.get("summary", entry.get("description", "")).strip()
                if not is_relevant(title, summary):
                    continue
                guid = stable_guid(entry)
                if guid in items:
                    continue  # dedupe
                link = entry.get("link", "").strip()
                if not link:
                    # require a source link — no point publishing an entry
                    # the subscriber can't click through to verify
                    continue
                records = estimate_records(title + " " + summary)
                items[guid] = {
                    "guid": guid,
                    "title": title,
                    "link": link,
                    "summary": summary,  # full pass-through, no truncation
                    "published": entry.get("published_parsed") or entry.get("updated_parsed"),
                    "source": src["name"],
                    "records": records,
                    "severity": severity_for(records, title),
                }
                n_kept += 1
            print(f"[ok {n_kept}/{n_total}]")
        except Exception as e:
            print(f"[fail: {e}]")
    return items


def build_feed(items):
    fg = FeedGenerator()
    fg.title("Obsidian Lake // US Data Breach Feed")
    fg.link(href="https://obsidianlake.example/breach-feed", rel="alternate")
    fg.link(href="https://obsidianlake.example/breach-feed.xml", rel="self")
    fg.description(
        "Curated rolling feed of significant US data breaches. "
        "Aggregated from public disclosures, regulatory filings, and the cypherpunk press."
    )
    fg.language("en-us")
    fg.generator("Obsidian Lake Breach Aggregator v1.0")
    fg.lastBuildDate(datetime.now(timezone.utc))

    # newest first
    sorted_items = sorted(
        items.values(),
        key=lambda x: x["published"] or (0,),
        reverse=True,
    )

    for it in sorted_items[:50]:  # cap at 50 newest
        fe = fg.add_entry()
        tag = it["severity"].upper()
        fe.title(f"[{tag}] {it['title']}")
        # <link> is the canonical source URL — every entry has one (enforced upstream)
        fe.link(href=it["link"])
        fe.guid(it["guid"], permalink=False)
        if it["published"]:
            fe.pubDate(datetime(*it["published"][:6], tzinfo=timezone.utc))
        fe.description(
            f"{it['summary']}\n\n"
            f"// Severity: {it['severity']} "
            f"// Records (est.): {it['records']:,} "
            f"// Source: {it['source']} "
            f"// Original: {it['link']}"
        )
        fe.category({"term": it["severity"]})
        fe.category({"term": it["source"]})

    return fg


def main():
    sources = yaml.safe_load(SOURCES_FILE.read_text())["sources"]
    print(f"polling {len(sources)} sources...")
    items = fetch_all(sources)
    print(f"\n{len(items)} unique breach items after filter + dedupe")

    if not items:
        print("no items — refusing to overwrite output with empty feed.", file=sys.stderr)
        sys.exit(1)

    fg = build_feed(items)
    fg.rss_file(str(OUTPUT_FILE), pretty=True)
    print(f"wrote {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
