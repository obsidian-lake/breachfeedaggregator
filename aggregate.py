"""
obsidian-lake breach + surveillance aggregator
----------------------------------------------
polls a manifest of upstream rss/atom feeds, filters for two categories of
us-relevant items:
  - BREACH:        data-breach disclosures, ransomware, exfil, leaks
  - SURVEILLANCE:  dragnet practices, 4th-amendment issues, geofence warrants,
                   stingrays, ALPR networks, data-broker location selling,
                   FISA/702/NSA reporting, ALPR, facial-recognition deployments

dedupes across sources and writes:
  - breach-feed.xml   merged rss 2.0 feed, newest first, items tagged [BREACH]
                      or [SURVEILLANCE] in the title
  - stats.json        aggregate impact stats consumed by the HUD on the
                      Breach Feed landing page (records exposed, PII records,
                      dollars at risk/settled, source count, last poll)

no llm in the loop. designed to run on github actions or forgejo cron.

usage:
  pip install -r requirements.txt
  python aggregate.py
"""

from __future__ import annotations

import hashlib
import json
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
STATS_FILE = ROOT / "stats.json"

# --------------------------------------------------------------------
# CATEGORY FILTERS — replace LLM judgement with keyword logic
# --------------------------------------------------------------------

# data-breach signals
BREACH_KEYWORDS = re.compile(
    r"\b(breach|leaked|exposed|exfiltrat|ransomware|stolen data|"
    r"hacked|data theft|cyberattack|disclosure|compromise|"
    r"hack|leak|spill|incident|extortion|"
    r"unauthori[sz]ed access|notification of)\b",
    re.IGNORECASE,
)

# surveillance / 4th-amendment / dragnet signals
SURVEILLANCE_KEYWORDS = re.compile(
    r"\b(dragnet|drag-net|warrantless|fourth amendment|4th amendment|"
    r"mass surveillance|bulk collection|stingray|cell-site simulator|"
    r"geofence warrant|geofence|reverse warrant|reverse-keyword|"
    r"fisa|section 702|fisc\b|"
    r"automated license plate|ALPR|flock safety|"
    r"facial recognition|face recognition|clearview|"
    r"NSA surveillance|FBI surveillance|police surveillance|"
    r"data broker|location data sold|location tracking|geolocation|"
    r"civil liberties|privacy violation|"
    r"foia release|inspector general report|"
    r"third-party doctrine|carpenter v\.|riley v\.)\b",
    re.IGNORECASE,
)

# noise filter — apply to both categories
EXCLUDE_KEYWORDS = re.compile(
    r"\b(podcast episode|webinar|whitepaper|how to prevent|"
    r"top 10|sponsored|gift guide|listicle|"
    r"cybersecurity awareness month)\b",
    re.IGNORECASE,
)

# us-relevance heuristic
US_HINTS = re.compile(
    r"\b(u\.?s\.?|usa|america|federal|congress|senate|"
    r"alabama|alaska|arizona|arkansas|california|colorado|connecticut|"
    r"delaware|florida|georgia|hawaii|idaho|illinois|indiana|iowa|"
    r"kansas|kentucky|louisiana|maine|maryland|massachusetts|michigan|"
    r"minnesota|mississippi|missouri|montana|nebraska|nevada|"
    r"new hampshire|new jersey|new mexico|new york|north carolina|"
    r"north dakota|ohio|oklahoma|oregon|pennsylvania|rhode island|"
    r"south carolina|south dakota|tennessee|texas|utah|vermont|"
    r"virginia|washington|west virginia|wisconsin|wyoming|"
    r"sec|hhs|ftc|cisa|fbi|nsa|dhs|doj|cbp|ice|hipaa|nyse|nasdaq|"
    r"supreme court|district court|ninth circuit|fifth circuit)\b",
    re.IGNORECASE,
)

# --------------------------------------------------------------------
# QUANTITATIVE EXTRACTORS — for the HUD stats
# --------------------------------------------------------------------

# matches "275 million", "64M", "1.4B", "13,000", etc.
RECORDS_RE = re.compile(r"([\d,.]+)\s*(million|m|billion|b|thousand|k)?", re.IGNORECASE)

# matches "$177 million", "$1.8B", "$2,500", "USD 4 million"
DOLLAR_RE = re.compile(
    r"(?:\$|usd\s*)([\d,.]+)\s*(billion|b|million|m|thousand|k)?",
    re.IGNORECASE,
)

# entries whose text contains any of these are counted toward the PII total.
# this is a heuristic: not every record in a "patient data" breach is PII,
# but most are, so this gives a reasonable upper-bound figure.
PII_KEYWORDS = re.compile(
    r"\b(ssn|social security|patient|phi\b|medical record|health record|"
    r"personal information|personally identifiable|"
    r"driver license|passport|date of birth|"
    r"credit card|debit card|banking|account number|"
    r"hipaa|name and address|customer record)\b",
    re.IGNORECASE,
)


def _scale(unit: str) -> int:
    u = (unit or "").lower()
    if u.startswith("b"): return 1_000_000_000
    if u.startswith("m"): return 1_000_000
    if u.startswith(("k", "thous")): return 1_000
    return 1


def estimate_records(text: str) -> int:
    """Largest plausible record count mentioned in the text."""
    best = 0
    for m in RECORDS_RE.finditer(text):
        try:
            n = float(m.group(1).replace(",", "")) * _scale(m.group(2))
        except ValueError:
            continue
        if n > best:
            best = int(n)
    return best


def estimate_dollars(text: str) -> int:
    """Largest plausible USD amount mentioned in the text (settlements, fines)."""
    best = 0
    for m in DOLLAR_RE.finditer(text):
        try:
            n = float(m.group(1).replace(",", "")) * _scale(m.group(2))
        except ValueError:
            continue
        if n > best:
            best = int(n)
    return best


def is_pii(text: str) -> bool:
    return bool(PII_KEYWORDS.search(text))


# --------------------------------------------------------------------
# QUALITATIVE EXTRACTORS — sector, threat actor, attack vector.
# These power the three readout cells on each card of the landing page.
# All best-effort regex; default to a neutral placeholder when unsure.
# --------------------------------------------------------------------

# Sector classification — first match wins, so order = priority.
# The returned token MUST match a sector filter chip on the landing page:
#   healthcare | finance | tech | telecom | education | retail | gov | other
SECTOR_PATTERNS = [
    ("healthcare", re.compile(r"\b(hospital|health|patient|medical|clinic|"
                              r"dermatology|pharma|hipaa|phi\b|medicaid|medicare|"
                              r"care provider|dental|behavioral health)\b", re.I)),
    ("finance",    re.compile(r"\b(bank|insurance|insurer|financial|fintech|"
                              r"credit union|payment|brokerage|lender|mortgage|"
                              r"securities|investment|payroll)\b", re.I)),
    ("telecom",    re.compile(r"\b(telecom|broadband|carrier|isp\b|wireless|"
                              r"fiber|mobile network|5g\b|cellular|landline)\b", re.I)),
    ("education",  re.compile(r"\b(school|university|college|student|education|"
                              r"k-12|campus|academic|learning management|lms\b|"
                              r"school district|edtech)\b", re.I)),
    ("gov",        re.compile(r"\b(government|federal agency|state agency|"
                              r"municipal|county|city of|department of|dmv\b|"
                              r"public sector|\.gov\b|election|veterans affairs)\b", re.I)),
    ("retail",     re.compile(r"\b(retail|e-?commerce|store chain|merchant|"
                              r"consumer goods|apparel|restaurant|qsr\b|"
                              r"marketplace|shopping|grocery)\b", re.I)),
    ("tech",       re.compile(r"\b(software|saas|cloud|platform|mobile app|"
                              r"tech (?:company|firm|giant)|developer|api\b|"
                              r"startup|data center|hosting|chatbot|ai (?:tool|firm))\b", re.I)),
]


def sector_for(text: str) -> str:
    for name, rx in SECTOR_PATTERNS:
        if rx.search(text):
            return name
    return "other"


# Named threat actors / ransomware crews. Extend freely — first hit wins.
KNOWN_ACTORS = [
    "ShinyHunters", "LockBit", "BlackCat", "ALPHV", "Cl0p", "Clop",
    "Scattered Spider", "Lazarus", "Lapsus$", "Lapsus", "BianLian", "Akira",
    "Rhysida", "Medusa", "Black Basta", "Royal", "Hunters International",
    "Qilin", "INC Ransom", "RansomHub", "Crimson Collective", "Lumma Stealer",
    "Mr. Raccoon", "Mr. Racoon", "Snatch", "8Base", "Hellcat", "Brain Cipher",
]
KNOWN_ACTORS_RE = re.compile(
    r"\b(" + "|".join(re.escape(a) for a in KNOWN_ACTORS) + r")\b", re.I
)

# Generic "claimed by X" / "group X" fallback for unlisted actors.
ACTOR_HINT_RE = re.compile(
    r"(?:claimed by|attributed to|ransomware (?:group|gang|crew)|threat actor|"
    r"hacking group|gang|operator[s]?)\s+(?:known as\s+|called\s+|named\s+)?"
    r"[\"']?([A-Z][A-Za-z0-9.$\- ]{2,26}?)[\"']?(?=[\s.,;:]|$)"
)


def actor_for(text: str) -> str:
    m = KNOWN_ACTORS_RE.search(text)
    if m:
        return m.group(1)
    m = ACTOR_HINT_RE.search(text)
    if m:
        return m.group(1).strip()
    if re.search(r"\b(white[- ]?hat|security researcher|researchers?)\b", text, re.I):
        return "Researchers (whitehat)"
    if re.search(r"\b(state-aligned|nation-state|iran-aligned|russia-aligned|"
                 r"china-aligned|north korea|apt\d+)\b", text, re.I):
        return "State-aligned actor"
    return "Unattributed"


# Attack-vector classification — first match wins.
VECTOR_PATTERNS = [
    ("Destructive malware (wiper)", re.compile(r"\b(wiper|destructive malware)\b", re.I)),
    ("Ransomware",                  re.compile(r"\bransomware\b", re.I)),
    ("3rd-party / supply chain",    re.compile(r"\b(third[- ]party|3rd[- ]party|"
                                               r"supply[- ]chain|vendor|bpo\b|"
                                               r"contractor|managed service|"
                                               r"subprocessor)\b", re.I)),
    ("OAuth / token abuse",         re.compile(r"\b(oauth|access token|api token|"
                                               r"session token|refresh token)\b", re.I)),
    ("Credential abuse",            re.compile(r"\b(credential|password|default cred|"
                                               r"stolen login|credential stuffing|"
                                               r"brute[- ]force|leaked key|infostealer|"
                                               r"stealer)\b", re.I)),
    ("Phishing / social eng.",      re.compile(r"\b(phishing|social engineering|"
                                               r"vishing|smishing|pretext|spear[- ]phish)\b", re.I)),
    ("Misconfiguration",            re.compile(r"\b(misconfigur|exposed (?:database|"
                                               r"bucket|server|elasticsearch|s3)|"
                                               r"unsecured|publicly accessible|open database)\b", re.I)),
    ("Exploited vulnerability",     re.compile(r"\b(zero[- ]day|0-day|exploit|"
                                               r"vulnerabilit|cve-|unpatched|"
                                               r"sql injection|remote code execution|rce\b)\b", re.I)),
    ("Insider",                     re.compile(r"\b(insider|rogue employee|"
                                               r"disgruntled (?:employee|worker))\b", re.I)),
]


def vector_for(text: str) -> str:
    for name, rx in VECTOR_PATTERNS:
        if rx.search(text):
            return name
    return "Under investigation"


# --------------------------------------------------------------------

def severity_for(records: int, title: str) -> str:
    if re.search(r"\b(critical|hospital|patients|wiper|destructive)\b", title, re.I):
        return "critical"
    if records >= 5_000_000:
        return "critical"
    if records >= 500_000:
        return "high"
    if records >= 10_000:
        return "medium"
    return "info"


def categorize(title: str, summary: str):
    """Return (is_breach, is_surveillance, is_relevant)."""
    blob = f"{title}\n{summary}"
    if EXCLUDE_KEYWORDS.search(blob):
        return (False, False, False)
    is_breach = bool(BREACH_KEYWORDS.search(blob))
    is_surveil = bool(SURVEILLANCE_KEYWORDS.search(blob))
    if not (is_breach or is_surveil):
        return (False, False, False)
    if not US_HINTS.search(blob):
        return (is_breach, is_surveil, False)
    return (is_breach, is_surveil, True)


def stable_guid(entry, prefix: str = "obsidian-lake:item") -> str:
    candidate = getattr(entry, "id", None) or getattr(entry, "link", None)
    if not candidate:
        seed = f"{entry.get('title', '')}|{entry.get('published', '')}"
        candidate = hashlib.sha1(seed.encode()).hexdigest()
    return f"{prefix}:{hashlib.sha1(candidate.encode()).hexdigest()[:16]}"


def fetch_all(sources):
    items = {}
    for src in sources:
        print(f"  ▸ {src['name']:<28}", end=" ", flush=True)
        try:
            parsed = feedparser.parse(src["url"])
            n_total = len(parsed.entries)
            n_kept = 0
            for entry in parsed.entries:
                title = entry.get("title", "").strip()
                summary = entry.get("summary", entry.get("description", "")).strip()
                is_breach, is_surveil, relevant = categorize(title, summary)
                if not relevant:
                    continue
                guid = stable_guid(entry)
                if guid in items:
                    continue
                link = entry.get("link", "").strip()
                if not link:
                    continue
                blob = title + " " + summary
                records = estimate_records(blob)
                dollars = estimate_dollars(blob)
                # Prefer the more specific category if both keyword sets fire.
                # In practice a "breach" entry can also discuss surveillance
                # implications — we tag whichever has stronger signal in the
                # title alone (titles drive subscriber attention).
                if is_breach and is_surveil:
                    category = "breach" if BREACH_KEYWORDS.search(title) else "surveillance"
                else:
                    category = "breach" if is_breach else "surveillance"

                items[guid] = {
                    "guid": guid,
                    "title": title,
                    "link": link,
                    "summary": summary,
                    "published": entry.get("published_parsed") or entry.get("updated_parsed"),
                    "source": src["name"],
                    "category": category,
                    "records": records,
                    "dollars": dollars,
                    "is_pii": is_pii(blob),
                    "severity": severity_for(records, title),
                    "sector": sector_for(blob),
                    "actor": actor_for(blob),
                    "vector": vector_for(blob),
                }
                n_kept += 1
            print(f"[ok {n_kept}/{n_total}]")
        except Exception as e:
            print(f"[fail: {e}]")
    return items


def build_feed(items):
    fg = FeedGenerator()
    fg.title("Obsidian Lake // US Breach + Surveillance Feed")
    fg.link(href="https://obsidianlake.example/breach-feed", rel="alternate")
    fg.link(href="https://obsidianlake.example/breach-feed.xml", rel="self")
    fg.description(
        "Curated rolling feed of significant US data breaches and dragnet-"
        "surveillance disclosures. Aggregated from public disclosures, "
        "regulatory filings, civil-liberties journalism, and the cypherpunk "
        "press. Calm signal, not vendor FUD."
    )
    fg.language("en-us")
    fg.generator("Obsidian Lake Breach + Surveillance Aggregator v1.2")
    fg.lastBuildDate(datetime.now(timezone.utc))

    sorted_items = sorted(
        items.values(),
        key=lambda x: x["published"] or (0,),
        reverse=True,
    )

    for it in sorted_items[:60]:
        fe = fg.add_entry()
        # Category tag goes first; severity rides along for breaches only.
        if it["category"] == "breach":
            tag = f"BREACH · {it['severity'].upper()}"
        else:
            tag = "SURVEILLANCE"
        fe.title(f"[{tag}] {it['title']}")
        fe.link(href=it["link"])
        fe.guid(it["guid"], permalink=False)
        if it["published"]:
            fe.pubDate(datetime(*it["published"][:6], tzinfo=timezone.utc))
        fe.description(
            f"{it['summary']}\n\n"
            f"// Category: {it['category']} "
            f"// Severity: {it['severity']} "
            f"// Sector: {it['sector']} "
            f"// Actor: {it['actor']} "
            f"// Vector: {it['vector']} "
            f"// Records (est.): {it['records']:,} "
            f"// $ (est.): ${it['dollars']:,} "
            f"// Source: {it['source']} "
            f"// Original: {it['link']}"
        )
        fe.category({"term": it["category"]})
        fe.category({"term": it["severity"]})
        fe.category({"term": it["sector"]})
        fe.category({"term": it["source"]})

    return fg


def compute_stats(items, source_count: int) -> dict:
    """Aggregate impact stats consumed by the HUD on the landing page."""
    records_exposed = sum(it["records"] for it in items.values() if it["category"] == "breach")
    pii_records = sum(it["records"] for it in items.values() if it["is_pii"])
    dollars_lost = sum(it["dollars"] for it in items.values())
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "records_exposed": records_exposed,
        "pii_records": pii_records,
        "dollars_lost": dollars_lost,
        "items_total": len(items),
        "items_breach": sum(1 for it in items.values() if it["category"] == "breach"),
        "items_surveillance": sum(1 for it in items.values() if it["category"] == "surveillance"),
        "sources_count": source_count,
    }


def main():
    sources = yaml.safe_load(SOURCES_FILE.read_text())["sources"]
    print(f"polling {len(sources)} sources...")
    items = fetch_all(sources)
    print(f"\n{len(items)} unique items after filter + dedupe")

    if not items:
        print("no items — refusing to overwrite output with empty feed.", file=sys.stderr)
        sys.exit(1)

    fg = build_feed(items)
    fg.rss_file(str(OUTPUT_FILE), pretty=True)
    print(f"wrote {OUTPUT_FILE}")

    stats = compute_stats(items, len(sources))
    STATS_FILE.write_text(json.dumps(stats, indent=2))
    print(f"wrote {STATS_FILE}")
    print(f"  records_exposed:    {stats['records_exposed']:,}")
    print(f"  pii_records:        {stats['pii_records']:,}")
    print(f"  dollars_lost:       ${stats['dollars_lost']:,}")
    print(f"  items (breach):     {stats['items_breach']}")
    print(f"  items (surveil.):   {stats['items_surveillance']}")


if __name__ == "__main__":
    main()
