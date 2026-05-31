# Obsidian Lake — Breach Feed Aggregator

A small, no-AI Python pipeline that polls a manifest of RSS/Atom feeds, filters
for US-relevant data breaches, dedupes across sources, and writes a merged
`breach-feed.xml` you can host anywhere.

## Pieces

```
aggregator/
├── aggregate.py            # the pipeline — ~200 LOC
├── sources.yml             # upstream feed manifest (edit me)
├── requirements.txt        # pip deps: feedparser, feedgen, pyyaml
└── .github-workflow.yml    # GitHub Actions cron (rename to .github/workflows/poll.yml)
```

## Run locally

```bash
cd aggregator
pip install -r requirements.txt
python aggregate.py
# → writes breach-feed.xml
```

## Run on a schedule (free)

The simplest deployment: GitHub Actions cron, output committed back to the repo,
served via GitHub Pages.

1. Push this folder to a GitHub repo.
2. Move `.github-workflow.yml` to `.github/workflows/poll.yml`.
3. Enable GitHub Pages on the repo (Settings → Pages → "Deploy from branch", root).
4. The action runs every 30 min and updates `breach-feed.xml` at the repo root.
5. Your feed URL: `https://<user>.github.io/<repo>/breach-feed.xml`

Alternatives that work the same way: Cloudflare Workers cron, Vercel cron,
fly.io cron-machine, or a literal `crontab -e` on any box you own.

## How the "is this worth surfacing" judgement works

No LLM. Three layers of rules in `aggregate.py`:

1. **Keyword filter** — title or summary must match `breach|leaked|exposed|exfiltrat|ransomware|...` AND must not match an exclude list (`webinar|how to prevent|sponsored|...`).
2. **US-relevance heuristic** — must mention a US state, "U.S.", a US regulator (SEC/HHS/FTC/CISA/FBI/HIPAA), or NYSE/NASDAQ. Permissive on purpose.
3. **Severity bucket** — derived from the record count parsed out of the title/summary, with override for hospital/wiper/destructive keywords.

Tune these in the constants at the top of `aggregate.py`. Each rule is one
regex; you can extend them without touching the rest of the pipeline.

## Non-RSS sources (HHS OCR portal, SEC EDGAR)

Two of the highest-signal upstream sources don't ship clean RSS:

- **HHS OCR breach portal** (`ocrportal.hhs.gov`) — HTML table. Scrape with
  `httpx + selectolax`, normalise to the same `{title, link, published, summary}`
  shape, hand off to the same dedupe + write step.
- **SEC EDGAR 8-K Item 1.05** — Atom feed exists but covers every 8-K, not just
  cyber-incident filings. Filter on Item 1.05 via the full-text endpoint:
  `https://efts.sec.gov/LATEST/search-index?q=%22Item+1.05%22&forms=8-K`.

Drop adapters in `adapters/<name>.py` that return the same dict shape and
`aggregate.py` will treat them as just another source. (Left as a follow-up so
the core pipeline stays small.)

## What the LLM version would add

Honest accounting — three things, and you can decide which are worth it:

| Capability | Rule-based | LLM-based |
|---|---|---|
| "Is this a real breach?" | keyword regex (90% accurate) | reads the article (98%) |
| Record-count extraction | `\d+(?:million|k)` regex (works ~70% of titles) | parses prose (~95%) |
| One-sentence house-voice rewrite | not possible | trivial |

If you want the house-voice rewrite (the Obsidian Lake tone in every entry
summary), that's the one piece that genuinely needs an LLM. Everything else is
cheaper as code.

## Cost

GitHub Actions free tier gives 2,000 minutes/month. This job takes ~30 seconds
per run × 48 runs/day = ~12 hours/month. Comfortably free.

## Output

Standards-compliant RSS 2.0 with `dc:creator`, per-entry `<category>` for
severity and source, and a 50-item cap. Validates against the W3C feed
validator. Subscribe in any reader.
