# AI Search Readiness Audit

**Is this page technically ready to be found and cited by AI assistants and search engines?** Get a 0-100 score and prioritized fixes in seconds, for one page or hundreds.

## What it checks
- **robots.txt per crawler**: Googlebot, Bingbot, OAI-SearchBot, Claude-SearchBot, PerplexityBot (scored), plus user-triggered agents and training crawlers such as GPTBot, ClaudeBot, Google-Extended, CCBot (reported, **not scored**: blocking training is a legitimate policy choice).
- **Indexability**: meta robots and `X-Robots-Tag` noindex.
- **Page hygiene**: title, meta description, canonical, `lang`, single `<h1>`, image alt coverage.
- **Structured data**: valid schema.org JSON-LD with at least one `@type`.
- **Content**: amount of server-rendered text.
- **Discovery**: sitemap (same-site Sitemap line in robots.txt, or `/sitemap.xml`). `/llms.txt` is reported as information only; support by major engines is unconfirmed.

## Input
```json
{ "urls": ["https://example.com/", "https://example.com/pricing"], "respectRobots": true, "maxUrls": 100 }
```

## Output (one dataset row per fetched page)
`score`, `grade` (A-F), `issues[]` sorted by severity with a concrete `fix`, `aiCrawlers[]` (allowed/blocked + matching rule), `signals`, `breakdown`, `hasSitemap`, `hasLlmsTxt`. If the page could not be audited after we tried to fetch it, the row carries a `status` (`http-404`, `not-html`, `fetch-failed`).

## Billing
You pay per result row (see the Pricing tab). A row is produced when we actually try to fetch a page, including pages that return an error, because the work was done. **Not billed** and listed in the `REJECTED` record instead: invalid URLs, private or local addresses, pages excluded by robots.txt, duplicates, and URLs above the caps (`maxUrls`, 50 per website per run). Use Apify's "maximum cost per run" to cap spending.

## Safety and politeness
- Public pages only. Private, local, link-local and reserved addresses are refused, including after redirects (max 5, each hop re-checked). Only ports 80 and 443.
- One request per page plus robots.txt, sitemap and llms.txt per site. Requests to one site are spaced. User agent: `TamisAuditBot`. If robots.txt disallows it, the page is skipped (turn off `respectRobots` only for sites you own).

## Limits
- The score measures **technical hygiene**. It does not predict rankings or whether an AI product will cite you.
- Content injected by JavaScript is not rendered, so client-side apps can look thinner than they are.
- Crawler roles are a simplification; check each vendor's current documentation.
- Not legal or SEO guarantees: treat it as a checklist.
