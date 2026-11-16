# Bulk SPF, DKIM & DMARC Audit

**Check email authentication for hundreds of domains at once.** Each domain gets a 0-100 score, a grade and prioritized fixes. DNS lookups only: no scraping, no email is sent.

## What it checks
- **SPF**: exactly one record, terminating policy (`-all`, `~all`, `+all`), and the **recursive DNS-lookup count** (limit 10; includes are followed, with a safety budget).
- **DKIM**: ~20 common selectors plus your own; flags revoked keys and keys of about 1024 bits.
- **DMARC**: policy (`none` / `quarantine` / `reject`), `pct`, `rua` reporting address, duplicate records.
- **MX**, **MTA-STS** and **TLS-RPT** records; BIMI presence (informational).

## Input
```json
{ "domains": ["example.com", "bob@example.org"], "dkimSelectors": ["myselector"], "maxDomains": 500 }
```
URLs and email addresses are reduced to their domain. Use the domain from your From address.

## Output (one dataset row per audited domain)
`score`, `grade`, `issues[]` (severity, message, fix), `spf` (record, `all`, `dnsLookups`), `dkim[]` (selector, key type, estimated size), `dmarc`, `mx`, `mtaSts`, `tlsRpt`, `bimi`.

## Billing
You pay per audited domain (see the Pricing tab). **Not billed** and listed in the `REJECTED` record: invalid or reserved names (IP addresses, localhost, `.local`...), non-existent domains (NXDOMAIN), DNS failures, duplicates and domains above `maxDomains`. Use Apify's "maximum cost per run" to cap spending.

## Limits (please read)
- DKIM selectors cannot be listed in DNS. "No DKIM found" means none of the tested selectors exist, not that signing is off. Add your selector in the input.
- Audit **organizational domains** (example.com). Subdomains inherit DMARC from their parent, which this Actor does not evaluate.
- Key size is estimated from the public key length. Results reflect DNS at the time of the run.
- Not legal or security advice.
