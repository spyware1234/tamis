# IBAN, BIC, SIREN, SIRET & EU VAT Validator

**Catch typos in supplier bank and company identifiers before you pay or onboard.** Offline checksums, a clear **ALLOW / REVIEW / BLOCK** verdict per row, and **IBANs masked by default**. Nothing is sent to a third party.

## What it checks
| Type | Test | Verdict when OK |
|---|---|---|
| IBAN | country length + mod-97 checksum | ALLOW |
| SIREN / SIRET (France) | Luhn checksum (La Poste exception handled) | ALLOW |
| French VAT (FRxx + SIREN) | VAT key computed from the SIREN + SIREN checksum | ALLOW |
| Other EU VAT numbers | country format only (no public offline checksum) | REVIEW |
| BIC / SWIFT | format only (a BIC has no checksum) | REVIEW |

**ALLOW** = passed a real checksum. **REVIEW** = plausible format, existence cannot be proven offline. **BLOCK** = failed.

## Input
```json
{ "items": ["FR1420041010050500013M02606", "FR44732829320", "DE89 3704 0044 0532 0130 01"], "type": "auto", "maskSensitive": true }
```
Spaces and dashes are ignored. Entries can be strings or `{"value": "BNPAFRPP", "type": "bic"}`.

## Output (one dataset row per entry)
```json
{ "index": 2, "input": "DE89**************3001", "type": "iban", "normalized": "DE89**************3001",
  "verdict": "BLOCK", "valid": false, "reasons": ["Checksum (mod 97) failed"], "details": { "country": "DE" }, "masked": true }
```
- **Privacy:** IBANs (and anything unrecognised, which may be a mistyped IBAN) are masked: country, check digits, last 4 characters. Match rows to your input with `index`. SIREN, SIRET, VAT numbers and BICs are public business identifiers and are echoed as typed. Set `maskSensitive` to `false` only if you need full values in the output.
- A `SUMMARY` record (key-value store) gives the batch verdict and counts. It contains no identifiers.

## Billing
You pay per result row (see the Pricing tab), nothing else. Each submitted entry produces one row, including duplicates and entries that fail validation. Entries above `maxItems` are skipped and not billed. Use Apify's "maximum cost per run" to cap spending.

## Use it from your tools
Call it through the Apify API, or from n8n, Make or Zapier, or give it to an AI agent through Apify's MCP integration, to validate a column of identifiers before a payment run.

## Limits (please read)
- It detects **typos and malformed numbers**. It does **not** prove that an account exists, who owns it or that a company is active, and it is **not** fraud detection.
- For non-French VAT numbers, confirm existence with the official EU VIES service.
- The IBAN length table covers the common countries; others return REVIEW if the checksum passes.
- Input is stored in your own Apify run storage like any Actor input; delete runs you no longer need.
- Not legal, tax or financial advice.
