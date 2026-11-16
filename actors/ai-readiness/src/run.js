import { auditUrl, normalizeUrl, isBillable } from './audit.js';
import { createSafeClient } from './safe-http.js';

export const LIMITS = { maxUrlsCap: 1000, defaultMaxUrls: 100, perSiteCap: 50, concurrency: 4, perSiteDelayMs: 300, rejectedCap: 1000 };

export function parseInput(raw) {
  const input = raw && typeof raw === 'object' ? raw : {};
  const { urls, respectRobots = true, maxUrls = LIMITS.defaultMaxUrls } = input;
  if (!Array.isArray(urls) || urls.length === 0) throw new Error('Input "urls" must be a non-empty array.');
  const max = Number.isInteger(maxUrls) ? maxUrls : LIMITS.defaultMaxUrls;
  if (max < 1 || max > LIMITS.maxUrlsCap) throw new Error(`Input "maxUrls" must be between 1 and ${LIMITS.maxUrlsCap}.`);
  if (urls.length > LIMITS.maxUrlsCap * 5) throw new Error('Too many URLs in one run.');
  return { urls, respectRobots: respectRobots !== false, maxUrls: max };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * BILLING MODEL: only Apify's synthetic `apify-default-dataset-item` is billable. Each record pushed to the default dataset
 * is charged once by the platform, atomically with the write. This code never calls Actor.charge().
 * Billable: audited pages and attempted fetches that failed (404, timeout, non-HTML), as Apify recommends for work already spent.
 * Not billable (kept out of the default dataset, listed in the REJECTED key-value record): invalid URLs, refused (non-public)
 * addresses, robots.txt exclusions, duplicates and URLs beyond the per-run or per-site caps.
 */
export async function run(Actor, { client = createSafeClient(), log = console, delayMs = LIMITS.perSiteDelayMs, concurrency = LIMITS.concurrency } = {}) {
  const { urls, respectRobots, maxUrls } = parseInput(await Actor.getInput());
  const rejected = [], seen = new Set(), groups = new Map();
  const reject = (url, status, error) => { if (rejected.length < LIMITS.rejectedCap) rejected.push({ url: String(url).slice(0, 200), status, error }); counts.rejected++; };
  const counts = { requested: urls.length, audited: 0, failedFetch: 0, rejected: 0, billed: 0 };
  let accepted = 0;
  for (const item of urls) {
    const raw = typeof item === 'string' ? item : item && typeof item === 'object' ? item.url : null;
    if (typeof raw !== 'string') { reject(String(raw), 'invalid-url', 'Each entry must be a string URL'); continue; }
    let u;
    try { u = normalizeUrl(raw); } catch (e) { reject(raw, 'invalid-url', e.message); continue; }
    if (seen.has(u.href)) { reject(u.href, 'duplicate', 'Duplicate URL ignored'); continue; }
    seen.add(u.href);
    if (accepted >= maxUrls) { reject(u.href, 'skipped-over-max-urls', `Above maxUrls (${maxUrls})`); continue; }
    const g = groups.get(u.origin) ?? [];
    if (g.length >= LIMITS.perSiteCap) { reject(u.href, 'skipped-site-limit', `More than ${LIMITS.perSiteCap} URLs for this site in one run`); continue; }
    g.push({ raw: u.href, index: accepted++ }); groups.set(u.origin, g);
  }

  const originCache = new Map(), queue = [...groups.values()];
  let sumScore = 0;
  const worker = async () => {
    for (let g = queue.shift(); g; g = queue.shift()) {
      for (let i = 0; i < g.length; i++) {
        if (i > 0) await sleep(delayMs); // politeness: one request burst at a time per site
        const r = await auditUrl(g[i].raw, { respectRobots, originCache, client });
        if (isBillable(r)) {
          await Actor.pushData({ index: g[i].index, ...r }); // platform charges this write; a throw aborts the run (fail closed)
          counts.billed++;
          if (r.ok) { counts.audited++; sumScore += r.score; } else counts.failedFetch++;
        } else reject(r.url, r.status, r.error);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, worker));

  const summary = { ...counts, averageScore: counts.audited ? Math.round(sumScore / counts.audited) : null };
  await Actor.setValue('SUMMARY', summary);
  await Actor.setValue('REJECTED', rejected);
  log.log(`Done: ${JSON.stringify(summary)}`);
  return summary;
}
