import { auditDomain, normalizeDomain, sanitizeSelectors, DEFAULT_SELECTORS } from './audit.js';

export const LIMITS = { maxDomainsCap: 5000, defaultMaxDomains: 500, concurrency: 5, rejectedCap: 1000 };

export function parseInput(raw) {
  const input = raw && typeof raw === 'object' ? raw : {};
  const { domains, dkimSelectors = [], maxDomains = LIMITS.defaultMaxDomains } = input;
  if (!Array.isArray(domains) || domains.length === 0) throw new Error('Input "domains" must be a non-empty array.');
  const max = Number.isInteger(maxDomains) ? maxDomains : LIMITS.defaultMaxDomains;
  if (max < 1 || max > LIMITS.maxDomainsCap) throw new Error(`Input "maxDomains" must be between 1 and ${LIMITS.maxDomainsCap}.`);
  if (domains.length > LIMITS.maxDomainsCap * 5) throw new Error('Too many domains in one run.');
  return { domains, max, selectors: [...new Set([...sanitizeSelectors(dkimSelectors), ...DEFAULT_SELECTORS])] };
}

/**
 * BILLING MODEL: only Apify's synthetic `apify-default-dataset-item` is billable; each audited domain is one record in the
 * default dataset, charged once by the platform atomically with the write. This code never calls Actor.charge().
 * Free (kept out of the default dataset, listed in the REJECTED key-value record): invalid domains, non-existent domains
 * (NXDOMAIN), DNS failures, duplicates and domains above the cap. A failing dataset write propagates and aborts the run.
 */
export async function run(Actor, { resolver, log = console, concurrency = LIMITS.concurrency } = {}) {
  const { domains, max, selectors } = parseInput(await Actor.getInput());
  const rejected = [], seen = new Set(), todo = [];
  const counts = { requested: domains.length, audited: 0, rejected: 0 };
  const reject = (d, status, error) => { if (rejected.length < LIMITS.rejectedCap) rejected.push({ domain: String(d).slice(0, 100), status, error }); counts.rejected++; };
  for (const d of domains) {
    let n;
    try { n = normalizeDomain(d); } catch (e) { reject(d, 'invalid-domain', e.message); continue; }
    if (seen.has(n)) { reject(n, 'duplicate', 'Duplicate domain ignored'); continue; }
    seen.add(n);
    if (todo.length >= max) { reject(n, 'skipped-over-max-domains', `Above maxDomains (${max})`); continue; }
    todo.push({ domain: n, index: todo.length });
  }
  let sum = 0;
  const queue = [...todo];
  const worker = async () => {
    for (let t = queue.shift(); t; t = queue.shift()) {
      const r = await auditDomain(t.domain, { resolver, selectors });
      if (r.ok) {
        await Actor.pushData({ index: t.index, ...r }); // the platform charges this write; a throw aborts the run (fail closed)
        counts.audited++; sum += r.score;
      } else reject(r.domain, r.status, r.error);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, worker));
  const summary = { ...counts, averageScore: counts.audited ? Math.round(sum / counts.audited) : null };
  await Actor.setValue('SUMMARY', summary);
  await Actor.setValue('REJECTED', rejected);
  log.log(`Done: ${JSON.stringify(summary)}`);
  return summary;
}
