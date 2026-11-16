// Daily smoke test of the PUBLISHED Actors through the Apify API.
// Exit code: 0 all good, 1 at least one check failed, 2 configuration error.
// Env: APIFY_TOKEN (secret, never printed), APIFY_USERNAME, optional APIFY_API_BASE (tests only).
// It starts each Actor with a tiny input, waits for it to finish, reads the dataset, and ALSO inspects the run's billing
// counters to catch double billing (a custom event charged next to the default dataset item event).
const base = (process.env.APIFY_API_BASE || 'https://api.apify.com').replace(/\/$/, '');
const token = process.env.APIFY_TOKEN;
const user = process.env.APIFY_USERNAME;
if (!token || !user || !/^[A-Za-z0-9._-]+$/.test(user)) { console.error('APIFY_TOKEN and a valid APIFY_USERNAME are required'); process.exit(2); }

export const CHECKS = [
  { actor: 'eu-payment-id-validator', input: { items: ['FR1420041010050500013M02606', 'DE89370400440532013001'] },
    verify: (items) => items.length === 2 && items[0].verdict === 'ALLOW' && items[1].verdict === 'BLOCK' && !JSON.stringify(items).includes('FR1420041010050500013M02606') },
  { actor: 'ai-search-readiness-audit', input: { urls: ['https://example.com/'], maxUrls: 1 },
    verify: (items) => items.length === 1 && items[0].status === 'audited' && typeof items[0].score === 'number' },
  { actor: 'email-auth-audit', input: { domains: ['example.com'], maxDomains: 1 },
    verify: (items) => items.length === 1 && items[0].status === 'audited' && typeof items[0].score === 'number' },
];

const api = (path, init = {}) => fetch(`${base}${path}`, { ...init, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', ...(init.headers || {}) }, signal: AbortSignal.timeout(150000) });

// Custom charged events next to the synthetic dataset-item event would mean customers are billed twice per result.
export function doubleBilling(counts) {
  if (!counts || typeof counts !== 'object') return false;
  const custom = Object.keys(counts).filter((k) => !k.startsWith('apify-') && counts[k] > 0);
  return custom.length > 0 && (counts['apify-default-dataset-item'] || 0) > 0;
}

async function runCheck({ actor, input, verify }) {
  const t0 = Date.now(), id = encodeURIComponent(`${user}~${actor}`);
  const out = (ok, detail) => ({ actor, ok, detail, ms: Date.now() - t0 });
  try {
    const start = await api(`/v2/acts/${id}/runs?waitForFinish=60`, { method: 'POST', body: JSON.stringify(input) });
    if (!start.ok) return out(false, `start HTTP ${start.status}`);
    let run = (await start.json()).data;
    for (let i = 0; i < 3 && run && ['READY', 'RUNNING'].includes(run.status); i++) {
      const poll = await api(`/v2/actor-runs/${run.id}?waitForFinish=60`);
      if (!poll.ok) return out(false, `poll HTTP ${poll.status}`);
      run = (await poll.json()).data;
    }
    if (run?.status !== 'SUCCEEDED') return out(false, `run status ${run?.status}`);
    const ds = await api(`/v2/datasets/${run.defaultDatasetId}/items?format=json&clean=true`);
    if (!ds.ok) return out(false, `dataset HTTP ${ds.status}`);
    const items = await ds.json();
    if (!Array.isArray(items) || !verify(items)) return out(false, 'unexpected output');
    if (doubleBilling(run.chargedEventCounts)) return out(false, `DOUBLE BILLING: ${JSON.stringify(run.chargedEventCounts)}`);
    return out(true, `${items.length} item(s)`);
  } catch (e) { return out(false, String(e.message ?? e).replace(token, '***')); }
}

const results = [];
for (const c of CHECKS) results.push(await runCheck(c));
for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.actor}  ${r.detail}  (${r.ms} ms)`);
process.exit(results.every((r) => r.ok) ? 0 : 1);
