import net from 'node:net';
import { joinTxt, parseSpf, parseDmarc, parseDkim } from './records.js';

export const DEFAULT_SELECTORS = ['default', 'google', 'selector1', 'selector2', 's1', 's2', 'k1', 'k2', 'k3', 'dkim', 'mail', 'smtp', 'mandrill', 'mxvault', 'zoho', 'protonmail', 'protonmail2', 'protonmail3', 'scph1220', 'everlytickey1', 'cm', 'pm'];

const RESERVED_NAME = /(^|\.)(localhost|local|internal|localdomain|lan|home\.arpa|intranet|invalid|onion|corp|home)\.?$/i;

export function normalizeDomain(raw) {
  if (typeof raw !== 'string') throw new Error('Domain must be a string');
  let s = raw.trim().toLowerCase();
  if (s.length > 300) throw new Error('Domain too long');
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/^.*@/, '').split(/[/?#:]/)[0].replace(/\.$/, '');
  if (!s) throw new Error('Empty domain');
  try { s = new URL('http://' + s).hostname; } catch { throw new Error('Invalid domain'); }
  if (net.isIP(s.replace(/^\[|\]$/g, ''))) throw new Error('IP addresses are not domains');
  if (s.length > 253 || !/^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/.test(s)) throw new Error('Invalid domain');
  if (RESERVED_NAME.test(s)) throw new Error('Reserved or local domain names are not audited');
  const tld = s.slice(s.lastIndexOf('.') + 1);
  if (!/^([a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(tld)) throw new Error('Invalid top-level domain');
  return s;
}

export const sanitizeSelectors = (list) => [...new Set((Array.isArray(list) ? list : []).filter((x) => typeof x === 'string')
  .map((x) => x.trim().toLowerCase()).filter((x) => /^[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?$/.test(x)))].slice(0, 20);

const NO_DATA = new Set(['ENODATA', 'ENOENT']);
const NXDOMAIN = new Set(['ENOTFOUND', 'NXDOMAIN']);
async function txt(resolver, name) {
  try { return (await resolver.resolveTxt(name)).map(joinTxt); } catch (e) { if (NO_DATA.has(e?.code) || NXDOMAIN.has(e?.code)) return []; throw e; }
}
async function mx(resolver, name) {
  try { return await resolver.resolveMx(name); } catch (e) { if (NO_DATA.has(e?.code) || NXDOMAIN.has(e?.code)) return []; throw e; }
}
async function exists(resolver, name) { // false only when the name does not exist at all (NXDOMAIN)
  try { await resolver.resolveTxt(name); return true; } catch (e) { if (NXDOMAIN.has(e?.code)) return false; if (NO_DATA.has(e?.code)) return true; throw e; }
}

// Counts DNS-querying SPF terms recursively (include/redirect targets are resolved). RFC 7208 limit is 10.
// `budget.left` bounds the number of DNS queries we are willing to spend on one (possibly hostile) record tree.
export async function spfLookups(resolver, spf, depth = 0, seen = new Set(), budget = { left: 40, exhausted: false }) {
  let n = spf.mechanisms.filter((m) => ['include', 'a', 'mx', 'ptr', 'exists'].includes(m.name)).length + (spf.redirect ? 1 : 0);
  if (depth >= 6) return n;
  const targets = [...spf.includes, ...(spf.redirect ? [spf.redirect] : [])];
  for (const t of targets) {
    if (seen.has(t)) continue;
    seen.add(t);
    if (budget.left <= 0) { budget.exhausted = true; break; }
    budget.left--;
    const rec = (await txt(resolver, t)).find((r) => /^v=spf1(\s|$)/i.test(r));
    if (rec) n += await spfLookups(resolver, parseSpf(rec), depth + 1, seen, budget);
  }
  return n;
}

export async function auditDomain(rawDomain, { resolver, selectors = DEFAULT_SELECTORS } = {}) {
  selectors = selectors.slice(0, 45);
  const checkedAt = new Date().toISOString();
  let domain;
  try { domain = normalizeDomain(rawDomain); } catch (e) { return { domain: rawDomain, ok: false, status: 'invalid-domain', error: e.message, checkedAt }; }
  const issues = [], breakdown = [];
  const add = (key, max, got) => breakdown.push({ key, max, points: got });
  const issue = (severity, code, message, fix) => issues.push({ severity, code, message, fix });

  try {
    if (!(await exists(resolver, domain))) return { domain, ok: false, status: 'domain-not-found', error: 'The domain does not exist (NXDOMAIN).', checkedAt };
    const [mxRecs, rootTxt, dmarcTxt, mtaTxt, tlsrptTxt, bimiTxt] = await Promise.all([
      mx(resolver, domain), txt(resolver, domain), txt(resolver, `_dmarc.${domain}`),
      txt(resolver, `_mta-sts.${domain}`), txt(resolver, `_smtp._tls.${domain}`), txt(resolver, `default._bimi.${domain}`),
    ]);

    // MX
    add('mx', 10, mxRecs.length ? 10 : 0);
    if (!mxRecs.length) issue('low', 'NO_MX', 'No MX records: the domain cannot receive email.', 'Fine for send-only domains; otherwise add MX records. Receivers may also check that a sender domain can receive replies.');

    // SPF
    const spfRecs = rootTxt.filter((r) => /^v=spf1(\s|$)/i.test(r));
    let spf = null, lookups = null, spfPts = 0;
    if (!spfRecs.length) issue('high', 'NO_SPF', 'No SPF record.', 'Publish one TXT record starting with v=spf1 listing your senders and ending with -all (or ~all while testing).');
    else if (spfRecs.length > 1) issue('high', 'MULTIPLE_SPF', `${spfRecs.length} SPF records found; receivers treat this as an error.`, 'Merge all senders into a single v=spf1 record.');
    else {
      spf = parseSpf(spfRecs[0]);
      const budget = { left: 40, exhausted: false };
      lookups = await spfLookups(resolver, spf, 0, new Set(), budget);
      if (budget.exhausted) issue('low', 'SPF_TREE_TRUNCATED', 'The SPF include tree is very large; analysis stopped after 40 DNS queries.', 'Simplify the record: a tree this large almost certainly exceeds the 10-lookup limit.');
      if (lookups > 10) issue('high', 'SPF_TOO_MANY_LOOKUPS', `SPF needs ${lookups} DNS lookups (limit 10): evaluation fails with a permanent error.`, 'Remove unused include: entries, replace includes with ip4/ip6 ranges, or use an SPF flattening service.');
      else {
        spfPts = 12;
        if (spf.all === '-') spfPts += 8;
        else if (spf.all === '~') { spfPts += 6; issue('low', 'SPF_SOFTFAIL', 'SPF ends with ~all (soft fail).', 'Move to -all once all legitimate senders are listed and DMARC reports are clean.'); }
        else if (spf.all === '+') issue('high', 'SPF_PLUS_ALL', 'SPF ends with +all: it authorizes every server on the internet.', 'Replace +all with -all or ~all immediately.');
        else issue('medium', 'SPF_NO_POLICY', spf.redirect ? 'SPF delegates via redirect=; policy lives in the target record.' : 'SPF has no terminating all mechanism (or uses ?all).', 'End the record with -all or ~all.');
        if (spf.redirect && !spf.all) spfPts += 4;
      }
    }
    add('spf', 20, spfPts);

    // DKIM (only the tested selectors can be found)
    const found = [];
    await Promise.all(selectors.map(async (sel) => {
      const recs = (await txt(resolver, `${sel}._domainkey.${domain}`)).filter((r) => /v=DKIM1|(^|;)\s*p=/i.test(r));
      if (recs.length) found.push({ selector: sel, ...parseDkim(recs[0]) });
    }));
    found.sort((a, b) => a.selector.localeCompare(b.selector));
    const live = found.filter((k) => k.hasKey);
    let dkimPts = 0;
    if (!found.length) issue('medium', 'DKIM_NOT_FOUND', `No DKIM key found among ${selectors.length} common selectors. Custom selectors cannot be discovered.`, 'Enable DKIM signing at your email provider and publish its selector record; pass your selector in the "dkimSelectors" input to verify it.');
    else if (!live.length) issue('high', 'DKIM_REVOKED', 'DKIM records exist but all keys are revoked (empty p=).', 'Publish a valid public key for the selector in use.');
    else {
      const best = Math.max(...live.map((k) => k.estimatedBits ?? 2048));
      dkimPts = best >= 2048 ? 20 : 14;
      if (best < 2048) issue('medium', 'DKIM_WEAK_KEY', `Strongest DKIM key found is about ${best} bits.`, 'Rotate to a 2048-bit key.');
    }
    add('dkim', 20, dkimPts);

    // DMARC
    const dmarcRecs = dmarcTxt.filter((r) => /^v=DMARC1/i.test(r.trim()));
    let dmarc = null, dPts = 0;
    if (!dmarcRecs.length) issue('high', 'NO_DMARC', 'No DMARC record at _dmarc.' + domain + '.', 'Publish v=DMARC1; p=none; rua=mailto:... first, then tighten to quarantine and reject.');
    else {
      if (dmarcRecs.length > 1) issue('high', 'MULTIPLE_DMARC', 'Multiple DMARC records found; receivers ignore DMARC in this case.', 'Keep a single DMARC record.');
      dmarc = parseDmarc(dmarcRecs[0]);
      dPts = dmarcRecs.length > 1 ? 0 : 15;
      let pol = dmarc.policy === 'reject' ? 20 : dmarc.policy === 'quarantine' ? 15 : dmarc.policy === 'none' ? 5 : 0;
      if (dmarc.pct < 100) { pol = Math.floor(pol / 2); issue('medium', 'DMARC_PCT', `DMARC policy applies to only ${dmarc.pct}% of mail.`, 'Raise pct to 100 once reports look clean.'); }
      if (dmarc.policy === 'none') issue('medium', 'DMARC_MONITOR_ONLY', 'DMARC policy is p=none (monitoring only): spoofed mail is not blocked.', 'Move to p=quarantine, then p=reject, after reviewing aggregate reports.');
      if (!dmarc.policy) issue('high', 'DMARC_NO_POLICY', 'DMARC record has no valid p= tag.', 'Add p=none, p=quarantine or p=reject.');
      if (dmarcRecs.length === 1) dPts += pol;
      if (dmarc.rua && dmarcRecs.length === 1) dPts += 5; else issue('low', 'DMARC_NO_RUA', 'No rua= reporting address: you will not receive aggregate reports.', 'Add rua=mailto:dmarc@yourdomain (or a reporting service).');
    }
    add('dmarc', 40, dPts);

    // Transport security (optional extras)
    const mta = mtaTxt.some((r) => /^v=STSv1/i.test(r));
    const tlsrpt = tlsrptTxt.some((r) => /^v=TLSRPTv1/i.test(r));
    add('mtaSts', 5, mta ? 5 : 0); add('tlsRpt', 5, tlsrpt ? 5 : 0);
    if (!mta) issue('low', 'NO_MTA_STS', 'No MTA-STS policy record.', 'Optional hardening: publish _mta-sts TXT and an HTTPS policy file to enforce TLS for inbound mail.');
    if (!tlsrpt) issue('low', 'NO_TLS_RPT', 'No TLS-RPT record.', 'Optional: publish _smtp._tls TXT (v=TLSRPTv1; rua=...) to receive TLS failure reports.');

    const score = breakdown.reduce((a, b) => a + b.points, 0);
    const grade = score >= 85 ? 'A' : score >= 70 ? 'B' : score >= 55 ? 'C' : score >= 40 ? 'D' : 'F';
    const order = { high: 0, medium: 1, low: 2 };
    issues.sort((a, b) => order[a.severity] - order[b.severity]);
    return {
      domain, ok: true, status: 'audited', score, grade, issues, breakdown, checkedAt,
      mx: mxRecs.sort((a, b) => a.priority - b.priority).map((m) => `${m.priority} ${m.exchange}`),
      spf: spf && { record: spf.raw, all: spf.all, dnsLookups: lookups },
      dkim: found.map(({ selector, keyType, estimatedBits, revoked, testing }) => ({ selector, keyType, estimatedBits, revoked, testing })),
      dmarc: dmarc && { record: dmarc.raw, policy: dmarc.policy, subdomainPolicy: dmarc.subdomainPolicy, pct: dmarc.pct, rua: dmarc.rua },
      mtaSts: mta, tlsRpt: tlsrpt, bimi: bimiTxt.some((r) => /^v=BIMI1/i.test(r)),
    };
  } catch (e) {
    return { domain, ok: false, status: 'dns-error', error: `${e?.code ?? ''} ${String(e?.message ?? e).slice(0, 120)}`.trim(), checkedAt };
  }
}
