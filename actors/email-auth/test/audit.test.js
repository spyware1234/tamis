import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { parseSpf, parseDmarc, parseDkim } from '../src/records.js';
import { auditDomain, normalizeDomain, spfLookups, sanitizeSelectors } from '../src/audit.js';

const spki = (bits) => crypto.generateKeyPairSync('rsa', { modulusLength: bits }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const K2048 = spki(2048), K1024 = spki(1024);

function fakeResolver(zone) {
  const miss = () => Object.assign(new Error('nx'), { code: 'ENOTFOUND' });
  return {
    resolveTxt: async (n) => { if (!zone.txt?.[n]) throw miss(); return zone.txt[n].map((s) => s.match(/.{1,200}/g)); }, // split into chunks like real DNS
    resolveMx: async (n) => { if (!zone.mx?.[n]) throw miss(); return zone.mx[n]; },
  };
}

test('SPF parsing', () => {
  const s = parseSpf('v=spf1 ip4:1.2.3.4 ip6:2001:db8::/32 include:_spf.google.com a mx -all');
  assert.deepEqual(s.includes, ['_spf.google.com']);
  assert.equal(s.all, '-'); assert.equal(s.ip4, 1); assert.equal(s.ip6, 1);
  assert.equal(parseSpf('v=spf1 redirect=_spf.example.com').redirect, '_spf.example.com');
  assert.equal(parseSpf('v=spf1 +all').all, '+');
  assert.equal(parseSpf('v=spf1 ?all').all, '?');
});
test('DMARC and DKIM parsing', () => {
  const d = parseDmarc('v=DMARC1; p=quarantine; pct=50; rua=mailto:a@x.com; adkim=s');
  assert.equal(d.policy, 'quarantine'); assert.equal(d.pct, 50); assert.equal(d.adkim, 's'); assert.equal(parseDmarc('v=DMARC1; p=reject').pct, 100);
  assert.equal(parseDkim(`v=DKIM1; k=rsa; p=${K2048}`).estimatedBits, 2048);
  assert.equal(parseDkim(`v=DKIM1; p=${K1024}`).estimatedBits, 1024);
  assert.equal(parseDkim('v=DKIM1; p=').revoked, true);
  assert.equal(parseDkim('v=DKIM1; k=ed25519; p=abc=').estimatedBits, null);
});
test('domain normalization', () => {
  assert.equal(normalizeDomain('https://Example.COM/path?x=1'), 'example.com');
  assert.equal(normalizeDomain('bob@Example.com'), 'example.com');
  assert.equal(normalizeDomain('example.com.'), 'example.com');
  assert.equal(normalizeDomain('bücher.de'), 'xn--bcher-kva.de');
  assert.throws(() => normalizeDomain('nodot'));
  for (const bad of ['127.0.0.1', '[::1]', 'localhost', 'a.localhost', 'intranet.lan', 'host.internal', 'x.local', '10.0.0.1', 'exa mple.com', '-bad.com', 'a..b.com', 'x.c0m', 'x.123', 'a.b.invalid', 'x.onion', 42, null, 'a'.repeat(300) + '.com']) assert.throws(() => normalizeDomain(bad), undefined, String(bad));
  assert.throws(() => normalizeDomain(''));
});
test('SPF lookup counting follows includes and detects the 10-lookup limit', async () => {
  const txt = { 'a.test': ['v=spf1 include:b.test include:c.test -all'], 'b.test': ['v=spf1 a mx include:d.test -all'], 'c.test': ['v=spf1 ip4:1.1.1.1 -all'], 'd.test': ['v=spf1 a a a a a a a a a -all'] };
  const r = fakeResolver({ txt });
  assert.equal(await spfLookups(r, parseSpf('v=spf1 include:a.test -all')), 1 + 2 + 3 + 9);
  assert.equal(await spfLookups(r, parseSpf('v=spf1 ip4:1.1.1.1 -all')), 0);
});

test('strong domain scores 100', async () => {
  const d = 'good.test';
  const r = await auditDomain(d, { resolver: fakeResolver({
    mx: { [d]: [{ exchange: 'mx2.good.test', priority: 20 }, { exchange: 'mx1.good.test', priority: 10 }] },
    txt: { [d]: ['v=spf1 include:_spf.mail.test -all'], '_spf.mail.test': ['v=spf1 ip4:10.0.0.0/8 -all'],
      [`_dmarc.${d}`]: ['v=DMARC1; p=reject; rua=mailto:d@good.test'], [`selector1._domainkey.${d}`]: [`v=DKIM1; k=rsa; p=${K2048}`],
      [`_mta-sts.${d}`]: ['v=STSv1; id=1'], [`_smtp._tls.${d}`]: ['v=TLSRPTv1; rua=mailto:t@good.test'] } }) });
  assert.equal(r.status, 'audited');
  assert.equal(r.score, 100, JSON.stringify(r.issues));
  assert.equal(r.grade, 'A');
  assert.deepEqual(r.mx, ['10 mx1.good.test', '20 mx2.good.test']);
  assert.equal(r.dkim[0].selector, 'selector1');
  assert.equal(r.spf.dnsLookups, 1);
});

test('weak domain: findings are prioritized', async () => {
  const d = 'weak.test';
  const r = await auditDomain(d, { resolver: fakeResolver({
    mx: { [d]: [{ exchange: 'mx.weak.test', priority: 10 }] },
    txt: { [d]: ['v=spf1 +all', 'v=spf1 -all'], [`_dmarc.${d}`]: ['v=DMARC1; p=none'], [`default._domainkey.${d}`]: [`v=DKIM1; p=${K1024}`] } }) });
  const codes = r.issues.map((i) => i.code);
  assert.ok(codes.includes('MULTIPLE_SPF') && codes.includes('DMARC_MONITOR_ONLY') && codes.includes('DKIM_WEAK_KEY') && codes.includes('DMARC_NO_RUA'));
  assert.equal(r.issues[0].severity, 'high');
  assert.ok(r.score < 50 && r.grade === "D", `score ${r.score}`);
});

test('empty domain, bad domain, DNS failure', async () => {
  const empty = await auditDomain('empty.test', { resolver: fakeResolver({ txt: { 'empty.test': ['hello'] } }) });
  assert.equal(empty.score, 0);
  assert.ok(empty.issues.some((i) => i.code === 'NO_SPF') && empty.issues.some((i) => i.code === 'NO_DMARC'));
  assert.equal((await auditDomain('???', { resolver: fakeResolver({}) })).status, 'invalid-domain');
  const boom = { resolveTxt: async () => { throw Object.assign(new Error('timeout'), { code: 'ETIMEOUT' }); }, resolveMx: async () => [] };
  assert.equal((await auditDomain('x.test', { resolver: boom })).status, 'dns-error');
});
test('SPF over 10 lookups yields a high issue and no SPF points', async () => {
  const d = 'many.test';
  const r = await auditDomain(d, { resolver: fakeResolver({ mx: { [d]: [{ exchange: 'm.many.test', priority: 1 }] }, txt: { [d]: ['v=spf1 ' + 'a '.repeat(11) + '-all'] } }) });
  assert.ok(r.issues.some((i) => i.code === 'SPF_TOO_MANY_LOOKUPS'));
  assert.equal(r.breakdown.find((b) => b.key === 'spf').points, 0);
});

test('non-existent domain (NXDOMAIN) is reported as such, not as an empty-but-valid audit', async () => {
  const r = await auditDomain('typo-domain.test', { resolver: fakeResolver({}) });
  assert.equal(r.status, 'domain-not-found');
  assert.equal(r.ok, false);
});
test('hostile SPF tree: DNS queries are bounded and the 10-lookup limit is still detected', async () => {
  const txt = { 'big.test': ['v=spf1 ' + Array.from({ length: 30 }, (_, i) => `include:n${i}.big.test`).join(' ') + ' -all'] };
  let queries = 0;
  for (let i = 0; i < 30; i++) txt[`n${i}.big.test`] = ['v=spf1 ' + Array.from({ length: 30 }, (_, j) => `include:m${i}-${j}.big.test`).join(' ') + ' -all'];
  const counting = fakeResolver({ txt });
  const r0 = counting.resolveTxt; counting.resolveTxt = async (n) => { queries++; return r0(n); };
  const r = await auditDomain('big.test', { resolver: Object.assign(counting, { resolveMx: async () => [{ exchange: 'm.big.test', priority: 1 }] }) });
  assert.ok(r.issues.some((i) => i.code === 'SPF_TOO_MANY_LOOKUPS'));
  assert.ok(r.issues.some((i) => i.code === 'SPF_TREE_TRUNCATED'));
  assert.ok(queries < 120, `queries ${queries}`);
});
test('selector sanitization', () => {
  assert.deepEqual(sanitizeSelectors(['Good', 'a.b-c', 'x/../y', 'bad selector', '', 5, null, 'good', '-no', 'a'.repeat(70)]), ['good', 'a.b-c']);
  assert.equal(sanitizeSelectors(Array.from({ length: 100 }, (_, i) => `s${i}`)).length, 20);
  assert.deepEqual(sanitizeSelectors('nope'), []);
});
