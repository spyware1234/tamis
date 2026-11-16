import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { parseRobots, isAllowed, analyzeBots } from '../src/robots.js';
import { extractSignals } from '../src/html.js';
import { scorePage } from '../src/score.js';
import { auditUrl, normalizeUrl } from '../src/audit.js';
import { createSafeClient } from '../src/safe-http.js';

// Test client: the guard stays ACTIVE, but 127.0.0.1 is declared reachable so a local server can play the website.
const localClient = () => createSafeClient({ isAddressAllowed: (ip) => ip === '127.0.0.1', allowedPorts: null });

const ROBOTS = `
User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
User-agent: CCBot
Disallow: /

User-agent: *
Disallow: /private/
Allow: /private/open$
Disallow: /*.pdf$
Sitemap: http://example.test/sitemap-main.xml
`;

test('robots: groups, specificity, wildcards, sitemap', () => {
  const r = parseRobots(ROBOTS);
  assert.equal(r.sitemaps[0], 'http://example.test/sitemap-main.xml');
  assert.equal(isAllowed(r, 'GPTBot', '/').allowed, false);
  assert.equal(isAllowed(r, 'ClaudeBot', '/x').allowed, false);
  assert.equal(isAllowed(r, 'CCBot', '/x').allowed, false);
  assert.equal(isAllowed(r, 'Googlebot', '/').allowed, true);
  assert.equal(isAllowed(r, 'Googlebot', '/private/a').allowed, false);
  assert.equal(isAllowed(r, 'Googlebot', '/private/open').allowed, true);
  assert.equal(isAllowed(r, 'Googlebot', '/private/open2').allowed, false);
  assert.equal(isAllowed(r, 'Googlebot', '/doc.pdf').allowed, false);
  assert.equal(isAllowed(r, 'Googlebot', '/doc.pdf?x=1').allowed, true);
});
test('robots: empty Disallow allows all; blanket block; no robots', () => {
  assert.equal(isAllowed(parseRobots('User-agent: *\nDisallow:'), 'GPTBot', '/a').allowed, true);
  const block = parseRobots('User-agent: *\nDisallow: /');
  assert.equal(analyzeBots(block).filter((b) => !b.allowed).length, 15);
  assert.equal(analyzeBots(null).every((b) => b.allowed), true);
  // a specific group overrides '*'
  const mixed = parseRobots('User-agent: *\nDisallow: /\n\nUser-agent: OAI-SearchBot\nAllow: /');
  assert.equal(isAllowed(mixed, 'OAI-SearchBot', '/p').allowed, true);
  assert.equal(isAllowed(mixed, 'PerplexityBot', '/p').allowed, false);
});

const body = (n) => Array.from({ length: n }, (_, i) => `word${i}`).join(' ');
const GOOD = `<!doctype html><html lang="en"><head><title>How to audit a website for AI search</title>
<meta name="description" content="A practical guide to checking robots.txt, structured data and content signals so AI assistants can find and cite your pages.">
<link rel="canonical" href="https://example.test/guide"><meta property="og:title" content="x">
<script type="application/ld+json">{"@context":"https://schema.org","@graph":[{"@type":"Article","headline":"x"},{"@type":["Organization","Brand"]}]}</script>
<script>var ignored = "should not count as words words words";</script></head>
<body><h1>Guide</h1><p>${body(320)}</p><img src="a.png" alt="A chart"><img src="b.png" alt="Another"></body></html>`;
const BAD = `<html><head><meta name="robots" content="noindex, nofollow"><title>x</title><script type="application/ld+json">{oops</script></head><body><h1>a</h1><h1>b</h1><p>short</p><img src="a.png"></body></html>`;

test('signals extraction', () => {
  const s = extractSignals(GOOD);
  assert.equal(s.title, 'How to audit a website for AI search');
  assert.equal(s.canonical, 'https://example.test/guide');
  assert.equal(s.lang, 'en');
  assert.equal(s.h1Count, 1);
  assert.deepEqual(s.jsonLd.types.sort(), ['Article', 'Brand', 'Organization']);
  assert.ok(s.wordCount >= 320 && s.wordCount < 340, `wordCount ${s.wordCount}`);
  assert.equal(s.noindex, false);
  const b = extractSignals(BAD);
  assert.equal(b.noindex, true);
  assert.equal(b.jsonLd.invalid, 1);
  assert.equal(b.h1Count, 2);
  assert.equal(b.imagesWithAlt, 0);
});
test('scoring: good page scores high, bad page low with prioritized issues', () => {
  const bots = analyzeBots(parseRobots('User-agent: *\nAllow: /'));
  const good = scorePage({ signals: extractSignals(GOOD), bots, hasSitemap: true, hasLlmsTxt: false });
  assert.equal(good.score, 100);
  assert.equal(good.grade, 'A');
  const blocked = analyzeBots(parseRobots('User-agent: *\nDisallow: /'));
  const bad = scorePage({ signals: extractSignals(BAD), bots: blocked, hasSitemap: false, hasLlmsTxt: false });
  assert.ok(bad.score < 40, `bad score ${bad.score}`);
  assert.equal(bad.issues[0].severity, 'high');
  assert.ok(bad.issues.some((i) => i.code === 'NOINDEX'));
  assert.equal(bad.breakdown.reduce((a, b) => a + b.max, 0), 100);
});

function server() {
  const srv = http.createServer((req, res) => {
    const send = (code, type, text, extra = {}) => { res.writeHead(code, { 'content-type': type, ...extra }); res.end(text); };
    if (req.url === '/robots.txt') return send(200, 'text/plain', 'User-agent: GPTBot\nDisallow: /\n\nUser-agent: TamisAuditBot\nDisallow: /secret\n\nUser-agent: *\nAllow: /\nSitemap: http://' + req.headers.host + '/sm.xml');
    if (req.url === '/sm.xml') return send(200, 'application/xml', '<urlset/>');
    if (req.url === '/good') return send(200, 'text/html; charset=utf-8', GOOD);
    if (req.url === '/hdr-noindex') return send(200, 'text/html', GOOD, { 'x-robots-tag': 'noindex' });
    if (req.url === '/pdf') return send(200, 'application/pdf', '%PDF');
    if (req.url === '/secret') return send(200, 'text/html', GOOD);
    return send(404, 'text/plain', 'nope');
  });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r(srv)));
}

test('end-to-end against a local server (real HTTP, robots, sitemap probe)', async () => {
  const srv = await server();
  const base = `http://127.0.0.1:${srv.address().port}`;
  const client = localClient();
  try {
    const cache = new Map();
    const ok = await auditUrl(`${base}/good`, { client, originCache: cache });
    assert.equal(ok.status, 'audited');
    assert.equal(ok.hasSitemap, true);
    assert.equal(ok.hasLlmsTxt, false);
    assert.equal(ok.score, 100);
    assert.equal(ok.aiCrawlers.find((b) => b.bot === 'GPTBot').allowed, false);
    assert.equal(ok.aiCrawlers.find((b) => b.bot === 'Googlebot').allowed, true);
    assert.equal(cache.size, 1);
    const hdr = await auditUrl(`${base}/hdr-noindex`, { client, originCache: cache });
    assert.ok(hdr.issues.some((i) => i.code === 'NOINDEX'));
    assert.equal((await auditUrl(`${base}/secret`, { client, originCache: cache })).status, 'blocked-by-robots');
    assert.equal((await auditUrl(`${base}/secret`, { client, originCache: cache, respectRobots: false })).status, 'audited');
    assert.equal((await auditUrl(`${base}/missing`, { client, originCache: cache })).status, 'http-404');
    assert.equal((await auditUrl(`${base}/pdf`, { client, originCache: cache })).status, 'not-html');
  } finally { srv.close(); }
});

test('input safety', async () => {
  assert.equal((await auditUrl('ftp://example.com')).status, 'invalid-url');
  assert.equal((await auditUrl('')).status, 'invalid-url');
  assert.equal((await auditUrl('http://localhost:3000')).status, 'blocked-address');
  assert.equal((await auditUrl('http://127.0.0.1/')).status, 'blocked-address');
  assert.equal((await auditUrl('http://192.168.1.5/')).status, 'blocked-address');
  assert.equal(normalizeUrl('example.com/a#frag').href, 'https://example.com/a');
});

test('hostile HTML is processed in linear time and outputs stay bounded', () => {
  const cases = {
    unclosedMeta: '<meta '.repeat(250000),
    ltFlood: '<'.repeat(1_400_000) + '>',
    unclosedScripts: '<script>'.repeat(150000),
    manyTags: '<a b="c">x</a>'.repeat(100000),
    hugeAttr: '<meta name="description" content="' + 'x'.repeat(1_000_000) + '">',
    longTitle: '<title>' + 'T'.repeat(1_000_000) + '</title>',
    deepJson: '<script type="application/ld+json">' + '['.repeat(100000) + ']'.repeat(100000) + '</script>',
    noGt: 'a<b '.repeat(300000),
  };
  for (const [name, html] of Object.entries(cases)) {
    const t0 = Date.now();
    const s = extractSignals(html);
    assert.ok(Date.now() - t0 < 1500, `${name} took ${Date.now() - t0} ms`);
    assert.ok((s.title ?? '').length <= 300 && (s.description ?? '').length <= 500, name);
    assert.ok(s.jsonLd.types.length <= 30);
  }
});
test('a robots.txt cannot redirect the sitemap probe to another host', async () => {
  const seen = [];
  const client = { fetchText: async (u) => (u.endsWith('/robots.txt') ? { status: 200, text: 'User-agent: *\nAllow: /\nSitemap: http://169.254.169.254/latest/meta-data\nSitemap: https://elsewhere.example/sm.xml' } : { status: 200, contentType: 'text/html', text: GOOD, url: u, redirects: 0 }),
    probe: async (u) => { seen.push(u); return 200; } };
  await auditUrl('https://site.test/page', { client });
  assert.ok(seen.includes('https://site.test/sitemap.xml'));
  assert.ok(!seen.some((u) => u.includes('169.254') || u.includes('elsewhere')));
});

test('hostile robots.txt: pathological patterns cannot stall the audit', () => {
  const evil = 'User-agent: *\nDisallow: /' + 'a*'.repeat(40) + 'b\n' + 'Disallow: /' + 'x'.repeat(5000) + '\n' + Array.from({ length: 20000 }, (_, i) => `Disallow: /p${i}`).join('\n');
  const t0 = Date.now();
  const r = parseRobots(evil);
  const d = isAllowed(r, 'GPTBot', '/' + 'a'.repeat(2000));
  assert.ok(Date.now() - t0 < 1000, `took ${Date.now() - t0} ms`);
  assert.equal(d.allowed, true);
  assert.ok(r.groups[0].rules.length <= 5000);
});
