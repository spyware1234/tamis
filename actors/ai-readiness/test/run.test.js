import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { run, parseInput, LIMITS } from '../src/run.js';
import { createSafeClient } from '../src/safe-http.js';
import { fakePlatform, RunAborted } from './helpers/fake-platform.js';

const quiet = { log() {} };
const localClient = () => createSafeClient({ isAddressAllowed: (ip) => ip === '127.0.0.1', allowedPorts: null });
const PAGE = '<!doctype html><html lang="en"><head><title>A reasonably long page title</title></head><body><h1>Hi</h1><p>' + 'word '.repeat(350) + '</p></body></html>';

function site() {
  const hits = [];
  const srv = http.createServer((req, res) => {
    hits.push({ url: req.url, t: Date.now() });
    if (req.url === '/robots.txt') { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('User-agent: TamisAuditBot\nDisallow: /private\n'); }
    if (req.url.startsWith('/ok')) { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(PAGE); }
    if (req.url === '/pdf') { res.writeHead(200, { 'content-type': 'application/pdf' }); return res.end('%PDF'); }
    if (req.url === '/to-internal') { res.writeHead(302, { location: 'http://127.0.0.2:1/' }); return res.end(); }
    res.writeHead(404, { 'content-type': 'text/plain' }); res.end('nope');
  });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r({ srv, hits, base: `http://127.0.0.1:${srv.address().port}` })));
}

test('input validation', () => {
  assert.throws(() => parseInput({}), /non-empty array/);
  assert.throws(() => parseInput({ urls: [] }), /non-empty array/);
  assert.throws(() => parseInput({ urls: ['a'], maxUrls: 0 }), /between 1 and/);
  assert.throws(() => parseInput({ urls: ['a'], maxUrls: 1e6 }), /between 1 and/);
  assert.equal(parseInput({ urls: ['a'] }).respectRobots, true);
  assert.equal(parseInput({ urls: ['a'], respectRobots: false }).respectRobots, false);
});

test('billing: only audited pages and attempted-but-failed fetches are written to the default dataset; refused inputs are free', async () => {
  const s = await site();
  try {
    const urls = [`${s.base}/ok1`, `${s.base}/ok1`, `${s.base}/ok2`, `${s.base}/missing`, `${s.base}/pdf`, `${s.base}/private/x`, `${s.base}/to-internal`,
      'ftp://x.test', '', 42, null, { url: `${s.base}/ok3` }, 'http://localhost/', 'http://169.254.169.254/', 'http://10.0.0.1/admin'];
    const { Actor, st } = fakePlatform({ input: { urls }, price: 0.01 });
    const sum = await run(Actor, { client: localClient(), log: quiet, delayMs: 0 });
    const statuses = st.dataset.map((r) => r.status).sort();
    assert.deepEqual(statuses, ['audited', 'audited', 'audited', 'http-404', 'not-html']);
    assert.equal(sum.billed, 5);
    assert.equal(+st.chargedUsd.toFixed(4), 0.05);                         // 5 results x $0.01, nothing else
    const rej = st.kv.REJECTED.map((r) => r.status).sort();
    assert.deepEqual(rej, ['blocked-address', 'blocked-address', 'blocked-address', 'blocked-address', 'blocked-by-robots', 'duplicate', 'invalid-url', 'invalid-url', 'invalid-url', 'invalid-url'].sort());
    assert.ok(st.dataset.every((r) => typeof r.index === 'number'));
    assert.equal(new Set(st.dataset.map((r) => r.url)).size, st.dataset.length, 'no URL billed twice');
  } finally { s.srv.close(); }
});

test('SSRF through the whole Actor: internal targets are never fetched nor billed', async () => {
  const internal = http.createServer((q, r) => { internal.hits++; r.end('INTERNAL'); }); internal.hits = 0;
  await new Promise((r) => internal.listen(0, '127.0.0.2', r));
  const s = await site();
  try {
    const { Actor, st } = fakePlatform({ input: { urls: [`http://127.0.0.2:${internal.address().port}/`, `${s.base}/to-internal`] }, price: 0.01 });
    await run(Actor, { client: localClient(), log: quiet, delayMs: 0 });
    assert.equal(internal.hits, 0);
    assert.equal(st.dataset.length, 0);
    assert.equal(st.chargedUsd, 0);
    assert.equal(st.kv.REJECTED.length, 2);
  } finally { s.srv.close(); internal.close(); }
});

test('spending limit and platform failure: nothing delivered without being charged; run stops', async () => {
  const s = await site();
  try {
    const urls = Array.from({ length: 10 }, (_, i) => `${s.base}/ok${i}`);
    const lim = fakePlatform({ input: { urls }, price: 0.01, maxTotalChargeUsd: 0.03 });
    await assert.rejects(() => run(lim.Actor, { client: localClient(), log: quiet, delayMs: 0, concurrency: 1 }), RunAborted);
    assert.equal(lim.st.dataset.length, 3);
    assert.ok(lim.st.chargedUsd <= 0.03 + 1e-9);
    const fail = fakePlatform({ input: { urls }, failAfterPushCalls: 2 });
    await assert.rejects(() => run(fail.Actor, { client: localClient(), log: quiet, delayMs: 0, concurrency: 1 }), /simulated platform error/);
    assert.equal(fail.st.dataset.length, 2);
  } finally { s.srv.close(); }
});

test('caps: maxUrls and per-site limit are enforced and not billed', async () => {
  const s = await site();
  try {
    const urls = Array.from({ length: LIMITS.perSiteCap + 5 }, (_, i) => `${s.base}/ok${i}`);
    const a = fakePlatform({ input: { urls, maxUrls: 1000 } });
    await run(a.Actor, { client: localClient(), log: quiet, delayMs: 0 });
    assert.equal(a.st.dataset.length, LIMITS.perSiteCap);
    assert.equal(a.st.kv.REJECTED.filter((r) => r.status === 'skipped-site-limit').length, 5);
    const b = fakePlatform({ input: { urls: urls.slice(0, 10), maxUrls: 3 } });
    await run(b.Actor, { client: localClient(), log: quiet, delayMs: 0 });
    assert.equal(b.st.dataset.length, 3);
    assert.equal(b.st.kv.REJECTED.filter((r) => r.status === 'skipped-over-max-urls').length, 7);
  } finally { s.srv.close(); }
});

test('politeness: robots.txt fetched once per site and requests to one site are spaced', async () => {
  const s = await site();
  try {
    const { Actor } = fakePlatform({ input: { urls: [`${s.base}/ok1`, `${s.base}/ok2`, `${s.base}/ok3`] } });
    await run(Actor, { client: localClient(), log: quiet, delayMs: 120 });
    assert.equal(s.hits.filter((h) => h.url === '/robots.txt').length, 1);
    assert.equal(s.hits.filter((h) => h.url === '/sitemap.xml').length, 1);
    const pageHits = s.hits.filter((h) => h.url.startsWith('/ok'));
    assert.equal(pageHits.length, 3);
    for (let i = 1; i < pageHits.length; i++) assert.ok(pageHits[i].t - pageHits[i - 1].t >= 100, 'spacing between page requests');
  } finally { s.srv.close(); }
});

test('Actor.charge is never needed or called', async () => {
  const s = await site();
  try {
    const { Actor } = fakePlatform({ input: { urls: [`${s.base}/ok1`] } });
    assert.equal(typeof Actor.charge, 'undefined');
    await run(Actor, { client: localClient(), log: quiet, delayMs: 0 });
  } finally { s.srv.close(); }
});
