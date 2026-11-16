import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { createSafeClient } from '../src/safe-http.js';
import { auditUrl } from '../src/audit.js';

function listen(handler, host = '0.0.0.0') {
  const hits = [];
  const srv = http.createServer((req, res) => { hits.push({ url: req.url, host: req.headers.host, ua: req.headers['user-agent'], enc: req.headers['accept-encoding'] }); handler(req, res); });
  return new Promise((r) => srv.listen(0, host, () => r({ srv, hits, port: srv.address().port })));
}
// Policy for tests: only 127.0.0.1 is "public". 127.0.0.2, 127.0.0.3 ... stand in for forbidden internal addresses.
const client = (extra = {}) => createSafeClient({ isAddressAllowed: (ip) => ip === '127.0.0.1', allowedPorts: null, ...extra });
const fakeLookup = (map) => (host, opts, cb) => { const a = map[host]; if (!a) return cb(Object.assign(new Error('nx'), { code: 'ENOTFOUND' })); cb(null, a.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }))); };

test('default policy refuses loopback / private / metadata targets without opening any connection', async () => {
  const { srv, hits, port } = await listen((q, s) => s.end('secret'));
  try {
    const c = createSafeClient(); // production defaults
    for (const url of [`http://127.0.0.1:${port}/`, `http://localhost:${port}/`, `http://[::1]:${port}/`, `http://2130706433:${port}/`, `http://0x7f.1:${port}/`,
      `http://127.1:${port}/`, 'http://169.254.169.254/latest/meta-data/', 'http://10.0.0.5/', 'http://192.168.1.1/', 'http://[::ffff:127.0.0.1]/', 'http://[fd00::1]/']) {
      const r = await c.fetchText(url);
      assert.equal(r.status, 0, url); assert.equal(r.blocked, true, `${url} -> ${r.error}`);
    }
    assert.equal(hits.length, 0, 'no request may reach the internal server');
  } finally { srv.close(); }
});

test('redirect from an allowed host to a forbidden address is blocked at the hop, and the target is never contacted', async () => {
  const target = await listen((q, s) => s.end('INTERNAL SECRET'));
  const front = await listen((req, res) => {
    const to = { '/to-127-0-0-2': `http://127.0.0.2:${target.port}/admin`, '/to-metadata': 'http://169.254.169.254/latest/meta-data/', '/to-v6': `http://[::1]:${target.port}/`,
      '/to-file': 'file:///etc/passwd', '/to-gopher': 'gopher://127.0.0.1:70/x', '/to-ftp': 'ftp://127.0.0.1/', '/to-creds': `http://user:pw@127.0.0.1:${target.port}/` }[req.url];
    if (!to) { res.writeHead(404); return res.end(); }
    res.writeHead(302, { location: to }); res.end();
  }, '127.0.0.1');
  try {
    const c = client();
    for (const p of ['/to-127-0-0-2', '/to-metadata', '/to-v6', '/to-file', '/to-gopher', '/to-ftp', '/to-creds']) {
      const r = await c.fetchText(`http://127.0.0.1:${front.port}${p}`);
      assert.equal(r.status, 0, p); assert.equal(r.blocked, true, `${p}: ${r.error}`);
      assert.ok(!r.text.includes('INTERNAL SECRET'));
    }
    assert.equal(target.hits.length, 0, 'internal target must never be requested');
    // same, through the full audit pipeline
    const a = await auditUrl(`http://127.0.0.1:${front.port}/to-127-0-0-2`, { client: c, respectRobots: false });
    assert.equal(a.status, 'blocked-address');
  } finally { front.srv.close(); target.srv.close(); }
});

test('legitimate redirects (absolute, relative, chained) are followed and re-validated; loops and long chains stop', async () => {
  const s = await listen((req, res) => {
    if (req.url === '/a') { res.writeHead(301, { location: '/b' }); return res.end(); }
    if (req.url === '/b') { res.writeHead(302, { location: `http://127.0.0.1:${s.port}/c` }); return res.end(); }
    if (req.url === '/c') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<title>ok</title>'); }
    if (req.url === '/loop') { res.writeHead(302, { location: '/loop' }); return res.end(); }
    const m = req.url.match(/^\/chain(\d+)$/);
    if (m) { res.writeHead(302, { location: `/chain${Number(m[1]) + 1}` }); return res.end(); }
    res.writeHead(404); res.end();
  }, '127.0.0.1');
  try {
    const c = client();
    const ok = await c.fetchText(`http://127.0.0.1:${s.port}/a`);
    assert.equal(ok.status, 200); assert.equal(ok.redirects, 2); assert.match(ok.text, /<title>ok/);
    const loop = await c.fetchText(`http://127.0.0.1:${s.port}/loop`);
    assert.equal(loop.status, 0); assert.match(loop.error, /Too many redirects/); assert.ok(!loop.blocked);
    const chain = await c.fetchText(`http://127.0.0.1:${s.port}/chain1`);
    assert.match(chain.error, /Too many redirects/);
    assert.ok(s.hits.length <= 3 + 6 + 6, `bounded number of requests (${s.hits.length})`);
  } finally { s.srv.close(); }
});

test('DNS rebinding / hostile DNS: private answers (also mixed with public ones) are refused; validated address is the one used', async () => {
  const s = await listen((req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(`<title>${req.headers.host}</title>`); }, '127.0.0.1');
  try {
    const lookups = { 'internal.evil.test': ['10.0.0.5'], 'mixed.evil.test': ['127.0.0.1', '10.0.0.5'], 'meta.evil.test': ['169.254.169.254'], 'v6.evil.test': ['::1'], 'mapped.evil.test': ['::ffff:10.0.0.1'], 'good.test': ['127.0.0.1'] };
    const c = client({ baseLookup: fakeLookup(lookups) });
    for (const h of ['internal.evil.test', 'mixed.evil.test', 'meta.evil.test', 'v6.evil.test', 'mapped.evil.test']) {
      const r = await c.fetchText(`http://${h}:${s.port}/`);
      assert.equal(r.status, 0, h); assert.equal(r.blocked, true, `${h}: ${r.error}`);
    }
    assert.equal(s.hits.length, 0);
    const ok = await c.fetchText(`http://good.test:${s.port}/`);
    assert.equal(ok.status, 200); assert.match(ok.text, /good\.test/); // Host header preserved, connection pinned to the validated IP
    // rebinding simulation: first answer public, second private. The client resolves ONCE per hop, so it cannot be tricked on connect.
    let calls = 0;
    const flip = (host, opts, cb) => { calls++; cb(null, [{ address: calls === 1 ? '127.0.0.1' : '10.0.0.5', family: 4 }]); };
    const c2 = client({ baseLookup: flip });
    const r2 = await c2.fetchText(`http://flip.test:${s.port}/`);
    assert.equal(r2.status, 200); assert.equal(calls, 1, 'exactly one resolution per request');
  } finally { s.srv.close(); }
});

test('only allowed ports in production policy; credentials and schemes refused', async () => {
  const c = createSafeClient({ baseLookup: fakeLookup({ 'site.test': ['93.184.216.34'] }) });
  for (const url of ['http://site.test:22/', 'http://site.test:6379/', 'https://site.test:9200/', 'http://user:pw@site.test/', 'ftp://site.test/', 'file:///etc/passwd']) {
    const r = await c.fetchText(url);
    assert.equal(r.status, 0, url); assert.equal(r.blocked, true, `${url}: ${r.error}`);
  }
});

test('limits: oversized body is truncated, slow server times out, no gzip (identity) requested, UA sent', async () => {
  const big = 'x'.repeat(3_000_000);
  const s = await listen((req, res) => {
    if (req.url === '/big') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(big); }
    if (req.url === '/slow') return; // never answers
    if (req.url === '/drip') { res.writeHead(200, { 'content-type': 'text/html' }); const t = setInterval(() => res.write('a'), 50); res.on('close', () => clearInterval(t)); return; }
    res.writeHead(200); res.end('ok');
  }, '127.0.0.1');
  try {
    const c = client();
    const b = await c.fetchText(`http://127.0.0.1:${s.port}/big`, { maxBytes: 100_000 });
    assert.equal(b.status, 200); assert.equal(b.truncated, true); assert.ok(b.text.length <= 100_000);
    const t0 = Date.now();
    const slow = await c.fetchText(`http://127.0.0.1:${s.port}/slow`, { timeoutMs: 700 });
    assert.equal(slow.status, 0); assert.match(slow.error, /timeout/); assert.ok(Date.now() - t0 < 3000);
    const t1 = Date.now();
    const drip = await c.fetchText(`http://127.0.0.1:${s.port}/drip`, { timeoutMs: 800, maxBytes: 10_000_000 });
    assert.ok(drip.status === 0 || drip.status === 200); assert.ok(Date.now() - t1 < 3500, 'total deadline enforced against slow-drip bodies');
    await c.fetchText(`http://127.0.0.1:${s.port}/ok`, { ua: 'TamisAuditBot/1.1' });
    const last = s.hits.at(-1);
    assert.equal(last.enc, 'identity'); assert.equal(last.ua, 'TamisAuditBot/1.1');
  } finally { s.srv.close(); }
});

test('connection refused and DNS failure are reported as failures, not crashes', async () => {
  const c = client({ baseLookup: fakeLookup({}) });
  const closed = await new Promise((r) => { const sv = net.createServer().listen(0, '127.0.0.1', () => { const p = sv.address().port; sv.close(() => r(p)); }); });
  assert.equal((await c.fetchText(`http://127.0.0.1:${closed}/`)).status, 0);
  const nx = await c.fetchText('http://nope.test/');
  assert.equal(nx.status, 0); assert.ok(!nx.blocked);
});
