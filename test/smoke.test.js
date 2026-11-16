import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';

const ROOT = new URL('..', import.meta.url).pathname;
const run = (env) => new Promise((resolve) => {
  const p = spawn('node', ['monitoring/smoke.mjs'], { env: { ...process.env, ...env }, cwd: ROOT });
  let out = ''; p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (out += d));
  p.on('close', (code) => resolve({ code, out }));
});
const ITEMS = {
  'eu-payment-id-validator': [{ verdict: 'ALLOW', input: 'FR14*******************2606' }, { verdict: 'BLOCK', input: 'DE89**************3001' }],
  'ai-search-readiness-audit': [{ status: 'audited', score: 80 }],
  'email-auth-audit': [{ status: 'audited', score: 55 }],
};
// Fake Apify API. `behaviour(actor)` customises one actor: { status, counts, httpStart, polls }
function api(behaviour = () => ({})) {
  const seen = { auth: [], starts: [] }, runs = {};
  const srv = http.createServer((req, res) => {
    seen.auth.push(req.headers.authorization);
    const send = (code, body) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
    let body = ''; req.on('data', (c) => (body += c)); req.on('end', () => {
      const u = new URL(req.url, 'http://x');
      let m;
      if ((m = u.pathname.match(/^\/v2\/acts\/([^/]+)\/runs$/)) && req.method === 'POST') {
        const [user, actor] = decodeURIComponent(m[1]).split('~'); const b = behaviour(actor);
        seen.starts.push({ user, actor, input: JSON.parse(body) });
        if (b.httpStart) return send(b.httpStart, {});
        runs[actor] = { id: `run-${actor}`, polls: b.polls ?? 0 };
        return send(201, { data: { id: `run-${actor}`, status: b.polls ? 'RUNNING' : (b.status || 'SUCCEEDED'), defaultDatasetId: `ds-${actor}`, chargedEventCounts: b.counts ?? { 'apify-actor-start': 1, 'apify-default-dataset-item': 2 } } });
      }
      if ((m = u.pathname.match(/^\/v2\/actor-runs\/run-(.+)$/))) {
        const actor = m[1], r = runs[actor], b = behaviour(actor); r.polls--;
        return send(200, { data: { id: r.id, status: r.polls > 0 ? 'RUNNING' : (b.status || 'SUCCEEDED'), defaultDatasetId: `ds-${actor}`, chargedEventCounts: b.counts ?? {} } });
      }
      if ((m = u.pathname.match(/^\/v2\/datasets\/ds-(.+)\/items$/))) return send(200, ITEMS[m[1]]);
      send(404, {});
    });
  });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r({ srv, seen, url: `http://127.0.0.1:${srv.address().port}` })));
}
const env = (url, extra = {}) => ({ APIFY_API_BASE: url, APIFY_TOKEN: 'SECRET-TOKEN-123', APIFY_USERNAME: 'tamis', ...extra });

test('smoke: all checks pass => exit 0; Bearer auth; user~actor path', async () => {
  const a = await api();
  try {
    const r = await run(env(a.url));
    assert.equal(r.code, 0, r.out);
    assert.equal(a.seen.starts.length, 3);
    assert.ok(a.seen.starts.every((s) => s.user === 'tamis'));
    assert.ok(a.seen.auth.every((x) => x === 'Bearer SECRET-TOKEN-123'));
    assert.ok(!r.out.includes('SECRET-TOKEN-123'), 'token must never be printed');
  } finally { a.srv.close(); }
});
test('smoke: long runs are polled until they finish', async () => {
  const a = await api((actor) => (actor === 'email-auth-audit' ? { polls: 2 } : {}));
  try { assert.equal((await run(env(a.url))).code, 0); } finally { a.srv.close(); }
});
test('smoke: failed run, HTTP error, wrong output => exit 1 with precise messages', async () => {
  const a = await api((actor) => ({ 'eu-payment-id-validator': { status: 'FAILED' }, 'email-auth-audit': { httpStart: 500 } }[actor] || {}));
  try {
    const r = await run(env(a.url));
    assert.equal(r.code, 1);
    assert.match(r.out, /FAIL  eu-payment-id-validator  run status FAILED/);
    assert.match(r.out, /FAIL  email-auth-audit  start HTTP 500/);
    assert.match(r.out, /PASS  ai-search-readiness-audit/);
  } finally { a.srv.close(); }
});
test('smoke: DOUBLE BILLING detected (custom event next to the default dataset item event)', async () => {
  const a = await api((actor) => (actor === 'ai-search-readiness-audit' ? { counts: { 'apify-actor-start': 1, 'url-audited': 1, 'apify-default-dataset-item': 1 } } : {}));
  try {
    const r = await run(env(a.url));
    assert.equal(r.code, 1);
    assert.match(r.out, /FAIL  ai-search-readiness-audit  DOUBLE BILLING/);
  } finally { a.srv.close(); }
});
test('smoke: missing or malformed configuration => exit 2', async () => {
  assert.equal((await run({ APIFY_TOKEN: '', APIFY_USERNAME: '' })).code, 2);
  assert.equal((await run({ APIFY_TOKEN: 't', APIFY_USERNAME: 'bad/user' })).code, 2);
});
