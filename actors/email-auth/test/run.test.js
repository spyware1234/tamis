import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { run, parseInput, LIMITS } from '../src/run.js';
import { fakePlatform, RunAborted } from './helpers/fake-platform.js';

const quiet = { log() {} };
const K = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const zoneFor = (d) => ({ mx: { [d]: [{ exchange: `mx.${d}`, priority: 10 }] }, txt: { [d]: ['v=spf1 -all'], [`_dmarc.${d}`]: ['v=DMARC1; p=reject; rua=mailto:r@x.test'], [`google._domainkey.${d}`]: [`v=DKIM1; p=${K}`] } });
function resolverFor(domains, { failFor = [] } = {}) {
  const miss = () => Object.assign(new Error('nx'), { code: 'ENOTFOUND' });
  const zones = domains.map(zoneFor);
  const txt = Object.assign({}, ...zones.map((z) => z.txt)), mx = Object.assign({}, ...zones.map((z) => z.mx));
  const guard = (n) => { if (failFor.some((d) => n === d || n.endsWith(`.${d}`))) throw Object.assign(new Error('timeout'), { code: 'ETIMEOUT' }); };
  return { resolveTxt: async (n) => { guard(n); if (!txt[n]) throw miss(); return txt[n].map((x) => [x]); }, resolveMx: async (n) => { guard(n); if (!mx[n]) throw miss(); return mx[n]; } };
}

test('input validation', () => {
  assert.throws(() => parseInput({}), /non-empty array/);
  assert.throws(() => parseInput({ domains: [] }), /non-empty array/);
  assert.throws(() => parseInput({ domains: ['a.com'], maxDomains: 0 }), /between 1 and/);
  assert.throws(() => parseInput({ domains: ['a.com'], maxDomains: 99999 }), /between 1 and/);
  assert.ok(parseInput({ domains: ['a.com'], dkimSelectors: ['mine', 'bad sel'] }).selectors.includes('mine'));
  assert.ok(!parseInput({ domains: ['a.com'], dkimSelectors: ['bad sel'] }).selectors.includes('bad sel'));
});

test('billing: one dataset write per audited domain; invalid, non-existent, failing and duplicate inputs are free', async () => {
  const good = ['good1.test', 'good2.test', 'good3.test'];
  const input = { domains: [...good, 'GOOD1.test', 'https://good2.test/path', 'nope.test', '127.0.0.1', 'localhost', 'bad domain', '', null, 'down.test'] };
  const { Actor, st } = fakePlatform({ input, price: 0.01 });
  const sum = await run(Actor, { resolver: resolverFor([...good, 'down.test'], { failFor: ['down.test'] }), log: quiet });
  assert.equal(st.dataset.length, 3);
  assert.equal(sum.audited, 3);
  assert.equal(+st.chargedUsd.toFixed(4), 0.03);
  assert.deepEqual(st.dataset.map((r) => r.domain).sort(), good);
  const rej = st.kv.REJECTED.map((r) => r.status).sort();
  assert.deepEqual(rej, ['dns-error', 'domain-not-found', 'duplicate', 'duplicate', 'invalid-domain', 'invalid-domain', 'invalid-domain', 'invalid-domain', 'invalid-domain'].sort());
  assert.ok(st.dataset.every((r) => r.score === 100 || typeof r.score === 'number'));
});

test('spending limit and platform failure: results are never delivered without being charged', async () => {
  const doms = Array.from({ length: 10 }, (_, i) => `d${i}.test`);
  const lim = fakePlatform({ input: { domains: doms }, price: 0.01, maxTotalChargeUsd: 0.04 });
  await assert.rejects(() => run(lim.Actor, { resolver: resolverFor(doms), log: quiet, concurrency: 1 }), RunAborted);
  assert.equal(lim.st.dataset.length, 4);
  assert.ok(lim.st.chargedUsd <= 0.04 + 1e-9);
  const fail = fakePlatform({ input: { domains: doms }, failAfterPushCalls: 3 });
  await assert.rejects(() => run(fail.Actor, { resolver: resolverFor(doms), log: quiet, concurrency: 1 }), /simulated platform error/);
  assert.equal(fail.st.dataset.length, 3);
});

test('caps, concurrency and no double rows', async () => {
  const doms = Array.from({ length: 12 }, (_, i) => `c${i}.test`);
  const { Actor, st } = fakePlatform({ input: { domains: doms, maxDomains: 7 } });
  await run(Actor, { resolver: resolverFor(doms), log: quiet });
  assert.equal(st.dataset.length, 7);
  assert.equal(new Set(st.dataset.map((r) => r.domain)).size, 7);
  assert.equal(st.kv.REJECTED.filter((r) => r.status === 'skipped-over-max-domains').length, 5);
  assert.equal(st.kv.SUMMARY.audited, 7);
});

test('Actor.charge is never needed or called', async () => {
  const { Actor } = fakePlatform({ input: { domains: ['g.test'] } });
  assert.equal(typeof Actor.charge, 'undefined');
  await run(Actor, { resolver: resolverFor(['g.test']), log: quiet });
});
