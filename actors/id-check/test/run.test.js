import test from 'node:test';
import assert from 'node:assert/strict';
import { run, parseInput, LIMITS } from '../src/run.js';
import { toOutput, validateItem, maskValue } from '../src/core.js';
import { fakePlatform, RunAborted } from './helpers/fake-platform.js';

const quiet = { log() {} };
const IBAN_OK = 'FR1420041010050500013M02606';

test('masking: IBAN never appears in full in the output', async () => {
  const { Actor, st } = fakePlatform({ input: { items: [IBAN_OK, 'DE89 3704 0044 0532 0130 01', 'FR14 2004 1010 0505 0001 3M02 60X', 'garbage-iban-FR1420041010050500013M0'] } });
  await run(Actor, quiet);
  const blob = JSON.stringify([st.dataset, st.kv]);
  for (const full of [IBAN_OK, 'DE89370400440532013001', '20041010050500013M02606', '0532013001']) assert.ok(!blob.includes(full), `leaked ${full}`);
  assert.equal(st.dataset[0].input, 'FR14*******************2606');
  assert.equal(st.dataset[0].masked, true);
  assert.ok(st.dataset.every((r) => r.details.bban === undefined));
});
test('masking can be disabled explicitly; public identifiers are echoed', async () => {
  const { Actor, st } = fakePlatform({ input: { items: [IBAN_OK, 'FR44732829320', 'BNPAFRPP'], maskSensitive: false } });
  await run(Actor, quiet);
  assert.equal(st.dataset[0].input, IBAN_OK);
  const m = fakePlatform({ input: { items: ['FR44732829320', 'BNPAFRPP', '73282932000074'] } });
  await run(m.Actor, quiet);
  assert.deepEqual(m.st.dataset.map((r) => r.input), ['FR44732829320', 'BNPAFRPP', '73282932000074']);
  assert.ok(m.st.dataset.every((r) => r.masked === false));
});
test('maskValue edge cases', () => {
  assert.equal(maskValue('abc'), '***');
  assert.equal(maskValue('FR14 2004 1010'), 'FR14****1010');
  assert.equal(toOutput(validateItem(undefined), 0).input, null);
});

test('billing: exactly one dataset write per result, summary stays out of the dataset, no custom events', async () => {
  const items = Array.from({ length: 120 }, (_, i) => (i % 2 ? IBAN_OK : '732829320'));
  const { Actor, st } = fakePlatform({ input: { items }, price: 0.002 });
  const s = await run(Actor, quiet);
  assert.equal(st.dataset.length, 120);
  assert.equal(s.processed, 120);
  assert.equal(+st.chargedUsd.toFixed(6), 0.24);            // 120 x $0.002, no more
  assert.ok(st.dataset.every((r) => typeof r.index === 'number' && 'verdict' in r)); // nothing but results
  assert.ok(st.kv.SUMMARY && st.kv.SUMMARY.processed === 120);
  assert.equal(new Set(st.dataset.map((r) => r.index)).size, 120); // no duplicate rows => no duplicate charge
});
test('spending limit: nothing is delivered beyond what was charged, and the run stops', async () => {
  const items = Array.from({ length: 200 }, () => '732829320');
  const { Actor, st } = fakePlatform({ input: { items }, price: 0.002, maxTotalChargeUsd: 0.1 }); // 50 results affordable
  await assert.rejects(() => run(Actor, quiet), RunAborted);
  assert.equal(st.dataset.length, 50);
  assert.ok(st.chargedUsd <= 0.1 + 1e-9);
  assert.equal(st.kv.SUMMARY, undefined);                    // no "success" summary after abort
});
test('platform error while writing: fail closed (no further results, error propagates)', async () => {
  const items = Array.from({ length: 300 }, () => '732829320');
  const { Actor, st } = fakePlatform({ input: { items }, failAfterPushCalls: 2 });
  await assert.rejects(() => run(Actor, quiet), /simulated platform error/);
  assert.equal(st.dataset.length, 2 * LIMITS.batchSize);
  assert.equal((st.dataset.length * 0.002).toFixed(6), st.chargedUsd.toFixed(6));
});
test('Actor.charge is never needed or called', async () => {
  const { Actor } = fakePlatform({ input: { items: ['732829320'] } });
  assert.equal(typeof Actor.charge, 'undefined');
  await run(Actor, quiet); // would throw TypeError if run() called Actor.charge
});

test('input validation', () => {
  assert.throws(() => parseInput(null), /non-empty array/);
  assert.throws(() => parseInput({ items: [] }), /non-empty array/);
  assert.throws(() => parseInput({ items: 'FR1' }), /non-empty array/);
  assert.throws(() => parseInput({ items: ['x'], type: 'passport' }), /must be one of/);
  assert.throws(() => parseInput({ items: ['x'], maxItems: 0 }), /between 1 and/);
  assert.throws(() => parseInput({ items: ['x'], maxItems: 10 ** 9 }), /between 1 and/);
  assert.equal(parseInput({ items: ['x'], maxItems: 'abc' }).maxItems, LIMITS.defaultMaxItems);
  assert.equal(parseInput({ items: ['x'] }).maskSensitive, true);
});
test('abuse and weird items: huge strings, objects, nulls, wrong hints, maxItems cap', async () => {
  const items = ['A'.repeat(100000), { value: 'x'.repeat(500) }, null, { nope: 1 }, [1, 2], 12345, { value: IBAN_OK, type: 'passport' }, { value: IBAN_OK, type: 'iban' }, '732829320', '732829320'];
  const { Actor, st } = fakePlatform({ input: { items, maxItems: 9 } });
  const s = await run(Actor, quiet);
  assert.equal(st.dataset.length, 9);
  assert.equal(s.skippedAboveMaxItems, 1);
  assert.equal(st.dataset[0].verdict, 'BLOCK'); assert.match(st.dataset[0].reasons[0], /longer than 100/);
  assert.equal(st.dataset[6].verdict, 'BLOCK'); assert.match(st.dataset[6].reasons[0], /Unsupported type/);
  assert.equal(st.dataset[7].verdict, 'ALLOW');
  assert.ok(!JSON.stringify(st.dataset).includes('AAAAAAAAAAAAAAAA'));
});
test('same item twice produces two rows (documented: each submitted item is processed and billed)', async () => {
  const { Actor, st } = fakePlatform({ input: { items: ['732829320', '732829320'] } });
  await run(Actor, quiet);
  assert.equal(st.dataset.length, 2);
});
