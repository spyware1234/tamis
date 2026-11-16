import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCsv, parseCsvLine, summarize, killCheck } from '../tools/finance.mjs';

const CSV = `date,actor,gross_usd,platform_cost_usd,notes
# comment line
2026-12-01,id-check,2.00,0.10,"first, paying user"
2026-12-15,email-auth,1.00,0.05,
2027-01-03,id-check,0.20,,"say ""hi"""`;

test('csv: quotes, commas in notes, blanks, comments', () => {
  assert.deepEqual(parseCsvLine('a,"b,c","d ""e""",f'), ['a', 'b,c', 'd "e"', 'f']);
  const rows = parseCsv(CSV);
  assert.equal(rows.length, 3);
  assert.equal(rows[0].notes, 'first, paying user');
  assert.equal(rows[2].platform_cost_usd, 0);
});
test('csv validation reports the faulty line', () => {
  assert.throws(() => parseCsv('date,gross_usd,platform_cost_usd\n2026-13-45,1,0'), /Line 2: invalid date/);
  assert.throws(() => parseCsv('date,gross_usd,platform_cost_usd\n2026-12-01,abc,0'), /Line 2.*gross_usd/);
  assert.throws(() => parseCsv('date,gross_usd,platform_cost_usd\n2026-12-01,-1,0'), />= 0/);
  assert.throws(() => parseCsv('date,actor\n2026-12-01,x'), /Missing column/);
  assert.deepEqual(parseCsv('# only comments'), []);
});
test('monthly profit = 0.8 x gross - platform cost (Apify formula)', () => {
  const s = summarize(parseCsv(CSV));
  assert.deepEqual(s, [{ month: '2026-12', gross: 3, cost: 0.15, profit: 2.25 }, { month: '2027-01', gross: 0.2, cost: 0, profit: 0.16 }]);
});
test('kill criteria', () => {
  const rows = parseCsv(CSV);
  assert.equal(killCheck({ rows, launch: '2026-12-01', today: '2027-01-15', users: 3 }).status, 'TOO_EARLY');
  assert.equal(killCheck({ rows, launch: '2026-11-01', today: '2027-01-15', users: 3 }).status, 'STOP_OR_PIVOT');
  assert.equal(killCheck({ rows, launch: '2026-11-01', today: '2027-01-15', users: 80 }).status, 'CONTINUE');
  assert.throws(() => killCheck({ rows, launch: '2026-11-01', today: '2027-01-15', users: NaN }), /--users/);
  assert.throws(() => killCheck({ rows, launch: 'nope', today: '2027-01-15', users: 1 }), /Invalid/);
});
