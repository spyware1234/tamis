// Usage: node tools/finance.mjs revenue.csv [--launch 2026-12-01 --users 12 --today 2027-01-30]
// CSV columns: date,actor,gross_usd,platform_cost_usd,notes     (one line per day or week; see docs)
// gross_usd = what users on PAID Apify plans were charged (Apify excludes free-plan users from your revenue).
// Profit follows Apify's documented formula: 0.8 x revenue - platform costs.
import fs from 'node:fs';

export function parseCsvLine(line) {
  const out = []; let cur = '', q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') q = false; else cur += c; }
    else if (c === '"') q = true; else if (c === ',') { out.push(cur); cur = ''; } else cur += c;
  }
  out.push(cur);
  return out.map((x) => x.trim());
}

export function parseCsv(text) {
  const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/).map((l, i) => ({ l, n: i + 1 })).filter(({ l }) => l.trim() && !l.trim().startsWith('#'));
  if (!lines.length) return [];
  const cols = parseCsvLine(lines[0].l).map((c) => c.toLowerCase());
  for (const need of ['date', 'gross_usd', 'platform_cost_usd']) if (!cols.includes(need)) throw new Error(`Missing column "${need}"`);
  return lines.slice(1).map(({ l, n }) => {
    const v = parseCsvLine(l), row = Object.fromEntries(cols.map((c, i) => [c, v[i] ?? '']));
    if (!/^\d{4}-\d{2}-\d{2}$/.test(row.date) || Number.isNaN(Date.parse(row.date))) throw new Error(`Line ${n}: invalid date "${row.date}" (use YYYY-MM-DD)`);
    for (const k of ['gross_usd', 'platform_cost_usd']) {
      const x = row[k] === '' ? 0 : Number(row[k]);
      if (!Number.isFinite(x) || x < 0) throw new Error(`Line ${n}: "${k}" must be a number >= 0`);
      row[k] = x;
    }
    return row;
  });
}

const round = (x) => Math.round(x * 100) / 100;
export function summarize(rows) {
  const by = {};
  for (const r of rows) {
    const b = (by[r.date.slice(0, 7)] ??= { month: r.date.slice(0, 7), gross: 0, cost: 0 });
    b.gross += r.gross_usd; b.cost += r.platform_cost_usd;
  }
  return Object.values(by).sort((a, b) => a.month.localeCompare(b.month))
    .map((b) => ({ month: b.month, gross: round(b.gross), cost: round(b.cost), profit: round(0.8 * b.gross - b.cost) }));
}

// Kill criteria (docs/FINANCES): 60 days after launch, fewer than 50 external users AND less than 10 USD gross => stop or pivot.
export function killCheck({ rows, launch, today, users }) {
  const days = Math.floor((new Date(today) - new Date(launch)) / 86400000);
  const gross = round(rows.reduce((a, r) => a + r.gross_usd, 0));
  if (!Number.isFinite(days)) throw new Error('Invalid --launch or --today date');
  if (days < 60) return { days, gross, status: 'TOO_EARLY', message: `Day ${days}/60: keep publishing and promoting.` };
  if (!Number.isFinite(users)) throw new Error('Pass --users N (distinct external users, see Apify Insights)');
  const fail = users < 50 && gross < 10;
  return { days, gross, users, status: fail ? 'STOP_OR_PIVOT' : 'CONTINUE', message: fail ? 'Criteria met: stop or pivot.' : 'Criteria not met: continue.' };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [file, ...rest] = process.argv.slice(2);
  const arg = (k, d) => { const i = rest.indexOf(`--${k}`); return i >= 0 ? rest[i + 1] : d; };
  try {
    const rows = parseCsv(fs.readFileSync(file, 'utf8'));
    console.table(summarize(rows));
    if (arg('launch')) console.log(killCheck({ rows, launch: arg('launch'), today: arg('today', new Date().toISOString().slice(0, 10)), users: arg('users') === undefined ? NaN : Number(arg('users')) }));
  } catch (e) { console.error(`Error: ${e.message}`); process.exit(1); }
}
