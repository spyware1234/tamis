import { validateItem, toOutput } from './core.js';

export const LIMITS = { maxItemsCap: 100000, defaultMaxItems: 5000, batchSize: 50 };
const TYPES = new Set(['auto', 'iban', 'bic', 'siren', 'siret', 'vat']);

export function parseInput(raw) {
  const input = raw && typeof raw === 'object' ? raw : {};
  const { items, type = 'auto', maxItems = LIMITS.defaultMaxItems, maskSensitive = true } = input;
  if (!Array.isArray(items) || items.length === 0) throw new Error('Input "items" must be a non-empty array.');
  if (!TYPES.has(type)) throw new Error(`Input "type" must be one of: ${[...TYPES].join(', ')}.`);
  const max = Number.isInteger(maxItems) ? maxItems : LIMITS.defaultMaxItems;
  if (max < 1 || max > LIMITS.maxItemsCap) throw new Error(`Input "maxItems" must be between 1 and ${LIMITS.maxItemsCap}.`);
  if (items.length > LIMITS.maxItemsCap * 2) throw new Error('Too many items in one run.');
  return { items, type, maxItems: max, maskSensitive: maskSensitive !== false };
}

/**
 * BILLING MODEL (see docs): the ONLY billable event is Apify's synthetic `apify-default-dataset-item`.
 * Every record written to the default dataset is charged once by the platform, atomically with the write.
 * This code therefore (1) never calls Actor.charge(), (2) writes nothing else to the default dataset.
 * Anything that must stay free (the summary) goes to the key-value store.
 * If a dataset write fails, the error propagates: the run fails and no further result is produced.
 */
export async function run(Actor, log = console) {
  const { items, type, maxItems, maskSensitive } = parseInput(await Actor.getInput());
  const list = items.slice(0, maxItems);
  const counts = { ALLOW: 0, REVIEW: 0, BLOCK: 0 };
  let batch = [], processed = 0;
  const flush = async () => { if (batch.length) { const b = batch; batch = []; await Actor.pushData(b); } };
  for (let i = 0; i < list.length; i++) {
    const out = toOutput(validateItem(list[i], type), i, { maskSensitive });
    counts[out.verdict]++; processed++;
    batch.push(out);
    if (batch.length >= LIMITS.batchSize) await flush();
  }
  await flush();
  const summary = {
    verdict: counts.BLOCK ? 'BLOCK' : counts.REVIEW ? 'REVIEW' : 'ALLOW',
    processed, ...counts, skippedAboveMaxItems: items.length - list.length, masked: maskSensitive,
  };
  await Actor.setValue('SUMMARY', summary);
  log.log(`Done: ${processed} checked, ALLOW ${counts.ALLOW}, REVIEW ${counts.REVIEW}, BLOCK ${counts.BLOCK}`);
  return summary;
}
