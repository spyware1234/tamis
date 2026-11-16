import dns from 'node:dns/promises';
import { Actor } from 'apify';
import { run } from './run.js';

const resolver = new dns.Resolver({ timeout: 4000, tries: 2 });

await Actor.init();
try {
  await run(Actor, { resolver });
  await Actor.exit();
} catch (err) {
  console.error(`Run failed: ${err?.message ?? err}`);
  await Actor.fail(String(err?.message ?? err).slice(0, 300));
}
