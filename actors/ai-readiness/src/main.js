import { Actor } from 'apify';
import { run } from './run.js';

await Actor.init();
try {
  await run(Actor);
  await Actor.exit();
} catch (err) {
  console.error(`Run failed: ${err?.message ?? err}`);
  await Actor.fail(String(err?.message ?? err).slice(0, 300));
}
