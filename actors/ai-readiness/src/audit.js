import { parseRobots, isAllowed, analyzeBots } from './robots.js';
import { extractSignals } from './html.js';
import { scorePage } from './score.js';
import { createSafeClient } from './safe-http.js';

export const UA_TOKEN = 'TamisAuditBot';
export const UA = `${UA_TOKEN}/1.1`;
const OBVIOUS_LOCAL = /(^|\.)(localhost|local|internal|localdomain|lan|home\.arpa|intranet)\.?$/i;

export function normalizeUrl(raw) {
  let s = String(raw ?? '').trim();
  if (!s) throw new Error('Empty URL');
  if (s.length > 2048) throw new Error('URL too long');
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) && !/^https?:\/\//i.test(s)) throw new Error('Only http(s) URLs are supported');
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  const u = new URL(s);
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only http(s) URLs are supported');
  u.hash = '';
  return u;
}

// Statuses that cost us real work (a network fetch of the target was attempted) are billable; the rest are not.
export const isBillable = (r) => r.ok === true || r.status === 'fetch-failed' || r.status === 'not-html' || /^http-\d{3}$/.test(r.status);

export async function loadOriginInfo(origin, client) {
  const r = await client.fetchText(`${origin}/robots.txt`, { ua: UA, timeoutMs: 6000, maxBytes: 500_000 });
  const robots = r.status === 200 ? parseRobots(r.text) : null;
  const sameHost = (robots?.sitemaps || []).find((x) => { try { return new URL(x).host === new URL(origin).host; } catch { return false; } });
  const sitemapUrl = sameHost || `${origin}/sitemap.xml`; // a robots.txt cannot make us probe another host
  const [sm, llms] = await Promise.all([client.probe(sitemapUrl, { ua: UA, timeoutMs: 6000 }), client.probe(`${origin}/llms.txt`, { ua: UA, timeoutMs: 6000 })]);
  return { robots, robotsBlocked: r.blocked === true, hasSitemap: sm === 200, hasLlmsTxt: llms === 200 };
}

export async function auditUrl(raw, { respectRobots = true, originCache = new Map(), client = createSafeClient() } = {}) {
  const checkedAt = new Date().toISOString();
  let u;
  try { u = normalizeUrl(raw); } catch (e) { return { url: String(raw).slice(0, 200), ok: false, status: 'invalid-url', error: e.message, checkedAt }; }
  if (OBVIOUS_LOCAL.test(u.hostname)) return { url: u.href, ok: false, status: 'blocked-address', error: 'Local host names are not audited.', checkedAt };

  const origin = u.origin;
  if (!originCache.has(origin)) originCache.set(origin, loadOriginInfo(origin, client));
  const info = await originCache.get(origin);
  const bots = analyzeBots(info.robots, u.pathname);

  if (respectRobots && info.robots && !isAllowed(info.robots, UA_TOKEN, u.pathname + u.search).allowed) {
    return { url: u.href, ok: false, status: 'blocked-by-robots', error: `robots.txt disallows ${UA_TOKEN} for this path; page not fetched.`, aiCrawlers: bots, checkedAt };
  }

  const page = await client.fetchText(u.href, { ua: UA });
  if (page.status === 0) {
    if (page.blocked) return { url: u.href, ok: false, status: 'blocked-address', error: page.error, checkedAt };
    return { url: u.href, ok: false, status: 'fetch-failed', error: page.error, aiCrawlers: bots, checkedAt };
  }
  if (page.status >= 400) return { url: u.href, ok: false, status: `http-${page.status}`, httpStatus: page.status, aiCrawlers: bots, checkedAt };
  if (page.contentType && !/html|xml/i.test(page.contentType)) return { url: u.href, ok: false, status: 'not-html', httpStatus: page.status, error: `Content-Type ${page.contentType.slice(0, 60)}`, checkedAt };

  const signals = extractSignals(page.text);
  const scored = scorePage({ signals, bots, xRobotsTag: page.xRobotsTag, hasSitemap: info.hasSitemap, hasLlmsTxt: info.hasLlmsTxt });
  return {
    url: u.href, finalUrl: page.url, ok: true, status: 'audited', httpStatus: page.status, redirects: page.redirects,
    score: scored.score, grade: scored.grade, issues: scored.issues, info: scored.info,
    aiCrawlers: bots, signals, hasSitemap: info.hasSitemap, hasLlmsTxt: info.hasLlmsTxt, breakdown: scored.breakdown,
    truncated: page.truncated, checkedAt,
  };
}
