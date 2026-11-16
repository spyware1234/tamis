// Minimal robots.txt parser following the common (Google-style) matching rules:
// most specific (longest) pattern wins, Allow wins ties, '*' and '$' wildcards, groups merged per agent.
const MAX_RULES = 5000, MAX_PATTERN = 512, MAX_STARS = 6; // bound the work a hostile robots.txt can cause
export function parseRobots(text = '') {
  text = String(text).slice(0, 600_000);
  const groups = [], sitemaps = [];
  let ruleCount = 0;
  let cur = null, lastWasAgent = false;
  for (let line of String(text).split(/\r?\n/)) {
    line = line.replace(/#.*$/, '').trim();
    if (!line) continue;
    const i = line.indexOf(':');
    if (i < 0) continue;
    const key = line.slice(0, i).trim().toLowerCase();
    const val = line.slice(i + 1).trim();
    if (key === 'user-agent') {
      if (!cur || !lastWasAgent) { cur = { agents: [], rules: [] }; groups.push(cur); }
      cur.agents.push(val.toLowerCase());
      lastWasAgent = true;
    } else if (key === 'allow' || key === 'disallow') {
      if (cur && ruleCount < MAX_RULES && val.length <= MAX_PATTERN && (val.match(/\*/g) || []).length <= MAX_STARS) { cur.rules.push({ allow: key === 'allow', path: val }); ruleCount++; }
      lastWasAgent = false;
    } else if (key === 'sitemap') {
      if (val && sitemaps.length < 20) sitemaps.push(val.slice(0, 500));
    } else lastWasAgent = false;
  }
  return { groups, sitemaps };
}

function patternToRegex(p) {
  const anchored = p.endsWith('$');
  const body = (anchored ? p.slice(0, -1) : p).split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*');
  return new RegExp('^' + body + (anchored ? '$' : ''));
}

export function isAllowed(robots, agent, path = '/') {
  const a = agent.toLowerCase();
  let groups = robots.groups.filter((g) => g.agents.includes(a));
  if (!groups.length) groups = robots.groups.filter((g) => g.agents.includes('*'));
  let best = null;
  for (const g of groups) {
    for (const r of g.rules) {
      if (r.path === '') continue; // empty Disallow = allow all; empty Allow = no-op
      if (!patternToRegex(r.path).test(path)) continue;
      if (!best || r.path.length > best.path.length || (r.path.length === best.path.length && r.allow && !best.allow)) best = r;
    }
  }
  return { allowed: best ? best.allow : true, rule: best ? `${best.allow ? 'Allow' : 'Disallow'}: ${best.path}` : null, groupMatched: groups.length > 0 };
}

// role: search = used to find/cite pages in answers; user = fetches on behalf of a person; training = model training / data collection.
// Classification is a simplification — verify against each vendor's current documentation.
export const AI_BOTS = [
  { bot: 'Googlebot', role: 'search', scored: true },
  { bot: 'Bingbot', role: 'search', scored: true },
  { bot: 'OAI-SearchBot', role: 'search', scored: true },
  { bot: 'Claude-SearchBot', role: 'search', scored: true },
  { bot: 'PerplexityBot', role: 'search', scored: true },
  { bot: 'ChatGPT-User', role: 'user', scored: false },
  { bot: 'Claude-User', role: 'user', scored: false },
  { bot: 'Perplexity-User', role: 'user', scored: false },
  { bot: 'GPTBot', role: 'training', scored: false },
  { bot: 'ClaudeBot', role: 'training', scored: false },
  { bot: 'Google-Extended', role: 'training', scored: false },
  { bot: 'Applebot-Extended', role: 'training', scored: false },
  { bot: 'CCBot', role: 'training', scored: false },
  { bot: 'Bytespider', role: 'training', scored: false },
  { bot: 'meta-externalagent', role: 'training', scored: false },
];

export function analyzeBots(robots, path = '/') {
  return AI_BOTS.map(({ bot, role, scored }) => {
    const d = robots ? isAllowed(robots, bot, path) : { allowed: true, rule: null, groupMatched: false };
    return { bot, role, scored, allowed: d.allowed, rule: d.rule };
  });
}
