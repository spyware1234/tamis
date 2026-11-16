// Heuristic 0-100 readiness score. It measures technical hygiene for AI/search retrieval; it does NOT predict rankings or citations.
export function scorePage({ signals: s, bots, xRobotsTag = '', hasSitemap, hasLlmsTxt }) {
  const breakdown = [], issues = [];
  const add = (key, max, got, issue) => { breakdown.push({ key, max, points: got }); if (got < max && issue) issues.push(issue); };
  const noindex = s.noindex || /\bnoindex\b|\bnone\b/i.test(xRobotsTag);

  add('indexable', 15, noindex ? 0 : 15, { severity: 'high', code: 'NOINDEX', message: 'Page is marked noindex (meta robots or X-Robots-Tag).', fix: 'Remove noindex if this page should appear in search and AI answers.' });

  const scored = bots.filter((b) => b.scored);
  const blocked = scored.filter((b) => !b.allowed);
  scored.forEach((b) => add(`bot:${b.bot}`, 5, b.allowed ? 5 : 0, { severity: 'high', code: 'BOT_BLOCKED', message: `${b.bot} is blocked by robots.txt (${b.rule}).`, fix: `Allow ${b.bot} in robots.txt if you want to be retrievable and citable by it.` }));
  if (blocked.length > 1) issues.splice(issues.findIndex((i) => i.code === 'BOT_BLOCKED'), 0, { severity: 'high', code: 'MULTI_BOT_BLOCKED', message: `${blocked.length} search/answer crawlers are blocked.`, fix: 'Review robots.txt: a blanket "Disallow: /" for "*" blocks every crawler without a specific group.' });

  const tl = s.title?.length ?? 0;
  add('title', 8, tl >= 10 && tl <= 70 ? 8 : tl > 0 ? 4 : 0, { severity: tl ? 'low' : 'high', code: tl ? 'TITLE_LENGTH' : 'NO_TITLE', message: tl ? `Title length is ${tl} characters (10-70 recommended).` : 'No <title> found.', fix: 'Write a specific title of 10-70 characters.' });
  const dl = s.description?.length ?? 0;
  add('description', 7, dl >= 50 && dl <= 170 ? 7 : dl > 0 ? 3 : 0, { severity: 'medium', code: dl ? 'DESC_LENGTH' : 'NO_DESCRIPTION', message: dl ? `Meta description is ${dl} characters (50-170 recommended).` : 'No meta description.', fix: 'Add a 50-170 character summary that states what the page answers.' });
  add('canonical', 5, s.canonical ? 5 : 0, { severity: 'medium', code: 'NO_CANONICAL', message: 'No canonical link.', fix: 'Add <link rel="canonical"> to avoid duplicate-URL ambiguity.' });
  add('lang', 3, s.lang ? 3 : 0, { severity: 'low', code: 'NO_LANG', message: 'No lang attribute on <html>.', fix: 'Set <html lang="..."> so language is unambiguous.' });
  add('h1', 7, s.h1Count === 1 ? 7 : s.h1Count > 1 ? 3 : 0, { severity: 'medium', code: s.h1Count ? 'MULTI_H1' : 'NO_H1', message: s.h1Count ? `${s.h1Count} <h1> elements found (1 expected).` : 'No <h1>.', fix: 'Use exactly one <h1> stating the page topic.' });
  const ok = s.jsonLd.blocks > 0 && s.jsonLd.types.length > 0;
  add('structuredData', 10, ok ? 10 : 0, { severity: 'medium', code: s.jsonLd.invalid ? 'JSONLD_INVALID' : 'NO_JSONLD', message: s.jsonLd.invalid ? `${s.jsonLd.invalid} JSON-LD block(s) fail to parse.` : 'No schema.org JSON-LD with an @type found.', fix: 'Add valid JSON-LD (e.g. Article, Product, FAQPage, Organization) matching the visible content.' });
  add('content', 8, s.wordCount >= 300 ? 8 : s.wordCount >= 150 ? 4 : 0, { severity: 'medium', code: 'THIN_CONTENT', message: `Only ${s.wordCount} words of server-rendered text. Content added by JavaScript is not seen by this audit.`, fix: 'Ensure the main content is present in the initial HTML and substantive.' });
  add('sitemap', 5, hasSitemap ? 5 : 0, { severity: 'low', code: 'NO_SITEMAP', message: 'No sitemap found (robots.txt Sitemap line or /sitemap.xml).', fix: 'Publish a sitemap.xml and reference it in robots.txt.' });
  const altRatio = s.imageCount ? s.imagesWithAlt / s.imageCount : 1;
  add('imageAlt', 7, altRatio >= 0.9 ? 7 : altRatio >= 0.6 ? 3 : 0, { severity: 'low', code: 'IMG_ALT', message: `Only ${Math.round(altRatio * 100)}% of images have alt text.`, fix: 'Add descriptive alt text to meaningful images.' });

  const score = breakdown.reduce((a, b) => a + b.points, 0);
  const grade = score >= 85 ? 'A' : score >= 70 ? 'B' : score >= 55 ? 'C' : score >= 40 ? 'D' : 'F';
  const order = { high: 0, medium: 1, low: 2 };
  issues.sort((a, b) => order[a.severity] - order[b.severity]);
  const info = [];
  if (!hasLlmsTxt) info.push('No /llms.txt found. It is optional and not scored: support by major engines is unconfirmed.');
  return { score, grade, breakdown, issues, info };
}
