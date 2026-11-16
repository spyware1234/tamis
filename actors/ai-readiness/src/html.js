// Linear-time HTML signal extractor. No backtracking regexes over the whole document: a hostile 1.5 MB page
// (thousands of unclosed tags, '<' floods, unterminated scripts) is processed in a single pass.
const MAX_HTML = 1_500_000, MAX_TAG = 4000, MAX_JSONLD = 500_000;
const decode = (s) => s.replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>');
const SKIP = new Set(['script', 'style', 'noscript', 'template', 'svg']);

function attrs(tag) {
  const out = {};
  const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/g;
  let m, n = 0;
  while ((m = re.exec(tag)) && n++ < 60) out[m[1].toLowerCase()] = decode(m[2] ?? m[3] ?? m[4] ?? '');
  return out;
}

export function extractSignals(htmlIn = '') {
  const html = String(htmlIn).slice(0, MAX_HTML);
  const lower = html.toLowerCase();
  const gts = [];
  for (let k = html.indexOf('>'); k !== -1; k = html.indexOf('>', k + 1)) gts.push(k);
  let p = 0, i = 0, words = 0, h1 = 0, h2 = 0, title = null, lang = null;
  const metas = [], links = [], imgs = [], types = new Set();
  let ldBlocks = 0, ldInvalid = 0;
  const walk = (n, depth = 0) => {
    if (depth > 20) return;
    if (Array.isArray(n)) return n.slice(0, 200).forEach((x) => walk(x, depth + 1));
    if (n && typeof n === 'object') {
      const t = n['@type'];
      if (typeof t === 'string') types.add(t.slice(0, 60)); else if (Array.isArray(t)) t.slice(0, 10).forEach((x) => types.add(String(x).slice(0, 60)));
      for (const v of Object.values(n).slice(0, 200)) walk(v, depth + 1);
    }
  };
  const addText = (s) => { if (s) words += s.split(/\s+/).filter(Boolean).length; };

  while (i < html.length) {
    const lt = html.indexOf('<', i);
    if (lt === -1) { addText(html.slice(i)); break; }
    addText(html.slice(i, lt));
    if (html.startsWith('<!--', lt)) { const e = html.indexOf('-->', lt + 4); if (e === -1) break; i = e + 3; continue; }
    while (p < gts.length && gts[p] <= lt) p++;
    if (p >= gts.length) { addText(html.slice(lt)); break; }          // no '>' left: the rest is plain text
    const gt = gts[p];
    if (gt - lt > MAX_TAG) { i = lt + 1; continue; }                  // too long to be a tag: treat '<' as text
    const raw = html.slice(lt, gt + 1);
    const m = /^<(\/?)([a-zA-Z][a-zA-Z0-9:-]*)/.exec(raw);
    if (!m) { i = gt + 1; continue; }
    const closing = m[1] === '/', name = m[2].toLowerCase();
    i = gt + 1;
    if (closing) continue;
    if (name === 'meta') metas.push(attrs(raw));
    else if (name === 'link') links.push(attrs(raw));
    else if (name === 'img') { if (imgs.length < 5000) imgs.push(attrs(raw)); }
    else if (name === 'h1') h1++;
    else if (name === 'h2') h2++;
    else if (name === 'html' && lang === null) lang = attrs(raw).lang?.match(/^[A-Za-z-]{2,20}/)?.[0] ?? null;
    else if (name === 'title' && title === null) {
      const e = lower.indexOf('</title', i);
      if (e !== -1) { title = decode(html.slice(i, Math.min(e, i + 600))).replace(/\s+/g, ' ').trim().slice(0, 300); i = e; }
    }
    if (SKIP.has(name)) {
      const e = lower.indexOf(`</${name}`, i);
      if (e === -1) break;                                            // unterminated block: ignore the rest
      if (name === 'script' && /application\/ld\+json/i.test(raw) && ldBlocks < 20) {
        ldBlocks++;
        const body = html.slice(i, Math.min(e, i + MAX_JSONLD)).trim();
        try { walk(JSON.parse(body)); } catch { ldInvalid++; }
      }
      i = e;
    }
  }
  const meta = (name) => metas.find((a) => (a.name || '').toLowerCase() === name)?.content;
  const robotsMeta = [meta('robots'), meta('googlebot')].filter(Boolean).join(',').toLowerCase().slice(0, 200);
  return {
    title,
    description: meta('description')?.trim().slice(0, 500) || null,
    canonical: links.find((a) => (a.rel || '').toLowerCase().split(/\s+/).includes('canonical'))?.href?.slice(0, 500) || null,
    lang, h1Count: h1, h2Count: h2, wordCount: words,
    jsonLd: { blocks: ldBlocks, invalid: ldInvalid, types: [...types].slice(0, 30) },
    ogTitle: !!metas.find((a) => a.property === 'og:title'),
    metaRobots: robotsMeta || null,
    noindex: /\bnoindex\b|\bnone\b/.test(robotsMeta),
    imageCount: imgs.length,
    imagesWithAlt: imgs.filter((a) => 'alt' in a && a.alt.trim() !== '').length,
  };
}
