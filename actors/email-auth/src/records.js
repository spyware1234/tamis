export const joinTxt = (rec) => (Array.isArray(rec) ? rec.join('') : String(rec));

export function parseSpf(txt) {
  const terms = txt.trim().split(/\s+/).slice(1);
  const out = { raw: txt, includes: [], mechanisms: [], redirect: null, all: null, ip4: 0, ip6: 0 };
  for (const t of terms) {
    const m = t.match(/^([+\-~?])?([a-z0-9]+)([:=/].*)?$/i);
    if (!m) continue;
    const q = m[1] || '+', name = m[2].toLowerCase(), rest = (m[3] || '').replace(/^[:=]/, '');
    if (name === 'redirect' && t.includes('=')) out.redirect = rest;
    else if (name === 'all') out.all = q;
    else if (name === 'include') { out.includes.push(rest); out.mechanisms.push({ name, value: rest }); }
    else if (name === 'ip4') out.ip4++;
    else if (name === 'ip6') out.ip6++;
    else if (['a', 'mx', 'ptr', 'exists'].includes(name)) out.mechanisms.push({ name, value: rest || null });
  }
  return out;
}

export function parseDmarc(txt) {
  const tags = {};
  for (const part of txt.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
  }
  return {
    raw: txt, policy: (tags.p || '').toLowerCase() || null, subdomainPolicy: (tags.sp || '').toLowerCase() || null,
    pct: tags.pct !== undefined ? Number(tags.pct) : 100, rua: tags.rua || null, ruf: tags.ruf || null,
    adkim: (tags.adkim || 'r').toLowerCase(), aspf: (tags.aspf || 'r').toLowerCase(),
  };
}

export function parseDkim(txt) {
  const tags = {};
  for (const part of txt.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).replace(/\s+/g, '').trim();
  }
  const keyType = (tags.k || 'rsa').toLowerCase();
  const p = tags.p ?? null;
  let bits = null;
  if (p && keyType === 'rsa') {
    const bytes = Buffer.from(p, 'base64').length; // SPKI DER size: ~94 B (512) / ~162 B (1024) / ~294 B (2048) / ~550 B (4096)
    bits = bytes >= 550 ? 4096 : bytes >= 420 ? 3072 : bytes >= 270 ? 2048 : bytes >= 140 ? 1024 : 512;
  }
  return { raw: txt, keyType, revoked: p === '', hasKey: !!p, estimatedBits: bits, testing: /(^|:)y(:|$)/.test(tags.t || '') };
}
