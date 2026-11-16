import net from 'node:net';

// Deny-by-default IP policy used by the SSRF guard. Anything unparseable is treated as blocked.
const v4ToInt = (s) => s.split('.').reduce((a, p) => (a << 8n) | BigInt(Number(p)), 0n);

const V4_BLOCKED = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24',
  '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
  '224.0.0.0/4', '240.0.0.0/4',
].map((c) => { const [a, l] = c.split('/'); const len = BigInt(l); return { base: v4ToInt(a), mask: ((1n << 32n) - 1n) << (32n - len) & ((1n << 32n) - 1n) }; });

export function isBlockedIpv4(s) {
  if (!net.isIPv4(s)) return true;
  const n = v4ToInt(s);
  return V4_BLOCKED.some(({ base, mask }) => (n & mask) === (base & mask));
}

function v6ToBig(input) {
  let s = input.split('%')[0];
  if (s.includes('.')) {
    const i = s.lastIndexOf(':');
    const n = v4ToInt(s.slice(i + 1));
    s = `${s.slice(0, i + 1)}${((n >> 16n) & 0xffffn).toString(16)}:${(n & 0xffffn).toString(16)}`;
  }
  const parts = s.split('::');
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length > 1 && parts[1] ? parts[1].split(':') : [];
  const fill = parts.length > 1 ? Array(8 - head.length - tail.length).fill('0') : [];
  const groups = [...head, ...fill, ...tail];
  if (groups.length !== 8) return null;
  return groups.reduce((a, g) => (a << 16n) | BigInt(parseInt(g || '0', 16)), 0n);
}
const inV6 = (n, prefixHex, len) => (n >> BigInt(128 - len)) === (BigInt(`0x${prefixHex}`) >> BigInt(128 - len));
const v6Prefix = (groups) => groups.reduce((a, g) => (a << 16n) | BigInt(g), 0n) << BigInt(16 * (8 - groups.length));
const asV4 = (n) => [24n, 16n, 8n, 0n].map((sh) => String((n >> sh) & 0xffn)).join('.');

export function isBlockedIpv6(s) {
  if (!net.isIPv6(s)) return true;
  const n = v6ToBig(s);
  if (n === null) return true;
  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d): apply the IPv4 policy to the embedded address.
  if ((n >> 32n) === 0xffffn) return isBlockedIpv4(asV4(n & 0xffffffffn));
  if ((n >> 32n) === 0n) return true; // ::, ::1, ::a.b.c.d (deprecated)
  // Default deny: only global unicast 2000::/3 is allowed, minus special-purpose ranges.
  if ((n >> 125n) !== 1n) return true;
  const deny = [[[0x2001, 0x0db8], 32], [[0x2001, 0x0000], 32], [[0x2001, 0x0002], 48], [[0x2001, 0x0010], 28], [[0x3fff], 20]];
  for (const [g, len] of deny) if ((n >> BigInt(128 - len)) === (v6Prefix(g) >> BigInt(128 - len))) return true;
  if ((n >> 112n) === 0x2002n) return isBlockedIpv4(asV4((n >> 80n) & 0xffffffffn)); // 6to4 embeds an IPv4 address
  return false;
}

export function isBlockedIp(ip) {
  const s = String(ip ?? '').replace(/^\[|\]$/g, '');
  if (net.isIPv4(s)) return isBlockedIpv4(s);
  if (net.isIPv6(s)) return isBlockedIpv6(s);
  return true;
}
