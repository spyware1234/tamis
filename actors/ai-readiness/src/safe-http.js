// SSRF-safe HTTP client. Guarantees, for the first request AND every redirect hop:
//  - only http/https, no credentials in the URL, only allowed ports (default 80/443)
//  - IP-literal hosts are checked directly; hostnames are resolved by OUR lookup, every returned address must be
//    allowed (public), and the socket connects to the address we validated (no second resolution => no DNS rebinding)
//  - redirects are followed manually (max 5) and re-validated; no auto-decompression (Accept-Encoding: identity)
//  - hard limits on time and body size
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import net from 'node:net';
import { isBlockedIp } from './ip.js';

export class BlockedError extends Error {
  constructor(message) { super(message); this.name = 'BlockedError'; this.blocked = true; }
}

const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const LOCAL_NAME = /(^|\.)(localhost|local|internal|localdomain|lan|home\.arpa|intranet)\.?$/i;

export function createSafeClient({
  isAddressAllowed = (ip) => !isBlockedIp(ip),
  allowedPorts = [80, 443],
  baseLookup = dns.lookup,
  maxRedirects = 5,
  defaultTimeoutMs = 12000,
  defaultMaxBytes = 2_000_000,
} = {}) {
  function guardedLookup(hostname, options, callback) {
    if (typeof options === 'function') { callback = options; options = {}; }
    baseLookup(hostname, { ...options, all: true }, (err, addrs) => {
      if (err) return callback(err);
      if (!addrs || !addrs.length) return callback(new Error(`No address for ${hostname}`));
      const bad = addrs.find((a) => !isAddressAllowed(a.address));
      if (bad) return callback(new BlockedError('Host resolves to a non-public address'));
      if (options && options.all) return callback(null, addrs);
      return callback(null, addrs[0].address, addrs[0].family);
    });
  }

  function validateUrl(u) {
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new BlockedError(`Scheme ${u.protocol} is not allowed`);
    if (u.username || u.password) throw new BlockedError('Credentials in URL are not allowed');
    const port = Number(u.port || (u.protocol === 'https:' ? 443 : 80));
    if (allowedPorts && !allowedPorts.includes(port)) throw new BlockedError(`Port ${port} is not allowed`);
    const host = u.hostname.replace(/^\[|\]$/g, '');
    if (!host || host.length > 253) throw new BlockedError('Invalid host');
    if (net.isIP(host)) { if (!isAddressAllowed(host)) throw new BlockedError('Non-public IP address'); }
    else if (LOCAL_NAME.test(host)) throw new BlockedError('Local host name');
  }

  function requestOnce(u, { method, headers, timeoutMs, maxBytes, readBody }) {
    return new Promise((resolve, reject) => {
      let done = false, timer;
      const finish = (fn, v) => { if (!done) { done = true; clearTimeout(timer); fn(v); } };
      const mod = u.protocol === 'https:' ? https : http;
      const req = mod.request(u, { method, headers, lookup: guardedLookup, agent: false, timeout: timeoutMs }, (res) => {
        const status = res.statusCode, hdrs = res.headers;
        if (!readBody || REDIRECTS.has(status)) { res.destroy(); return finish(resolve, { status, headers: hdrs, body: Buffer.alloc(0), truncated: false }); }
        const chunks = []; let n = 0, truncated = false;
        res.on('data', (c) => {
          if (truncated) return;
          n += c.length;
          if (n > maxBytes) { truncated = true; chunks.push(c.subarray(0, c.length - (n - maxBytes))); res.destroy(); } else chunks.push(c);
        });
        res.on('close', () => finish(resolve, { status, headers: hdrs, body: Buffer.concat(chunks), truncated }));
        res.on('error', (e) => { if (!truncated) finish(reject, e); });
      });
      timer = setTimeout(() => req.destroy(new Error('timeout')), timeoutMs);
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', (e) => finish(reject, e));
      req.end();
    });
  }

  async function request(rawUrl, { method = 'GET', ua = 'TamisAuditBot/1.0', timeoutMs = defaultTimeoutMs, maxBytes = defaultMaxBytes, readBody = true } = {}) {
    const headers = { 'user-agent': ua, accept: 'text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5', 'accept-encoding': 'identity', connection: 'close' };
    let u;
    try { u = new URL(rawUrl); } catch { return { status: 0, error: 'Invalid URL', blocked: false, url: String(rawUrl), text: '' }; }
    const deadline = Date.now() + timeoutMs;
    try {
      for (let hop = 0; hop <= maxRedirects; hop++) {
        validateUrl(u);
        const remaining = Math.max(1000, deadline - Date.now());
        const r = await requestOnce(u, { method, headers, timeoutMs: remaining, maxBytes, readBody });
        if (REDIRECTS.has(r.status) && r.headers.location) {
          if (hop === maxRedirects) return { status: 0, error: 'Too many redirects', blocked: false, url: u.href, text: '' };
          u = new URL(r.headers.location, u); // may throw => caught below (invalid redirect target)
          continue;
        }
        return {
          status: r.status, url: u.href, redirects: hop,
          contentType: String(r.headers['content-type'] || ''), xRobotsTag: String(r.headers['x-robots-tag'] || ''),
          text: readBody ? r.body.toString('utf8') : '', truncated: r.truncated,
        };
      }
      return { status: 0, error: 'Too many redirects', blocked: false, url: u.href, text: '' };
    } catch (e) {
      return { status: 0, url: u.href, text: '', blocked: !!e.blocked, error: e.blocked ? e.message : String(e.message ?? e).slice(0, 200) };
    }
  }

  return {
    fetchText: (url, opts) => request(url, { ...opts, readBody: true }),
    probe: async (url, opts) => { const r = await request(url, { ...opts, readBody: false }); return r.status; },
  };
}
