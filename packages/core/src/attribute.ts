import { T } from './thresholds';
import type { Ctx, Flow } from './context';
import { dgaScore, isPrivate } from './detect/detectors';
import type { ActivityRow } from './types';

// Small allowlist of service families, taken from vendor documentation for update, time and connectivity checks.
const DAEMON: [RegExp, string][] = [
  [/(^|\.)(windowsupdate|update\.microsoft|delivery\.mp\.microsoft)\.com$/i, 'OS update'],
  [/(^|\.)(swscan|swdist|mesu)\.apple\.com$/i, 'OS update'],
  [/(^|\.)(archive\.ubuntu|security\.ubuntu|deb\.debian)\.(com|org)$/i, 'OS update'],
  [/(^|\.)(pool\.ntp\.org|time\.windows\.com|time\.apple\.com|time\.google\.com)$/i, 'Time sync'],
  [/(^|\.)(connectivitycheck\.gstatic\.com|captive\.apple\.com|msftconnecttest\.com|detectportal\.firefox\.com)$/i, 'Connectivity check'],
  [/(^|\.)(ocsp\.|crl\.)/i, 'Certificate check'],
];
const BROWSER_UA = /(mozilla|chrome|safari|firefox|edg)\//i;
const CDN = /(akamai|cloudfront|fastly|cloudflare|googleusercontent|azureedge)/i;
const ODD_TLD = /\.(zip|mov|top|xyz|click|gq|tk|ml)$/i;
const BRANDS = ['google', 'microsoft', 'paypal', 'apple', 'amazon', 'facebook'];
const swap = (s: string) => s.replace(/0/g, 'o').replace(/1/g, 'l').replace(/rn/g, 'm').replace(/vv/g, 'w');

function rate(name: string, f: { bytesOut: number; bytesIn: number; clearCred?: boolean }) {
  const reasons: string[] = [];
  let score = 0;
  const main = name.split('.').slice(-2, -1)[0] ?? name;
  if (dgaScore(name)) { score += 2; reasons.push('Name looks machine-generated'); }
  if (name.startsWith('xn--') || name.includes('.xn--')) { score += 1; reasons.push('Punycode name, check for a lookalike'); }
  if (ODD_TLD.test(name)) { score += 1; reasons.push('Top-level domain often abused'); }
  const lookalike = BRANDS.find((b) => main !== b && swap(main).includes(b));
  if (lookalike) { score += 2; reasons.push(`Looks like ${lookalike} but is not`); }
  if (f.bytesOut > T.LARGE_UPLOAD_MIN && f.bytesOut > f.bytesIn * T.LARGE_UPLOAD_RATIO) { score += 1; reasons.push('Uploads far more than it downloads'); }
  return { score, reasons };
}

export function attribute(ctx: Ctx): ActivityRow[] {
  const groups = new Map<string, Flow[]>();
  for (const f of ctx.flows) {
    if (f.pb === 53 || f.pa === 53 || f.pb === 67 || f.pb === 68) continue;
    const key = f.domain ?? (f.hiddenName ? `(name hidden by ${f.hiddenName}) ${f.b}` : f.b);
    (groups.get(key) ?? groups.set(key, []).get(key)!).push(f);
  }
  const rows: ActivityRow[] = [];
  for (const [domain, fs] of groups) {
    const f = fs[0]!, hidden = f.hiddenName;
    const bytesIn = fs.reduce((n, x) => n + x.bytesBA, 0), bytesOut = fs.reduce((n, x) => n + x.bytesAB, 0);
    const basis: string[] = [`port ${f.pb}`];
    if (f.domainSource) basis.push(f.domainSource);
    const daemon = f.domain && DAEMON.find(([r]) => r.test(f.domain!));
    let klass = 'Unknown';
    if (f.pb === 123 || f.pa === 123) { klass = 'System daemon'; basis.push('NTP'); }
    else if ([5353, 5355, 137, 1900].includes(f.pb)) { klass = 'System daemon'; basis.push('local discovery'); }
    else if (daemon) { klass = 'System daemon'; basis.push(daemon[1]); }
    else if (f.ua && BROWSER_UA.test(f.ua)) { klass = 'Web / browser-like'; basis.push('browser-style User-Agent'); }
    else if (f.ua) { klass = 'App / API client'; basis.push('non-browser User-Agent'); }
    else if (f.pb === 443 || f.pb === 80) { klass = f.ja3 ? 'Web / browser-like' : 'App / API client'; if (f.ja3) basis.push(`TLS fingerprint ${f.ja3.slice(0, 8)}`); }
    else if (ctx.gateways.has(f.b)) { klass = 'Infrastructure'; basis.push('gateway'); }
    const { score, reasons } = hidden ? { score: 0, reasons: [`The domain is hidden by ${hidden}. PacketMD will not guess it.`] } : f.domain && !daemon ? rate(f.domain, { bytesIn, bytesOut }) : { score: 0, reasons: [] as string[] };
    if (!f.domain && !hidden && !isPrivate(f.b) && f.pb === 443) reasons.push('TLS to a bare address with no name');
    if (f.domainSource === 'HTTP Host header' && !isPrivate(f.b)) reasons.push('Plain HTTP to a public address');
    const ratingVal: ActivityRow['rating'] = score >= 3 ? 'Likely malicious' : score >= 1 ? 'Suspicious' : daemon || (f.domain && CDN.test(f.domain)) ? 'Clean-looking' : f.domain ? 'Clean-looking' : 'Unknown';
    rows.push({
      domain, source: hidden ? `Hidden by ${hidden}` : f.domainSource ?? 'No name seen, address only', sourcePacket: f.domainPacket ?? f.first, klass, basis,
      bytesIn, bytesOut, first: Math.min(...fs.map((x) => x.t0)), last: Math.max(...fs.map((x) => x.t1)), requests: fs.length, protocol: f.proto,
      health: fs.reduce((n, x) => n + x.retrans.length + x.rst.length, 0), rating: ratingVal, reasons, conv: fs.slice(0, 40).map((x) => x.id),
    });
  }
  return rows.sort((a, b) => b.bytesIn + b.bytesOut - (a.bytesIn + a.bytesOut)).slice(0, 2000);
}
