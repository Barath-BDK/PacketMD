import type { Report } from '@packetmd/core';

/** Replaces every IP and MAC with a stable label before anything leaves the browser. Names such as domains stay, and the UI says so. */
const isIpv6 = (m: string) => {
  // Times such as 10:30:05 and MACs share the alphabet, so only a real address shape counts.
  if (m.length > 39 || /^\d{1,2}(:\d{2}){1,2}$/.test(m) || /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(m)) return false;
  const parts = m.split(':'), gap = m.indexOf('::');
  if (/^:[^:]|[^:]:$/.test(m) || gap !== m.lastIndexOf('::') || parts.length > 9 || parts.some((p) => p.length > 4)) return false;
  return gap < 0 ? parts.length === 8 : parts.length >= 3;
};

export function pseudonymize<T>(value: T): T {
  const seen = new Map<string, string>();
  const swap = (kind: string) => (m: string) => { if (!seen.has(m)) seen.set(m, `${kind}-${seen.size + 1}`); return seen.get(m)!; };
  const text = JSON.stringify(value)
    // One flat character run, because a nested IPv6 pattern can hang on a crafted name.
    .replace(/(?<![\w:])[0-9a-f:]{2,}(?![\w:])/gi, (m) => (isIpv6(m) ? swap('host')(m) : m))
    .replace(/\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi, (m) => swap('mac')(m.replace(/-/g, ':').toLowerCase()))
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, swap('host'));
  return JSON.parse(text) as T;
}

/** The whole report for reopening later. Packet rows never go, and every address is replaced with one consistent map. */
export function fullPayload(r: Report) {
  return pseudonymize({ ...r, rows: [], baseline: { gateways: {}, dhcpServers: [], resolvers: [], ipMac: {} }, hosts: r.hosts.slice(0, 200), conversations: r.conversations.slice(0, 500), activity: r.activity.slice(0, 300) });
}

/** Findings only, using the same labels as the full report so one host never gets two names. */
export function payload(r: Report) {
  const full = fullPayload(r);
  // Stays inside the share function's limits, so a capture with long values cannot make sharing fail.
  const cut = (x: string, n: number) => x.slice(0, n);
  const findings = full.findings.slice(0, 30).map((f) => ({
    id: f.id, lane: f.lane, hypothesis: f.hypothesis, title: cut(f.title, 160), confidence: f.confidence, plain: cut(f.plain, 1000), cause: cut(f.cause, 1000),
    whyNotTheOther: cut(f.whyNotTheOther, 1000), analogy: cut(f.analogy, 400), verifyBy: cut(f.verifyBy, 400), fixTitles: f.fixSteps.slice(0, 12).map((x) => cut(f.fixIf ? `If confirmed: ${x.title}` : x.title, 200)), proofPackets: f.evidence.slice(0, 20).map((e) => e.no),
  }));
  // Most serious first, so the share function's size limit only ever costs the least important findings.
  while (findings.length > 1 && new TextEncoder().encode(JSON.stringify(findings)).length > 60_000) findings.pop();
  return { file_sha256: r.defense.sha256, summary: pseudonymize({ headline: cut(r.headline, 300), packets: r.defense.packets, schema: r.schema }), findings };
}
