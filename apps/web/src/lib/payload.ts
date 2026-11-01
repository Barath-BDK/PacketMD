import type { Report } from '@packetmd/core';

/** Replaces every IP and MAC with a stable label before anything leaves the browser. */
export function pseudonymize<T>(value: T): T {
  const seen = new Map<string, string>();
  const swap = (kind: string) => (m: string) => { if (!seen.has(m)) seen.set(m, `${kind}-${seen.size + 1}`); return seen.get(m)!; };
  const text = JSON.stringify(value)
    .replace(/\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/gi, swap('mac'))
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, swap('host'))
    // IPv6 needs at least two colons, so times like 10:30 are left alone.
    .replace(/(?<![\w:])(?:[0-9a-f]{1,4}:){2,7}(?::?[0-9a-f]{1,4})+(?![\w:])|(?<![\w:])(?:[0-9a-f]{1,4}:)+:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?(?![\w:])/gi, (m) => (/^\d{1,2}(:\d{2}){1,2}$/.test(m) ? m : swap('host')(m)));
  return JSON.parse(text) as T;
}

/** Findings only. Packet rows, offsets into the file and raw values never go out. */
export function payload(r: Report) {
  const findings = r.findings.map((f) => pseudonymize({
    id: f.id, lane: f.lane, hypothesis: f.hypothesis, title: f.title, confidence: f.confidence, plain: f.plain, cause: f.cause,
    whyNotTheOther: f.whyNotTheOther, analogy: f.analogy, verifyBy: f.verifyBy, fixTitles: f.fixSteps.map((s) => s.title), proofPackets: f.evidence.slice(0, 20).map((e) => e.no),
  }));
  return { file_sha256: r.defense.sha256, summary: pseudonymize({ headline: r.headline, packets: r.defense.packets, schema: r.schema }), findings };
}
