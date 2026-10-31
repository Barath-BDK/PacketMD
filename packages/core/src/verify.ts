import type { Report } from './types';

export interface VerifyRow { title: string; hypothesis: string; status: 'RESOLVED' | 'STILL PRESENT' | 'NEW'; before?: string; after?: string }

/** Compares two captures finding by finding, on stable fingerprints rather than packet numbers. */
export function diffReports(before: Report, after: Report): VerifyRow[] {
  const real = (r: Report) => r.findings.filter((f) => f.lane === 'FAULT' || f.lane === 'ATTACK' || f.lane === 'INCONCLUSIVE');
  const a = real(before), b = real(after);
  const rows: VerifyRow[] = a.map((f) => {
    const hit = b.find((x) => x.fingerprint === f.fingerprint) ?? b.find((x) => x.hypothesis === f.hypothesis && x.hosts[0] === f.hosts[0]);
    return { title: f.title, hypothesis: f.hypothesis, status: hit ? 'STILL PRESENT' : 'RESOLVED', before: f.id, after: hit?.id };
  });
  for (const f of b) {
    const seen = a.some((x) => x.fingerprint === f.fingerprint || (x.hypothesis === f.hypothesis && x.hosts[0] === f.hosts[0]));
    if (!seen) rows.push({ title: f.title, hypothesis: f.hypothesis, status: 'NEW', after: f.id });
  }
  return rows;
}
