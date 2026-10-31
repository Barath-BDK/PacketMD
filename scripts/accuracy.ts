import { readFileSync, writeFileSync } from 'node:fs';
import { analyze } from '@packetmd/core';
import { fileSource } from '../packages/cli/src/source';

// Measures the engine against ground truth. Every number on the Methodology page comes from this file.
const expected = JSON.parse(readFileSync('samples/expected.json', 'utf8')) as Record<string, { findings: string[]; allowed: string[]; note: string }>;
let tp = 0, fp = 0, fn = 0, negatives = 0, falseAlarms = 0;
const rows: { file: string; expected: string[]; got: string[]; ok: boolean; extra: string[]; missed: string[] }[] = [];

for (const [name, e] of Object.entries(expected)) {
  const src = fileSource(`samples/${name}.pcap`);
  const r = await analyze(src, `${name}.pcap`);
  src.close();
  const got = r.findings.filter((f) => f.lane !== 'BENIGN').map((f) => f.lane === 'INCONCLUSIVE' ? `inconclusive:${f.hypothesis}` : f.hypothesis);
  const missed = e.findings.filter((h) => !got.includes(h));
  const extra = got.filter((h) => !e.findings.includes(h) && !e.allowed.includes(h));
  tp += e.findings.length - missed.length; fn += missed.length; fp += extra.length;
  if (!e.findings.length) { negatives++; if (got.length) falseAlarms++; }
  rows.push({ file: name, expected: e.findings, got, ok: !missed.length && !extra.length, extra, missed });
}
const out = {
  samples: rows.length, precision: +(tp / (tp + fp || 1)).toFixed(3), recall: +(tp / (tp + fn || 1)).toFixed(3),
  falseAlarmRate: +(falseAlarms / (negatives || 1)).toFixed(3), hardNegatives: negatives, rows,
};
writeFileSync('samples/accuracy.json', JSON.stringify(out, null, 2));
for (const r of rows) console.log(`${r.ok ? 'ok  ' : 'MISS'} ${r.file.padEnd(34)} want [${r.expected}] got [${r.got}]`);
console.log(`precision ${out.precision}  recall ${out.recall}  false-alarm rate ${out.falseAlarmRate} on ${negatives} clean samples`);
