import { readFileSync } from 'node:fs';
import { analyze } from '@packetmd/core';
import { fileSource } from '../packages/cli/src/source';

const dir = process.argv[2] ?? 'evasion';
// Reports which deliberately evasive captures slipped through and which clean look-alikes raised an alarm.
const cases = JSON.parse(readFileSync(`labgen/${dir}/manifest.json`, 'utf8')) as { file: string; must: string[] | null; why: string; allow?: string[] }[];
let caught = 0, attacks = 0, quiet = 0, clean = 0;
for (const c of cases) {
  const s = fileSource(`labgen/${dir}/${c.file}.pcap`), r = await analyze(s, `${c.file}.pcap`);
  s.close();
  const raised = r.findings.filter((f) => f.lane === 'ATTACK' || f.lane === 'INCONCLUSIVE');
  const all = r.findings.map((f) => `${f.lane}:${f.hypothesis}`).join(' ') || 'nothing';
  if (c.must) {
    attacks++;
    const ok = raised.some((f) => c.must!.includes(f.hypothesis));
    if (ok) caught++;
    console.log(`${ok ? 'ok    ' : 'SLIPS '} ${c.file.padEnd(30)} ${all}`);
  } else {
    clean++;
    const ok = !r.findings.some((f) => f.lane !== 'BENIGN' && !(c.allow ?? []).includes(f.hypothesis));
    if (ok) quiet++;
    console.log(`${ok ? 'ok    ' : 'ALARM '} ${c.file.padEnd(30)} ${all}`);
  }
}
console.log(`caught ${caught} of ${attacks} evasive attacks, ${quiet} of ${clean} look-alikes stayed quiet`);
