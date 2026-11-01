import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyze, isDisposableEmail } from '@packetmd/core';
import { fileSource } from '../packages/cli/src/source';

type Case = { file: string; must: string[] | null; why: string; dir?: string; allow?: string[] };
const load = (dir: string) => (JSON.parse(readFileSync(`labgen/${dir}/manifest.json`, 'utf8')) as Case[]).map((c) => ({ ...c, dir }));
const cases = [...load('evasion'), ...load('blind'), ...load('blind2')];

describe('evasion: an attacker trying to slip past the detectors', () => {
  for (const c of cases.filter((x) => x.must)) it(`${c.file}: ${c.why}`, async () => {
    const s = fileSource(`labgen/${c.dir}/${c.file}.pcap`), r = await analyze(s, `${c.file}.pcap`);
    s.close();
    const raised = r.findings.filter((f) => f.lane === 'ATTACK' || f.lane === 'INCONCLUSIVE').map((f) => f.hypothesis);
    expect(raised.some((h) => c.must!.includes(h)), `raised ${raised}`).toBe(true);
  });
});

describe('look-alikes: normal traffic that must not raise an alarm', () => {
  for (const c of cases.filter((x) => !x.must)) it(`${c.file}: ${c.why}`, async () => {
    const s = fileSource(`labgen/${c.dir}/${c.file}.pcap`), r = await analyze(s, `${c.file}.pcap`);
    s.close();
    expect(r.findings.filter((f) => f.lane !== 'BENIGN' && !c.allow?.includes(f.hypothesis)).map((f) => f.hypothesis)).toEqual([]);
  });
  for (const file of ['clean-cloud-backup', 'clean-vpn-keepalive']) it(`${file} is questioned, never called an attack`, async () => {
    const s = fileSource(`labgen/blind2/${file}.pcap`), r = await analyze(s, `${file}.pcap`);
    s.close();
    expect(r.findings.filter((f) => f.lane === 'ATTACK')).toEqual([]);
  });
});

describe('temporary email tricks', () => {
  it('sees through a trailing dot, spaces and capitals', () => {
    for (const e of ['a@mailinator.com.', ' a@MAILINATOR.com ', 'a@sharklasers.com.', 'A@Mail.TM.']) expect(isDisposableEmail(e), e).toBe(true);
  });
});
