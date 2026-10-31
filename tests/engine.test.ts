import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyze, diffReports, type Report } from '@packetmd/core';
import { fileSource } from '../packages/cli/src/source';
import { decide, softmax } from '../packages/core/src/verdict/engine';

const run = async (n: string, baseline?: Report['baseline']) => { const s = fileSource(`samples/${n}.pcap`); const r = await analyze(s, `${n}.pcap`, { baseline }); s.close(); return r; };
const expected = JSON.parse(readFileSync('samples/expected.json', 'utf8')) as Record<string, { findings: string[] }>;
const truth = JSON.parse(readFileSync('samples/scapy-truth.json', 'utf8')) as Record<string, [number, string | null, string | null, number | null, number | null][]>;

describe('differential against Scapy', () => {
  for (const name of Object.keys(truth)) it(name, async () => {
    const r = await run(name), t = truth[name]!;
    expect(r.rows.length).toBe(t.length);
    r.rows.forEach((row, i) => {
      const [len, src, dst, sp, dp] = t[i]!;
      expect(row.capLen).toBe(len);
      if (src) { expect(row.src).toBe(src); expect(row.dst).toBe(dst); }
      if (sp && !row.proto.startsWith('IP')) { expect(row.sport).toBe(sp); expect(row.dport).toBe(dp); }
    });
  });
});

describe('ground truth', () => {
  for (const [name, e] of Object.entries(expected)) it(name, async () => {
    const r = await run(name);
    const got = r.findings.filter((f) => f.lane !== 'BENIGN').map((f) => (f.lane === 'INCONCLUSIVE' ? `inconclusive:${f.hypothesis}` : f.hypothesis));
    for (const h of e.findings) expect(got).toContain(h);
  });
});

describe('verdict engine', () => {
  const cand = (weights: Record<string, number>, matched = false) => ({ detector: 'x', topic: 't', hypotheses: ['arp-spoof', 'duplicate-ip'], hosts: ['a'], t0: 0, t1: 1, evidence: [1], facts: {}, signals: [{ id: 's', label: 's', weights, packets: [1] }], benign: [{ id: 'b', label: 'b', matched, packets: [] }] });
  it('softmax sums to one', () => expect(softmax([1, 2, 3]).reduce((a, b) => a + b)).toBeCloseTo(1));
  it('goes INCONCLUSIVE on a thin margin', () => {
    const c = decide([cand({ 'arp-spoof': 1, 'duplicate-ip': 0.5 })]);
    expect(c.lane).toBe('INCONCLUSIVE');
  });
  it('blocks ATTACK when a benign check matched', () => {
    const c = decide([cand({ 'arp-spoof': 6 }, true)]);
    expect(c.lane).not.toBe('ATTACK');
  });
  it('issues ATTACK on strong evidence', () => expect(decide([cand({ 'arp-spoof': 6 })]).lane).toBe('ATTACK'));
});

describe('nuance required by the brief', () => {
  it('home router is a fault, the same shape with foreign DNS is an attack', async () => {
    expect((await run('rogue-dhcp-benign-router')).findings[0]!.lane).toBe('FAULT');
    expect((await run('rogue-dhcp-malicious')).findings[0]!.lane).toBe('ATTACK');
  });
  it('flood and outage separate', async () => {
    expect((await run('syn-flood')).findings[0]!.hypothesis).toBe('syn-flood');
    expect((await run('server-outage')).findings[0]!.hypothesis).toBe('server-outage');
  });
});

describe('fixes are file-specific', () => {
  it('use the real addresses from the capture', async () => {
    const f = (await run('arp-spoof')).findings[0]!;
    expect(JSON.stringify(f.fixSteps)).toContain('de:ad:be:ef:00:66');
  });
  it('contain no unresolved blanks', async () => {
    const r = await run('mixed-incident');
    expect(JSON.stringify(r.findings.map((f) => f.fixSteps))).not.toMatch(/undefined|null/);
  });
});

describe('stories', () => {
  it('explain why a benign verdict is benign', async () => {
    const f = (await run('failover-gratuitous-arp')).findings.find((x) => x.lane === 'BENIGN')!;
    expect(f.story.map((s) => s.key)).toEqual(['seen', 'flag', 'cleared', 'verdict']);
    expect(f.story[2]!.caption.length).toBeGreaterThan(20);
  });
  it('show both sides and what is missing when inconclusive', async () => {
    const f = (await run('arp-gateway-ambiguous')).findings.find((x) => x.lane === 'INCONCLUSIVE')!;
    expect(f.story.map((s) => s.key)).toEqual(['seen', 'case-a', 'case-b', 'gap', 'next']);
    expect(f.nextCapture).toBeTruthy();
  });
  it('give every reading level different words', async () => {
    const f = (await run('arp-spoof')).findings[0]!;
    expect(new Set([f.levels.beginner.what, f.levels.technical.what, f.levels.analyst.what]).size).toBe(3);
    expect(new Set([f.levels.beginner.why, f.levels.technical.why, f.levels.analyst.why]).size).toBe(3);
  });
  it('start at the attacker, not at earlier innocent traffic', async () => {
    const r = await run('arp-spoof'), f = r.findings[0]!;
    const start = f.story.find((s) => s.key === 'start')!;
    expect(r.rows[start.packets[0]! - 1]!.srcMac).toBe('de:ad:be:ef:00:66');
  });
});

describe('verify fix and baseline', () => {
  it('marks findings RESOLVED after the fix', async () => {
    const rows = diffReports(await run('mixed-incident'), await run('mixed-incident-after-fix'));
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((x) => x.status === 'RESOLVED')).toBe(true);
  });
  it('STILL PRESENT when nothing changed', async () => {
    const r = await run('arp-spoof');
    expect(diffReports(r, r).every((x) => x.status === 'STILL PRESENT')).toBe(true);
  });
  it('a saved baseline flags a clean-looking change of owner', async () => {
    const base = (await run('normal-baseline')).baseline;
    base.ipMac['192.168.1.1'] = '00:00:00:00:00:99';
    const r = await run('normal-baseline', base);
    expect(r.findings.some((f) => f.signals.some((s) => s.id === 'off-baseline'))).toBe(true);
  });
});

describe('attribution', () => {
  it('shows a hidden domain as hidden, never guessed', async () => {
    const a = (await run('hidden-domain-ech')).activity;
    expect(a.some((x) => x.source === 'Hidden by ECH')).toBe(true);
    expect(a.some((x) => x.source === 'Hidden by DoT')).toBe(true);
  });
  it('classes update and connectivity checks as daemons, not malicious', async () => {
    const a = (await run('normal-baseline')).activity;
    const d = a.find((x) => x.domain === 'connectivitycheck.gstatic.com')!;
    expect(d.klass).toBe('System daemon');
    expect(d.rating).toBe('Clean-looking');
    expect(d.source).toBe('TLS SNI');
  });
});
