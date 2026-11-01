import { describe, expect, it } from 'vitest';
import { analyze, type ByteSource } from '@packetmd/core';

// A hostile capture must not crash or stall the engine by sheer shape: every test is a volume attack on the analysis itself.
const mem = (b: Uint8Array): ByteSource => ({ size: b.length, read: async (o, l) => b.subarray(o, o + l) });

function pcap(frames: Uint8Array[]) {
  const size = 24 + frames.reduce((n, f) => n + 16 + f.length, 0), b = new Uint8Array(size), v = new DataView(b.buffer);
  v.setUint32(0, 0xa1b2c3d4, true); v.setUint16(4, 2, true); v.setUint16(6, 4, true); v.setUint32(16, 65535, true); v.setUint32(20, 1, true);
  let o = 24, t = 0;
  for (const f of frames) { v.setUint32(o, 1760000000 + (t >> 12), true); v.setUint32(o + 4, (t++ & 4095) * 200, true); v.setUint32(o + 8, f.length, true); v.setUint32(o + 12, f.length, true); b.set(f, o + 16); o += 16 + f.length; }
  return b;
}
const eth = (src: number, type: number) => [0, 0x1a, 0x2b, 0, 0, 1, 2, 0, (src >> 16) & 255, (src >> 8) & 255, src & 255, 1, type >> 8, type & 255];
function tcp(i: number, srcIp: number[], dstIp: number[], sport: number, dport: number, flags: number) {
  const ip = [0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0, ...srcIp, ...dstIp];
  return new Uint8Array([...eth(i, 0x800), ...ip, sport >> 8, sport & 255, dport >> 8, dport & 255, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 16, 0, 0, 0, 0, 0]);
}
function arp(i: number, spa: number[], tpa: number[], op = 2) {
  return new Uint8Array([...eth(i, 0x806), 0, 1, 8, 0, 6, 4, 0, op, 2, 0, (i >> 16) & 255, (i >> 8) & 255, i & 255, 1, ...spa, 0, 1, 2, 3, 4, 5, ...tpa]);
}
const q = (i: number) => [10, (i >> 16) & 255, (i >> 8) & 255, i & 255];
const timed = async (frames: Uint8Array[]) => { const t = Date.now(), r = await analyze(mem(pcap(frames)), 'x.pcap'); return { r, ms: Date.now() - t }; };
const N = 150_000, LIMIT = 45_000;

describe('volume attacks on the engine', () => {
  it('one source scanning a huge number of ports and hosts', async () => {
    const { r, ms } = await timed(Array.from({ length: N }, (_, i) => tcp(1, [10, 0, 0, 1], q(i), 40000, i % 65000 + 1, 2)));
    expect(r.rows.length).toBe(N); expect(ms).toBeLessThan(LIMIT);
    expect(r.findings.some((f) => f.hypothesis === 'port-scan')).toBe(true);
  }, 90000);
  it('a SYN flood from every source at one service', async () => {
    const { r, ms } = await timed(Array.from({ length: N }, (_, i) => tcp(i, q(i), [192, 168, 1, 80], i % 60000 + 1024, 80, 2)));
    expect(ms).toBeLessThan(LIMIT);
    expect(r.findings.some((f) => f.hypothesis === 'syn-flood')).toBe(true);
  }, 90000);
  it('half-open attempts at a huge number of different services', async () => {
    const { ms } = await timed(Array.from({ length: N }, (_, i) => tcp(i, q(i), q(i + 7), 1024 + (i % 60000), i % 60000 + 1, 2)));
    expect(ms).toBeLessThan(LIMIT);
  }, 90000);
  it('thousands of addresses each claimed by two MACs', async () => {
    const frames: Uint8Array[] = [];
    for (let i = 0; i < 30000; i++) { frames.push(arp(1, q(i), [10, 0, 0, 1])); frames.push(arp(2, q(i), [10, 0, 0, 1])); }
    const { r, ms } = await timed(frames);
    expect(ms).toBeLessThan(LIMIT);
    expect(r.findings.length).toBeLessThanOrEqual(200);
  }, 90000);
  it('every packet malformed', async () => {
    const bad = (i: number) => { const f = tcp(i, q(i), q(i + 1), 1, 2, 2); f[14] = 0x42; return f; };
    const { r, ms } = await timed(Array.from({ length: N }, (_, i) => bad(i)));
    expect(ms).toBeLessThan(LIMIT);
    expect(r.findings.some((f) => f.hypothesis === 'parser-evasion')).toBe(true);
  }, 90000);
  it('out of order and identical timestamps', async () => {
    const b = pcap(Array.from({ length: 2000 }, (_, i) => tcp(1, [10, 0, 0, 1], [10, 0, 0, 2], 4000, i % 40 + 1, 2)));
    const v = new DataView(b.buffer);
    for (let o = 24, i = 0; o < b.length; i++) { v.setUint32(o, i % 2 ? 0 : 0xffffffff, true); o += 16 + v.getUint32(o + 8, true); }
    const r = await analyze(mem(b), 'x.pcap');
    expect(r.rows.length).toBe(2000);
  }, 30000);
  it('a valid capture with no packets at all', async () => {
    const r = await analyze(mem(pcap([])), 'empty.pcap');
    expect(r.findings).toEqual([]);
    expect(r.rows).toEqual([]);
  });
  it('a capture with a single packet', async () => {
    const r = await analyze(mem(pcap([tcp(1, [10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 2)])), 'one.pcap');
    expect(r.rows.length).toBe(1);
  });
});
