import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyze, BUDGET, Rejected } from '@packetmd/core';

const samples = readdirSync('samples').filter((f) => f.endsWith('.pcap') && !f.startsWith('large'));
const RUNS = Number(process.env.FUZZ_RUNS ?? 12);

// Seeded so a failure can be replayed.
function rng(seed: number) { return () => (seed = (seed * 1664525 + 1013904223) >>> 0) / 2 ** 32; }

function mutate(b: Uint8Array, r: () => number) {
  const out = b.slice();
  const kind = Math.floor(r() * 4);
  if (kind === 0) for (let i = 0; i < 40; i++) out[Math.floor(r() * out.length)]! ^= 1 << Math.floor(r() * 8);
  if (kind === 1) return out.subarray(0, Math.max(24, Math.floor(r() * out.length)));
  if (kind === 2) { const v = new DataView(out.buffer); for (let i = 0; i < 12; i++) { const o = 24 + Math.floor(r() * (out.length - 40)); v.setUint32(o, r() < 0.5 ? 0xffffffff : Math.floor(r() * 70000), true); } }
  if (kind === 3) out.fill(0xff, 24 + Math.floor(r() * 200), Math.min(out.length, 300 + Math.floor(r() * 400)));
  return out;
}

describe('mutation fuzz', () => {
  for (const name of samples) it(`${name} never throws or overruns a budget`, async () => {
    const base = new Uint8Array(readFileSync(`samples/${name}`));
    const r = rng(name.length * 7919);
    for (let i = 0; i < RUNS; i++) {
      const b = mutate(base, r);
      try {
        const rep = await analyze({ size: b.length, read: async (o, l) => b.subarray(o, o + l) }, name);
        expect(rep.defense.packets).toBeLessThanOrEqual(BUDGET.maxPackets);
        for (const row of rep.rows) expect(row.info.length).toBeLessThan(BUDGET.maxString + 10);
      } catch (e) { if (!(e instanceof Rejected)) throw e; }
    }
  });
});
