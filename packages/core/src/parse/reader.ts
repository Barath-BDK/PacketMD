import { BUDGET } from '../thresholds';
import type { ByteSource, RawPacket } from '../types';

export interface ParseStats { format: string; linkTypes: Set<number>; skipped: number; anomalies: Map<string, number>; truncated: boolean }

export const newStats = (format: string): ParseStats => ({ format, linkTypes: new Set(), skipped: 0, anomalies: new Map(), truncated: false });
export function note(s: ParseStats, key: string, n = 1) { s.anomalies.set(key, (s.anomalies.get(key) ?? 0) + n); }

/** Sliding window over the source, so memory stays at chunkBytes whatever the file size. */
class Window {
  buf: Uint8Array = new Uint8Array(0);
  base = 0;
  constructor(private src: ByteSource) {}
  async need(off: number, len: number): Promise<Uint8Array | null> {
    if (len < 0 || off < 0 || off + len > this.src.size) return null;
    if (off < this.base || off + len > this.base + this.buf.length) {
      this.base = off;
      this.buf = await this.src.read(off, Math.max(len, BUDGET.chunkBytes));
    }
    const s = off - this.base;
    return s + len <= this.buf.length ? this.buf.subarray(s, s + len) : null;
  }
}

const rd32 = (b: Uint8Array, o: number, le: boolean) => {
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  return v.getUint32(o, le);
};

export async function* parsePcap(src: ByteSource, st: ParseStats): AsyncGenerator<RawPacket> {
  const w = new Window(src);
  const h = await w.need(0, 24);
  if (!h) { st.truncated = true; note(st, 'truncated global header'); return; }
  const magic = rd32(h, 0, false);
  const le = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1;
  const nano = magic === 0xa1b23c4d || magic === 0x4d3cb2a1;
  const snap = rd32(h, 16, le);
  const link = rd32(h, 20, le) & 0x0fffffff;
  if (snap > BUDGET.maxPacketBytes) note(st, 'header snaplen larger than any real capture');
  st.linkTypes.add(link);
  let off = 24, no = 0;
  while (off < src.size) {
    if (no >= BUDGET.maxPackets) { st.truncated = true; note(st, 'packet budget reached'); return; }
    const r = await w.need(off, 16);
    if (!r) { st.truncated = true; note(st, 'file ends inside a record header'); return; }
    const sec = rd32(r, 0, le), frac = rd32(r, 4, le), cap = rd32(r, 8, le), orig = rd32(r, 12, le);
    if (cap > BUDGET.maxPacketBytes) {
      // No way to find the next record after a lying length, so the walk stops here.
      st.truncated = true; st.skipped++; note(st, 'record length lie'); return;
    }
    const d = await w.need(off + 16, cap);
    if (!d) { st.truncated = true; st.skipped++; note(st, 'file ends inside a packet'); return; }
    no++;
    yield { no, ts: sec + frac / (nano ? 1e9 : 1e6), capLen: cap, origLen: orig, linkType: link, recordOffset: off, dataOffset: off + 16, data: d };
    off += 16 + cap;
  }
}

export async function* parsePcapng(src: ByteSource, st: ParseStats): AsyncGenerator<RawPacket> {
  const w = new Window(src);
  let off = 0, no = 0, le = true;
  let ifaces: { link: number; res: number }[] = [];
  while (off < src.size) {
    if (no >= BUDGET.maxPackets) { st.truncated = true; note(st, 'packet budget reached'); return; }
    const h = await w.need(off, 12);
    if (!h) { st.truncated = true; note(st, 'file ends inside a block header'); return; }
    const type0 = rd32(h, 0, true);
    if (type0 === 0x0a0d0d0a) {
      const bom = rd32(h, 8, true);
      if (bom === 0x1a2b3c4d) le = true;
      else if (bom === 0x4d3c2b1a) le = false;
      else { st.truncated = true; note(st, 'bad byte-order magic'); return; }
      ifaces = [];
    }
    const type = rd32(h, 0, le), blen = rd32(h, 4, le);
    // Length 0 would loop forever and a misaligned one desynchronises the walk: both end it here.
    if (blen < 12 || blen % 4 !== 0 || blen > BUDGET.maxPcapngBlock) {
      st.truncated = true; note(st, 'pcapng block length lie'); return;
    }
    if (off + blen > src.size) { st.truncated = true; note(st, 'pcapng block length past end of file'); return; }
    const b = await w.need(off, blen);
    if (!b) { st.truncated = true; return; }
    if (type === 1 && blen >= 20) {
      const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
      const link = dv.getUint16(8, le);
      let res = 1e-6, p = 16;
      while (p + 4 <= blen - 4) {
        const code = dv.getUint16(p, le), len = dv.getUint16(p + 2, le);
        if (code === 0) break;
        if (code === 9 && len === 1 && p + 4 < blen) { const v = b[p + 4]!; res = v & 0x80 ? 2 ** -(v & 0x7f) : 10 ** -(v & 0x7f); }
        p += 4 + ((len + 3) & ~3);
      }
      ifaces.push({ link, res });
      st.linkTypes.add(link);
    } else if ((type === 6 || type === 3) && blen >= 16) {
      const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
      const ifc = ifaces[type === 6 ? dv.getUint32(8, le) : 0];
      const dataStart = type === 6 ? 28 : 12;
      const cap = type === 6 ? (blen >= 32 ? dv.getUint32(20, le) : 0) : dv.getUint32(8, le);
      const orig = type === 6 ? (blen >= 32 ? dv.getUint32(24, le) : 0) : cap;
      if (!ifc) { st.skipped++; note(st, 'packet on unknown interface'); }
      else if (dataStart + cap + 4 > blen || cap > BUDGET.maxPacketBytes) { st.skipped++; note(st, 'pcapng packet length lie'); }
      else {
        const ts = type === 6 ? (dv.getUint32(12, le) * 4294967296 + dv.getUint32(16, le)) * ifc.res : 0;
        no++;
        yield { no, ts, capLen: cap, origLen: orig, linkType: ifc.link, recordOffset: off, dataOffset: off + dataStart, blockType: type === 6 ? 'EPB' : 'SPB', data: b.subarray(dataStart, dataStart + cap) };
      }
    }
    off += blen;
  }
}

/** Reads one packet's bytes at a known offset, for Investigator and the Source Locator. */
export const readPacket = (src: ByteSource, dataOffset: number, capLen: number) =>
  src.read(dataOffset, Math.min(capLen, BUDGET.maxPacketBytes));
