import { analyze, dissect, ENGINE_SCHEMA, followStream, Rejected, type Baseline, type ByteSource, type PacketRow } from '@packetmd/core';

// Runs under connect-src 'none': this file can read the File it was handed and post plain JSON back, nothing else.
const source = (f: File): ByteSource => ({ size: f.size, read: async (o, l) => new Uint8Array(await f.slice(o, o + l).arrayBuffer()) });
const post = (m: unknown) => (self as unknown as Worker).postMessage(m);

async function probe() {
  try { await fetch('/worker/analyze.js'); return false; } catch { return true; }
}

self.onmessage = async (e: MessageEvent) => {
  const m = e.data as { type: string; id?: number; file?: File; baseline?: Baseline; row?: PacketRow; rows?: { row: PacketRow; fromA: boolean; start: number }[] };
  try {
    if (m.type === 'hello') post({ type: 'ready', schema: ENGINE_SCHEMA, sandboxed: await probe() });
    if (m.type === 'analyze') {
      const report = await analyze(source(m.file!), m.file!.name, { baseline: m.baseline, onProgress: (done, total) => post({ type: 'progress', done, total }) });
      post({ type: 'done', report });
    }
    if (m.type === 'packet') {
      const r = m.row!, data = await source(m.file!).read(r.dataOffset, r.capLen);
      const { tree } = dissect({ no: r.no, ts: r.ts, capLen: r.capLen, origLen: r.len, linkType: r.linkType, recordOffset: r.recordOffset, dataOffset: r.dataOffset, data });
      post({ type: 'packet', id: m.id, tree, bytes: Array.from(data) });
    }
    if (m.type === 'stream') {
      const src = source(m.file!), chunks = [];
      for (const x of m.rows!) { const d = await src.read(x.row.dataOffset, x.row.capLen); chunks.push({ fromA: x.fromA, data: d.subarray(x.start) }); }
      post({ type: 'stream', id: m.id, ...followStream(chunks) });
    }
  } catch (err) {
    if (err instanceof Rejected) post({ type: 'rejected', gate: err.result });
    else post({ type: 'error', id: m.id, message: 'The analysis stopped safely on this file.' });
  }
};
