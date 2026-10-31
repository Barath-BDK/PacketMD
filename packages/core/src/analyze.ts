import { BUDGET } from './thresholds';
import { Sha256 } from './hash';
import { gate, type GateResult } from './parse/intake';
import { newStats, note, parsePcap, parsePcapng } from './parse/reader';
import { decode } from './decode/decode';
import { baselineOf, buildContext, type Ctx } from './context';
import { runDetectors } from './detect/detectors';
import { cluster, decide } from './verdict/engine';
import { chain, headline, toFinding } from './explain/finding';
import { attribute } from './attribute';
import { ENGINE_SCHEMA, type Baseline, type ByteSource, type HostRow, type Pkt, type Report } from './types';

export class Rejected extends Error { constructor(public result: GateResult) { super(result.reason); } }

const SUPPORTED = new Set([0, 1, 101, 113]);

export interface Options { baseline?: Baseline; onProgress?: (done: number, total: number) => void }

async function sha(src: ByteSource) {
  const h = new Sha256();
  for (let o = 0; o < src.size; o += BUDGET.chunkBytes) h.update(await src.read(o, Math.min(BUDGET.chunkBytes, src.size - o)));
  return h.digest();
}

export async function analyze(src: ByteSource, fileName: string, opts: Options = {}): Promise<Report> {
  const start = Date.now();
  const res = gate(fileName, src.size, await src.read(0, Math.min(16, src.size)));
  if (!res.ok) throw new Rejected(res);
  const stats = newStats(res.format!);
  const iter = res.format === 'pcap' ? parsePcap(src, stats) : parsePcapng(src, stats);
  const pkts: Pkt[] = [];
  const unsupported = new Set<number>();
  let lastTick = 0;
  for await (const raw of iter) {
    if (Date.now() - start > BUDGET.maxParseMs) { stats.truncated = true; note(stats, 'time budget reached'); break; }
    if (!SUPPORTED.has(raw.linkType)) { unsupported.add(raw.linkType); stats.skipped++; continue; }
    try { pkts.push(decode(raw)); }
    catch { stats.skipped++; note(stats, 'packet failed to decode'); }
    if (raw.no - lastTick >= 20000) { lastTick = raw.no; opts.onProgress?.(raw.dataOffset, src.size); }
  }
  // Worked on a contiguous list: get() indexes by no, so renumber after any skip.
  pkts.forEach((p, i) => { p.no = i + 1; });
  const ctx = buildContext(pkts, opts.baseline);
  const cases = cluster(runDetectors(ctx, stats.anomalies)).map(decide);
  const findings = cases.map((c, i) => toFinding(ctx, c, i + 1)).filter((f) => f !== null);
  chain(findings);
  findings.forEach((f, i) => { f.id = `F${i + 1}`; });

  const parseMs = Date.now() - start;
  const report: Report = {
    schema: ENGINE_SCHEMA,
    defense: {
      fileName: res.name, size: src.size, sha256: await sha(src), format: res.format!, linkTypes: [...stats.linkTypes], packets: pkts.length,
      skipped: stats.skipped, anomalies: Object.fromEntries(stats.anomalies), truncated: stats.truncated, unsupportedLink: unsupported.size > 0, parseMs,
      checks: [
        ...res.steps.map((s) => ({ label: s.label, ok: s.ok, detail: s.detail })),
        { label: 'Packet budget', ok: pkts.length <= BUDGET.maxPackets, detail: `${pkts.length} of ${BUDGET.maxPackets}` },
        { label: 'Structure', ok: !stats.truncated, detail: stats.truncated ? `Stopped safely: ${[...stats.anomalies.keys()][0] ?? 'file ends early'}` : 'Every record boundary was valid' },
        { label: 'Link type', ok: !unsupported.size, detail: unsupported.size ? `Link type ${[...unsupported][0]} is not supported, for example 802.11. Those packets were skipped.` : 'Supported' },
        { label: 'Payload handling', ok: true, detail: 'Raw bytes stayed inside the sandboxed Worker' },
      ],
    },
    headline: headline(findings),
    findings,
    ...summarise(ctx),
    baseline: baselineOf(ctx),
  };
  return report;
}

function summarise(ctx: Ctx) {
  const { pkts, flows } = ctx;
  const t0 = pkts[0]?.ts ?? 0, t1 = pkts.at(-1)?.ts ?? 0;
  const hosts = new Map<string, HostRow>();
  const proto = new Map<string, { name: string; pkts: number; bytes: number }>();
  const dur = Math.max(t1 - t0, 0.001), step = Math.max(dur / 120, 0.001);
  const bins = Array.from({ length: Math.ceil(dur / step) + 1 }, (_, i) => ({ t: t0 + i * step, pkts: 0, bytes: 0, bad: 0 }));
  const touch = (ip: string, ts: number) => {
    let h = hosts.get(ip);
    if (!h) hosts.set(ip, (h = { ip, macs: [], names: [], pkts: 0, bytesIn: 0, bytesOut: 0, role: 'Host', firstSeen: ts, lastSeen: ts }));
    h.lastSeen = ts;
    return h;
  };
  for (const p of pkts) {
    const b = bins[Math.min(bins.length - 1, Math.floor((p.ts - t0) / step))];
    if (b) { b.pkts++; b.bytes += p.len; if (p.flags?.length || p.anomalies?.length) b.bad++; }
    const e = proto.get(p.proto) ?? { name: p.proto, pkts: 0, bytes: 0 };
    e.pkts++; e.bytes += p.len; proto.set(p.proto, e);
    if (p.src && p.src !== '0.0.0.0') {
      const h = touch(p.src, p.ts);
      h.pkts++; h.bytesOut += p.len;
      if (p.srcMac && !h.macs.includes(p.srcMac) && h.macs.length < 6) h.macs.push(p.srcMac);
    }
    if (p.dst && !/^(255\.|224\.|ff)/.test(p.dst) && p.dst !== '0.0.0.0') { const h = touch(p.dst, p.ts); h.pkts++; h.bytesIn += p.len; }
    if (p.dhcp?.hostname && p.src) { const h = touch(p.src, p.ts); if (!h.names.includes(p.dhcp.hostname)) h.names.push(p.dhcp.hostname); }
  }
  for (const g of ctx.gateways) if (hosts.has(g)) hosts.get(g)!.role = 'Gateway';
  for (const p of pkts) {
    if (p.dhcp?.server && hosts.has(p.dhcp.server) && hosts.get(p.dhcp.server)!.role === 'Host') hosts.get(p.dhcp.server)!.role = 'DHCP server';
    if (p.dns?.qr && p.dns.kind === 'dns' && hosts.has(p.src!) && hosts.get(p.src!)!.role === 'Host') hosts.get(p.src!)!.role = 'DNS server';
  }
  const conversations = flows.slice().sort((a, b) => b.bytes - a.bytes).slice(0, 5000).map((f) => ({
    id: f.id, proto: f.proto, a: f.a, b: f.b, aPort: f.pa, bPort: f.pb, pkts: f.pkts, bytes: f.bytes, t0: f.t0, t1: f.t1,
    state: f.proto === 'UDP' ? 'datagram' : f.rst.length ? 'reset' : f.est ? (f.fin ? 'closed' : 'open') : f.synAck.length ? 'half-open' : 'no answer',
    domain: f.domain, domainSource: f.domainSource, domainPacket: f.domainPacket,
  }));
  const domainOf = new Map<string, string>();
  flows.forEach((f) => { if (f.domain) domainOf.set(f.b, f.domain); });
  const rows = pkts.map((p) => ({
    no: p.no, ts: p.ts, src: p.src ?? p.srcMac ?? '', dst: p.dst ?? p.dstMac ?? '', proto: p.proto, len: p.len, info: p.info, capLen: p.capLen,
    recordOffset: p.recordOffset, dataOffset: p.dataOffset, blockType: p.blockType, flags: p.flags, sport: p.tcp?.sport ?? p.udp?.sport, dport: p.tcp?.dport ?? p.udp?.dport,
    srcMac: p.srcMac, dstMac: p.dstMac, linkType: 1, domain: p.dst ? domainOf.get(p.dst) : undefined, qname: p.dns?.qname,
  }));
  return {
    hosts: [...hosts.values()].sort((a, b) => b.pkts - a.pkts).slice(0, 2000), conversations,
    activity: attribute(ctx), protocols: [...proto.values()].sort((a, b) => b.pkts - a.pkts), timeline: bins, t0, t1, rows,
  };
}
