import { BUDGET } from './thresholds';
import type { Baseline, Pkt } from './types';

export interface Retrans { no: number; ts: number; gap: number; size: number; fast: boolean; fromA: boolean }
interface Dir { next: number; lastTs: number; lastAck: number; dup: number }

export interface Flow {
  id: string; proto: 'TCP' | 'UDP'; a: string; b: string; pa: number; pb: number;
  pkts: number; bytes: number; bytesAB: number; bytesBA: number; t0: number; t1: number; first: number;
  nos: number[];
  syn: { no: number; ts: number }[]; synAck: number[]; est: boolean; rst: { no: number; ts: number; fromA: boolean; early: boolean }[]; fin: boolean;
  retrans: Retrans[]; dup: number; zeroWin: number[]; rtt?: number; largeRetrans: number; maxOk: number; mss?: number;
  domain?: string; domainRank: number; domainSource?: string; domainPacket?: number; hiddenName?: 'ECH' | 'DoT' | 'DoH';
  dA: Dir; dB: Dir; ua?: string; ja3?: string; firstData?: number;
}

export interface MacSeen { mac: string; first: number; last: number; count: number; pkts: number[]; replies: number; unsolicited: number; announces: number }

export interface Ctx {
  pkts: Pkt[];
  flows: Flow[];
  evicted: number;
  ipMac: Map<string, Map<string, MacSeen>>;     // IP to claiming MACs, from ARP
  macIps: Map<string, Set<string>>;
  arpAsks: Map<string, number>;                 // who-has requests by "asker>target"
  dnsMap: Map<string, { name: string; no: number; exp: number }>;
  dhcpRouters: Map<string, number>;             // router option counts
  dhcpDns: Set<string>;
  gateways: Set<string>;
  baseline?: Baseline;
  get(no: number): Pkt;
}

const seqAfter = (a: number, b: number) => ((a - b) | 0) > 0;
const RANK = { dns: 1, host: 2, sni: 3 };

const isSynthetic = (ip: string) => ip === '0.0.0.0' || ip === '255.255.255.255';

export function buildContext(pkts: Pkt[], baseline?: Baseline): Ctx {
  const flowMap = new Map<string, Flow>();
  const ctx: Ctx = {
    pkts, flows: [], evicted: 0, ipMac: new Map(), macIps: new Map(), arpAsks: new Map(), dnsMap: new Map(),
    dhcpRouters: new Map(), dhcpDns: new Set(), gateways: new Set(), baseline,
    get: (no) => pkts[no - 1]!,
  };

  for (const p of pkts) {
    if (p.arp) observeArp(ctx, p);
    if (p.dhcp) {
      if (p.dhcp.router && (p.dhcp.msgType === 2 || p.dhcp.msgType === 5)) ctx.dhcpRouters.set(p.dhcp.router, (ctx.dhcpRouters.get(p.dhcp.router) ?? 0) + 1);
      if (p.dhcp.msgType === 5 || p.dhcp.msgType === 2) p.dhcp.dns.forEach((d) => ctx.dhcpDns.add(d));
    }
    if (p.dns?.qr && p.dns.kind === 'dns') {
      let cname = p.dns.qname;
      for (const a of p.dns.answers) {
        if (a.type === 5) continue;
        if ((a.type === 1 || a.type === 28) && a.data) ctx.dnsMap.set(a.data, { name: cname, no: p.no, exp: p.ts + a.ttl });
      }
    }
    if (p.src && p.dst && (p.tcp || p.udp)) track(ctx, flowMap, p);
    if (p.tcp?.flags === 4 || (p.tcp && p.tcp.flags & 4)) (p.flags ??= []).push('rst');
  }
  ctx.flows = [...flowMap.values()];
  // The busiest ARP-claimed DHCP router, or a conventional gateway address that others ask for.
  for (const [r] of ctx.dhcpRouters) ctx.gateways.add(r);
  for (const g of Object.keys(baseline?.gateways ?? {})) ctx.gateways.add(g);
  if (!ctx.gateways.size) for (const ip of ctx.ipMac.keys()) if (/\.(1|254)$/.test(ip)) ctx.gateways.add(ip);
  return ctx;
}

function observeArp(ctx: Ctx, p: Pkt) {
  const a = p.arp!;
  if (a.op === 1 && a.spa !== a.tpa && !isSynthetic(a.spa)) {
    const k = `${a.spa}>${a.tpa}`;
    ctx.arpAsks.set(k, (ctx.arpAsks.get(k) ?? 0) + 1);
  }
  if (isSynthetic(a.spa)) return;
  let m = ctx.ipMac.get(a.spa);
  if (!m) ctx.ipMac.set(a.spa, (m = new Map()));
  let s = m.get(a.sha);
  if (!s) m.set(a.sha, (s = { mac: a.sha, first: p.ts, last: p.ts, count: 0, pkts: [], replies: 0, unsolicited: 0, announces: 0 }));
  s.last = p.ts; s.count++;
  if (s.pkts.length < 200) s.pkts.push(p.no);
  if (a.spa === a.tpa) s.announces++;
  if (a.op === 2) {
    s.replies++;
    const k = `${a.tpa}>${a.spa}`, asks = ctx.arpAsks.get(k) ?? 0;
    if (asks > 0) ctx.arpAsks.set(k, asks - 1);
    else { s.unsolicited++; if (a.spa !== a.tpa) (p.flags ??= []).push('arp-unsolicited'); }
  }
  let ips = ctx.macIps.get(a.sha);
  if (!ips) ctx.macIps.set(a.sha, (ips = new Set()));
  ips.add(a.spa);
}

function flowOf(ctx: Ctx, map: Map<string, Flow>, p: Pkt): { f: Flow; fromA: boolean } {
  const sp = p.tcp?.sport ?? p.udp!.sport, dp = p.tcp?.dport ?? p.udp!.dport, proto = p.tcp ? 'TCP' : 'UDP';
  const k1 = `${proto}|${p.src}:${sp}|${p.dst}:${dp}`, k2 = `${proto}|${p.dst}:${dp}|${p.src}:${sp}`;
  let f = map.get(k1);
  if (f) return { f, fromA: true };
  f = map.get(k2);
  if (f) return { f, fromA: false };
  if (map.size >= BUDGET.maxFlows) { const oldest = map.keys().next().value!; map.delete(oldest); ctx.evicted++; }
  const d = (): Dir => ({ next: 0, lastTs: 0, lastAck: -1, dup: 0 });
  f = {
    id: `c${map.size + ctx.evicted + 1}`, proto: proto as Flow['proto'], a: p.src!, b: p.dst!, pa: sp, pb: dp,
    pkts: 0, bytes: 0, bytesAB: 0, bytesBA: 0, t0: p.ts, t1: p.ts, first: p.no, nos: [], syn: [], synAck: [], est: false, rst: [], fin: false,
    retrans: [], dup: 0, zeroWin: [], largeRetrans: 0, maxOk: 0, domainRank: 0, dA: d(), dB: d(),
  };
  map.set(k1, f);
  const hit = ctx.dnsMap.get(p.dst!);
  if (hit && hit.exp >= p.ts) setDomain(f, hit.name, 'DNS answer', hit.no, RANK.dns);
  if (proto === 'TCP' && (dp === 853 || sp === 853)) f.hiddenName = 'DoT';
  return { f, fromA: true };
}

function setDomain(f: Flow, name: string, source: string, no: number, rank: number) {
  if (rank > f.domainRank) { f.domain = name; f.domainSource = source; f.domainPacket = no; f.domainRank = rank; }
}

function track(ctx: Ctx, map: Map<string, Flow>, p: Pkt) {
  const { f, fromA } = flowOf(ctx, map, p);
  f.pkts++; f.bytes += p.len; f.t1 = p.ts;
  if (f.nos.length < 20000) f.nos.push(p.no);
  if (fromA) f.bytesAB += p.len; else f.bytesBA += p.len;
  (p as Pkt & { flow?: string }).flow = f.id;
  if (p.tls?.sni) setDomain(f, p.tls.sni, 'TLS SNI', p.no, RANK.sni);
  if (p.tls?.ech && !p.tls.sni) f.hiddenName = 'ECH';
  if (p.tls?.ja3) f.ja3 = p.tls.ja3;
  if (p.http?.host) setDomain(f, p.http.host, 'HTTP Host header', p.no, RANK.host);
  if (p.http?.ua) f.ua = p.http.ua;
  const t = p.tcp;
  if (!t) return;
  const me = fromA ? f.dA : f.dB, syn = !!(t.flags & 2), ack = !!(t.flags & 16), rst = !!(t.flags & 4);
  if (syn && !ack) {
    if (f.syn.length && f.syn[0]!.no !== p.no) (p.flags ??= []).push('retransmit');
    f.syn.push({ no: p.no, ts: p.ts });
    if (t.mss) f.mss = t.mss;
  }
  if (syn && ack) { f.synAck.push(p.no); if (f.syn.length && f.rtt === undefined) f.rtt = p.ts - f.syn[0]!.ts; }
  if (!syn && ack && !rst && f.synAck.length) f.est = true;
  if (rst) f.rst.push({ no: p.no, ts: p.ts, fromA, early: !f.est });
  if (t.flags & 1) f.fin = true;
  if (t.win === 0 && !rst && !syn) { f.zeroWin.push(p.no); (p.flags ??= []).push('zerowin'); }
  if (t.payload > 0) {
    if (f.firstData === undefined) f.firstData = p.ts;
    const end = (t.seq + t.payload) | 0;
    if (me.next !== 0 && !seqAfter(end, me.next)) {
      const other = fromA ? f.dB : f.dA;
      f.retrans.push({ no: p.no, ts: p.ts, gap: p.ts - me.lastTs, size: p.len, fast: other.dup >= 3, fromA });
      (p.flags ??= []).push('retransmit');
      if (p.len >= 1400 && p.df) f.largeRetrans++;
    } else {
      me.next = end;
      if (p.len > f.maxOk) f.maxOk = p.len;
    }
    me.lastTs = p.ts;
    me.dup = 0;
  } else if (ack && !syn && !rst) {
    if (me.lastAck === t.ack) { me.dup++; f.dup++; if (me.dup >= 3) (p.flags ??= []).push('dupack'); }
    else me.dup = 0;
  }
  me.lastAck = t.ack;
}

export function baselineOf(ctx: Ctx): Baseline {
  const gateways: Record<string, string> = {}, ipMac: Record<string, string> = {};
  for (const [ip, macs] of ctx.ipMac) {
    const best = [...macs.values()].sort((a, b) => b.count - a.count)[0]!;
    ipMac[ip] = best.mac;
    if (ctx.gateways.has(ip)) gateways[ip] = best.mac;
  }
  const dhcpServers = [...new Set(ctx.pkts.filter((p) => p.dhcp?.server).map((p) => p.dhcp!.server!))];
  const resolvers = [...new Set(ctx.pkts.filter((p) => p.dns?.kind === 'dns' && !p.dns.qr).map((p) => p.dst!))];
  return { gateways, dhcpServers, resolvers, ipMac };
}
