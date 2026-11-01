import { T } from '../thresholds';
import type { Ctx } from '../context';
import type { Candidate, Pkt } from '../types';

const isPrivate = (ip: string) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(ip);

const sig = (id: string, label: string, weights: Record<string, number>, packets: number[]) => ({ id, label, weights, packets: packets.slice(0, 40) });
function span(ctx: Ctx, nos: number[]) {
  let t0 = Infinity, t1 = -Infinity;
  for (const n of nos) { const t = ctx.get(n).ts; if (t < t0) t0 = t; if (t > t1) t1 = t; }
  return { t0, t1 };
}
function group<K>(items: Pkt[], key: (p: Pkt) => K | null) {
  const m = new Map<K, Pkt[]>();
  for (const p of items) { const k = key(p); if (k === null) continue; const l = m.get(k); if (l) l.push(p); else m.set(k, [p]); }
  return m;
}
const scanCand = (ctx: Ctx, src: string, target: string, mode: string, ports: number, hosts: number, nos: number[], label: string): Candidate => ({
  detector: 'scan', topic: 'scan', hypotheses: ['port-scan'], hosts: [src], ...span(ctx, nos), evidence: nos.slice(0, 40),
  signals: [sig('sweep', label, { 'port-scan': 4, benign: -1.5 }, nos)], benign: [],
  facts: { source: src, target, targetIp: '', mode, ports, hosts, open: [] },
});

/** Scans that never send a SYN, or do not use TCP at all, so the handshake-based detector cannot see them. */
export function otherScans(ctx: Ctx): Candidate[] {
  const out: Candidate[] = [];
  const stealth = ctx.pkts.filter((p) => p.tcp && !(p.tcp.flags & 0x16)); // no SYN, ACK or RST
  for (const [key, ps] of group(stealth, (p) => `${p.src}|${p.dst}`)) {
    const ports = new Set(ps.map((p) => p.tcp!.dport));
    if (ports.size < T.SCAN_PORTS_MIN) continue;
    const [src, dst] = key.split('|') as [string, string];
    out.push(scanCand(ctx, src, dst, 'stealth', ports.size, 1, ps.map((p) => p.no), `${src} sent ${ps.length} TCP packets with no SYN to ${ports.size} ports on ${dst}. Normal software never does this: it maps ports while avoiding connection logs.`));
  }
  const udp = ctx.pkts.filter((p) => p.udp && !p.dns?.qr && p.udp.sport !== 53 && p.udp.sport !== 123 && p.udp.dport < 49152);
  for (const [key, ps] of group(udp, (p) => `${p.src}|${p.dst}`)) {
    const ports = new Set(ps.map((p) => p.udp!.dport));
    if (ports.size < T.SCAN_PORTS) continue;
    const [src, dst] = key.split('|') as [string, string];
    out.push(scanCand(ctx, src, dst, 'UDP', ports.size, 1, ps.map((p) => p.no), `${src} sent UDP to ${ports.size} ports on ${dst}.`));
  }
  // ACK probes map firewall rules. They belong to no connection, so each is a tiny flow with no handshake.
  const ack = new Map<string, Ctx['flows']>();
  for (const f of ctx.flows) if (f.proto === 'TCP' && !f.syn.length && !f.synAck.length && f.pkts <= 2 && (!f.bytesBA || f.rst.some((r) => !r.fromA))) { const k = `${f.a}|${f.b}`, l = ack.get(k); if (l) l.push(f); else ack.set(k, [f]); }
  for (const [key, fs] of ack) {
    const ports = new Set(fs.map((f) => f.pb));
    if (ports.size < T.SCAN_PORTS) continue;
    const [src, dst] = key.split('|') as [string, string];
    out.push(scanCand(ctx, src, dst, 'ACK', ports.size, 1, fs.map((f) => f.first), `${src} sent lone ACK packets to ${ports.size} ports on ${dst} with no connection behind them, which maps firewall rules.`));
  }
  const pings = ctx.pkts.filter((p) => p.icmp?.type === 8);
  for (const [src, ps] of group(pings, (p) => p.src ?? null)) {
    const hosts = new Set(ps.map((p) => p.dst));
    if (hosts.size >= T.SWEEP_HOSTS) out.push(scanCand(ctx, src, `${hosts.size} hosts`, 'ping sweep', 1, hosts.size, ps.map((p) => p.no), `${src} pinged ${hosts.size} different addresses, mapping which hosts are alive.`));
  }
  const asks = ctx.pkts.filter((p) => p.arp?.op === 1 && p.arp.spa !== p.arp.tpa);
  for (const [src, ps] of group(asks, (p) => p.arp!.sha)) {
    const hosts = new Set(ps.map((p) => p.arp!.tpa));
    if (hosts.size >= T.ARP_SWEEP_HOSTS) out.push(scanCand(ctx, ps[0]!.arp!.spa, `${hosts.size} hosts`, 'ARP sweep', 1, hosts.size, ps.map((p) => p.no), `${src} asked for ${hosts.size} addresses over ARP, sweeping the subnet.`));
  }
  return out;
}

/** One device pretending to be many clients to empty the address pool. */
export function dhcpStarvation(ctx: Ctx): Candidate[] {
  const ask = ctx.pkts.filter((p) => p.dhcp?.msgType === 1), macs = new Set(ask.map((p) => p.dhcp!.chaddr));
  const done = new Set(ctx.pkts.filter((p) => p.dhcp?.msgType === 3).map((p) => p.dhcp!.chaddr));
  const finished = [...macs].filter((m) => done.has(m)).length;
  if (macs.size < T.DHCP_STARVE_MACS || finished / macs.size > 0.5) return [];
  const nos = ask.map((p) => p.no);
  return [{
    detector: 'dhcp', topic: 'dhcp-starve', hypotheses: ['dhcp-starvation'], hosts: [ask[0]!.srcMac ?? ''], ...span(ctx, nos), evidence: nos.slice(0, 40),
    signals: [sig('many-macs', `${macs.size} different devices asked for an address and only ${finished} finished, the mark of invented identities.`, { 'dhcp-starvation': 4, benign: -2 }, nos)], benign: [],
    facts: { clients: macs.size, finished },
  }];
}

/** RST frames whose source MAC differs from the rest of that side of the connection. */
export function rstInjection(ctx: Ctx): Candidate[] {
  const flows = ctx.flows.filter((f) => f.forgedRst.length);
  if (!flows.length) return [];
  const nos = flows.flatMap((f) => f.forgedRst), f0 = flows[0]!, p0 = ctx.get(nos[0]!);
  return [{
    detector: 'tcp', topic: 'tcp-integrity', hypotheses: ['rst-injection'], hosts: [f0.a, f0.b], ...span(ctx, nos), evidence: nos.slice(0, 40),
    signals: [sig('wrong-mac', `${nos.length} resets claimed to come from ${p0.src} but arrived from a different MAC (${p0.srcMac}) than the rest of that connection.`, { 'rst-injection': 4, 'tcp-reset': -2, benign: -2 }, nos)], benign: [],
    facts: { victim: p0.dst ?? '', peer: p0.src ?? '', mac: p0.srcMac ?? '', count: nos.length },
  }];
}

export function icmpRedirect(ctx: Ctx): Candidate[] {
  const bad = ctx.pkts.filter((p) => p.icmp?.type === 5 && !ctx.gateways.has(p.src ?? ''));
  if (!bad.length) return [];
  const nos = bad.map((p) => p.no), p0 = bad[0]!;
  return [{
    detector: 'icmp', topic: 'redirect', hypotheses: ['icmp-redirect'], hosts: [p0.src ?? '', p0.dst ?? ''], ...span(ctx, nos), evidence: nos.slice(0, 40),
    signals: [sig('non-gw', `${p0.src} told ${p0.dst} to change its route, but only the gateway should ever send that.`, { 'icmp-redirect': 4, benign: -2 }, nos)], benign: [],
    facts: { source: p0.src ?? '', victim: p0.dst ?? '', mac: p0.srcMac ?? '', count: bad.length },
  }];
}

const AUTH_PORTS = new Set([21, 22, 23, 445, 1433, 3306, 3389, 5900]);
const VPN_PORTS = new Set([500, 1194, 4500, 51820]);
const AMPLIFIERS = new Set([19, 53, 123, 161, 389, 1900, 11211]);

export function bruteForce(ctx: Ctx): Candidate[] {
  const groups = new Map<string, Ctx['flows']>();
  for (const f of ctx.flows) if (f.proto === 'TCP' && f.est && AUTH_PORTS.has(f.pb) && f.bytes < T.BRUTE_MAX_BYTES) { const k = `${f.a}|${f.b}|${f.pb}`, l = groups.get(k); if (l) l.push(f); else groups.set(k, [f]); }
  const out: Candidate[] = [];
  for (const [key, fs] of groups) {
    if (fs.length < T.BRUTE_MIN) continue;
    const [src, dst, port] = key.split('|') as [string, string, string], nos = fs.map((f) => f.first);
    out.push({
      detector: 'auth', topic: 'brute', hypotheses: ['brute-force'], hosts: [src, dst], ...span(ctx, nos), evidence: nos.slice(0, 40),
      signals: [sig('repeats', `${src} opened ${fs.length} short connections to the login service on ${dst} port ${port}, each ending almost at once.`, { 'brute-force': 4, benign: -2 }, nos)], benign: [],
      facts: { source: src, target: dst, port: Number(port), count: fs.length },
    });
  }
  const targets = new Map<string, Ctx['flows']>();
  for (const fs of groups.values()) { const f = fs[0]!, k = `${f.b}|${f.pb}`, l = targets.get(k); if (l) for (const x of fs) l.push(x); else targets.set(k, [...fs]); }
  for (const [key, fs] of targets) {
    const sources = new Set(fs.map((f) => f.a)).size;
    if (sources < T.BRUTE_SOURCES) continue;
    const [dst, port] = key.split('|') as [string, string], nos = fs.map((f) => f.first);
    out.push({
      detector: 'auth', topic: 'brute', hypotheses: ['brute-force'], hosts: [dst], ...span(ctx, nos), evidence: nos.slice(0, 40),
      signals: [sig('many-sources', `${sources} different hosts each made a short attempt at the login service on ${dst} port ${port}.`, { 'brute-force': 4, benign: -2 }, nos)], benign: [],
      facts: { source: `${sources} hosts`, target: dst, port: Number(port), count: fs.length, multi: 1 },
    });
  }
  return out;
}

export function floods(ctx: Ctx): Candidate[] {
  const hits = ctx.pkts.filter((p) => p.dst && !p.dst.startsWith('224.') && !p.dst.startsWith('ff') && !p.dst.endsWith('.255') && (p.icmp?.type === 8 || (p.udp && p.udp.sport !== 443 && !AMPLIFIERS.has(p.udp.sport) && !AMPLIFIERS.has(p.udp.dport))));
  const sent = new Map<string, number>();
  for (const p of ctx.pkts) if (p.src && (p.udp || p.icmp)) sent.set(p.src, (sent.get(p.src) ?? 0) + 1);
  const out: Candidate[] = [];
  for (const [dst, ps] of group(hits, (p) => p.dst!)) {
    const secs = ps[ps.length - 1]!.ts - ps[0]!.ts, pps = ps.length / Math.max(secs, 0.001), replies = sent.get(dst) ?? 0;
    if (ps.length < T.FLOOD_PKTS || pps < T.FLOOD_PPS || replies > ps.length * T.FLOOD_REPLY_RATIO) continue;
    const nos = ps.map((p) => p.no), srcs = new Set(ps.map((p) => p.src));
    out.push({
      detector: 'volume', topic: 'flood', hypotheses: ['udp-flood'], hosts: [dst], ...span(ctx, nos), evidence: nos.slice(0, 40),
      signals: [sig('one-way-rate', `${dst} received ${ps.length} packets at ${Math.round(pps)} a second and sent ${replies} back.`, { 'udp-flood': 4, benign: -2 }, nos)], benign: [],
      facts: { target: dst, count: ps.length, pps: Math.round(pps), sources: srcs.size, peer: ps[0]!.src ?? '', replies, kind: ps[0]!.udp ? 'UDP' : 'ping' },
    });
  }
  return out;
}

export function reflection(ctx: Ctx): Candidate[] {
  const out: Candidate[] = [];
  const asked = new Set<string>(), owners = new Map<string, Set<string>>();
  for (const p of ctx.pkts) {
    if (p.udp && AMPLIFIERS.has(p.udp.dport)) asked.add(`${p.src}|${p.dst}`);
    if (p.src && p.srcMac && !p.dstMac?.startsWith('ff:ff')) (owners.get(p.src) ?? owners.set(p.src, new Set()).get(p.src)!).add(p.srcMac);
  }
  const hits = ctx.pkts.filter((p) => p.udp && AMPLIFIERS.has(p.udp.sport) && p.dst && !asked.has(`${p.dst}|${p.src}`));
  for (const [dst, ps] of group(hits, (p) => p.dst!)) {
    if (ps.length < T.REFLECT_PKTS) continue;
    const nos = ps.map((p) => p.no), srcs = new Set(ps.map((p) => p.src));
    out.push({
      detector: 'volume', topic: 'reflection', hypotheses: ['reflection'], hosts: [dst], ...span(ctx, nos), evidence: nos.slice(0, 40),
      signals: [sig('unasked', `${dst} got ${ps.length} replies from ${srcs.size} servers on port ${ps[0]!.udp!.sport} with no request in the capture.`, { reflection: 4, benign: -2 }, nos)], benign: [],
      facts: { target: dst, count: ps.length, sources: srcs.size, via: `port ${ps[0]!.udp!.sport}` },
    });
  }
  const smurf = ctx.pkts.filter((p) => p.icmp?.type === 8 && p.src && p.srcMac && (p.dstMac?.startsWith('ff:ff') || p.dst?.endsWith('.255')) && owners.has(p.src) && !owners.get(p.src)!.has(p.srcMac));
  for (const [src, ps] of group(smurf, (p) => p.src!)) {
    if (ps.length < T.SMURF_PKTS) continue;
    const nos = ps.map((p) => p.no);
    out.push({
      detector: 'volume', topic: 'reflection', hypotheses: ['reflection'], hosts: [src], ...span(ctx, nos), evidence: nos.slice(0, 40),
      signals: [sig('smurf', `${ps[0]!.srcMac} sent ${ps.length} pings to the broadcast address using the address of ${src}, so every host answers ${src}.`, { reflection: 4, benign: -2 }, nos)], benign: [],
      facts: { target: src, count: ps.length, sources: 1, via: 'broadcast ping' },
    });
  }
  return out;
}

export function slowloris(ctx: Ctx): Candidate[] {
  const by = new Map<string, Ctx['flows']>();
  for (const f of ctx.flows) if (f.proto === 'TCP' && f.est && !f.fin && !f.rst.length && f.pkts <= 8 && f.bytesBA < 200) { const k = `${f.b}|${f.pb}`, l = by.get(k); if (l) l.push(f); else by.set(k, [f]); }
  const out: Candidate[] = [];
  for (const [key, fs] of by) {
    if (fs.length < T.SLOW_CONNS) continue;
    const [dst, port] = key.split('|') as [string, string], nos = fs.map((f) => f.first);
    out.push({
      detector: 'volume', topic: 'slowloris', hypotheses: ['slowloris'], hosts: [dst], ...span(ctx, nos), evidence: nos.slice(0, 40),
      signals: [sig('idle', `${fs.length} connections to ${dst} port ${port} were opened, got no answer, and were never closed.`, { slowloris: 4, benign: -2 }, nos)], benign: [],
      facts: { target: dst, port: Number(port), count: fs.length, sources: new Set(fs.map((f) => f.a)).size },
    });
  }
  return out;
}

export function rogueRouter(ctx: Ctx): Candidate[] {
  const ras = ctx.pkts.filter((p) => p.icmp6 === 134 && p.srcMac);
  if (!ras.length) return [];
  const toNet = new Map<string, number>();
  for (const p of ctx.pkts) if (p.dst && p.dstMac && p.ipv === 4 && !isPrivate(p.dst) && !p.dst.startsWith('224.') && !p.dstMac.startsWith('ff:ff')) toNet.set(p.dstMac, (toNet.get(p.dstMac) ?? 0) + 1);
  const gateway = [...toNet].sort((a, b) => b[1] - a[1])[0]?.[0] ?? '';
  const byMac = group(ras, (p) => p.srcMac!), out: Candidate[] = [];
  for (const [mac, ps] of byMac) {
    if (mac === gateway || (!gateway && byMac.size < 2)) continue;
    const nos = ps.map((p) => p.no);
    out.push({
      detector: 'rogue', topic: 'rogue-ra', hypotheses: ['rogue-ra'], hosts: [ps[0]!.src ?? mac], ...span(ctx, nos), evidence: nos.slice(0, 40),
      signals: [sig('not-gateway', `${mac} sent router advertisements${gateway ? `, but traffic leaves through ${gateway}` : ' alongside another router'}.`, { 'rogue-ra': 3.5, benign: -2 }, nos)], benign: [],
      facts: { mac, gateway, count: ps.length },
    });
  }
  return out;
}

/** Weak on purpose: provider QinQ links carry double tags legitimately. */
export function vlanHopping(ctx: Ctx): Candidate[] {
  const out: Candidate[] = [];
  for (const [mac, ps] of group(ctx.pkts.filter((p) => p.vlanDepth && p.srcMac), (p) => p.srcMac!)) {
    if (ps.length < T.VLAN_DOUBLE) continue;
    const nos = ps.map((p) => p.no);
    out.push({
      detector: 'rogue', topic: 'vlan', hypotheses: ['vlan-hopping'], hosts: [ps[0]!.src ?? mac], ...span(ctx, nos), evidence: nos.slice(0, 40),
      signals: [sig('double-tag', `${mac} sent ${ps.length} frames with two VLAN tags.`, { 'vlan-hopping': 1.2 }, nos)], benign: [],
      facts: { mac, count: ps.length, vlan: ps[0]!.vlan ?? 0 },
    });
  }
  return out;
}

export function landAttack(ctx: Ctx): Candidate[] {
  const ps = ctx.pkts.filter((p) => p.src && p.src === p.dst && (p.tcp || p.udp) && !p.src.startsWith('127.') && p.src !== '::1');
  if (!ps.length) return [];
  const nos = ps.map((p) => p.no);
  return [{
    detector: 'evasion', topic: 'evasion', hypotheses: ['parser-evasion'], hosts: [ps[0]!.src!], ...span(ctx, nos), evidence: nos.slice(0, 40),
    signals: [sig('land', `${ps.length} packets name ${ps[0]!.src} as both sender and receiver, which no normal stack sends.`, { 'parser-evasion': 3.5, benign: -2 }, nos)], benign: [],
    facts: { host: ps[0]!.src!, count: ps.length, kinds: 'same source and destination' },
  }];
}

export function icmpTunnel(ctx: Ctx): Candidate[] {
  const big = ctx.pkts.filter((p) => (p.icmp?.type === 8 || p.icmp?.type === 0) && p.len >= T.ICMP_TUNNEL_BYTES);
  const out: Candidate[] = [];
  for (const [key, ps] of group(big, (p) => [p.src, p.dst].sort().join('|'))) {
    if (ps.length < T.ICMP_TUNNEL_MIN || new Set(ps.map((p) => p.icmp!.tail)).size < 2) continue;
    const req = ps.find((p) => p.icmp!.type === 8) ?? ps[0]!, nos = ps.map((p) => p.no);
    out.push({
      detector: 'icmp', topic: `icmp-tunnel-${key}`, hypotheses: ['icmp-tunnel'], hosts: [req.src ?? '', req.dst ?? ''], ...span(ctx, nos), evidence: nos.slice(0, 40),
      signals: [sig('big-pings', `${ps.length} large ping packets carried changing data. A real ping repeats one pattern and gets the same bytes back.`, { 'icmp-tunnel': 3.5, benign: -2 }, nos)], benign: [],
      facts: { host: req.src ?? '', peer: req.dst ?? '', count: ps.length, size: req.len },
    });
  }
  return out;
}

export function loginGuessing(ctx: Ctx): Candidate[] {
  const posts = ctx.pkts.filter((p) => p.http?.method === 'POST' && /log.?in|sign.?in|auth|wp-login|token|session/i.test(p.http.path));
  const out: Candidate[] = [];
  for (const [key, ps] of group(posts, (p) => `${p.src}|${p.dst}|${p.tcp?.dport}`)) {
    if (ps.length < T.LOGIN_POSTS || (ps[ps.length - 1]!.ts - ps[0]!.ts) / (ps.length - 1) > T.LOGIN_GAP_S) continue;
    const [src, dst, port] = key.split('|') as [string, string, string], nos = ps.map((p) => p.no);
    out.push({
      detector: 'auth', topic: 'brute', hypotheses: ['brute-force'], hosts: [src, dst], ...span(ctx, nos), evidence: nos.slice(0, 40),
      signals: [sig('login-posts', `${src} sent ${ps.length} login requests to ${ps[0]!.http!.path} on ${dst}.`, { 'brute-force': 4, benign: -2 }, nos)], benign: [],
      facts: { source: src, target: dst, port: Number(port), count: ps.length },
    });
  }
  return out;
}

export function udpBeacon(ctx: Ctx): Candidate[] {
  const out: Candidate[] = [];
  const out0 = ctx.pkts.filter((p) => p.udp && p.src && p.dst && p.ipv === 4 && !isPrivate(p.dst) && ![53, 123, 67, 68].includes(p.udp.dport) && !p.dst.startsWith('224.'));
  for (const [key, ps] of group(out0, (p) => `${p.src}|${p.dst}|${p.udp!.dport}`)) {
    if (ps.length < T.BEACON_MIN) continue;
    const gaps = ps.slice(1).map((p, i) => p.ts - ps[i]!.ts), mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    const sd = Math.sqrt(gaps.reduce((a, x) => a + (x - mean) ** 2, 0) / gaps.length);
    if (mean < T.BEACON_MIN_S || sd / mean > T.BEACON_JITTER_NO_NAME) continue;
    const [src, dst, port] = key.split('|') as [string, string, string], nos = ps.map((p) => p.no);
    out.push({
      detector: 'behaviour', topic: 'beacon', hypotheses: ['beaconing'], hosts: [src, dst], ...span(ctx, nos), evidence: nos.slice(0, 40),
      // A VPN keepalive is timed the same way, so on those ports this can only raise a question.
      signals: [sig('udp-rhythm', `${src} sent UDP to ${dst} ${ps.length} times, about every ${mean.toFixed(1)} s, with no name to explain it.${VPN_PORTS.has(Number(port)) ? ' This port is also used by VPN keepalives.' : ''}`, VPN_PORTS.has(Number(port)) ? { beaconing: 1.2 } : { beaconing: 3.5, benign: -1.5 }, nos)], benign: [],
      facts: { host: src, peer: dst, port: Number(port), every: +mean.toFixed(1), count: ps.length, domain: '' },
    });
  }
  return out;
}

/** Deliberately weak: a backup looks identical, so this can only ever raise a question. */
export function exfil(ctx: Ctx): Candidate[] {
  const out: Candidate[] = [];
  for (const f of ctx.flows) {
    if (f.bytesAB < T.EXFIL_MIN || f.bytesAB < f.bytesBA * T.LARGE_UPLOAD_RATIO || isPrivate(f.b)) continue;
    out.push({
      detector: 'behaviour', topic: 'exfil', hypotheses: ['data-exfil'], hosts: [f.a, f.b], t0: f.t0, t1: f.t1, evidence: f.nos.slice(0, 40),
      signals: [sig('one-way', `${f.a} sent ${Math.round(f.bytesAB / 1024)} KB to ${f.domain ?? f.b} and got ${Math.round(f.bytesBA / 1024)} KB back.`, { 'data-exfil': 1.2 }, f.nos)], benign: [],
      facts: { host: f.a, peer: f.b, port: f.pb, up: f.bytesAB, down: f.bytesBA, mb: +(f.bytesAB / 1048576).toFixed(1), dom: f.domain ?? '' },
    });
  }
  return out.slice(0, 20);
}

export function macFlood(ctx: Ctx): Candidate[] {
  const once = [...ctx.macCount.entries()].filter(([, n]) => n.frames <= 2);
  if (once.length < T.MAC_FLOOD) return [];
  const nos = once.slice(0, 40).map(([, n]) => n.first);
  return [{
    detector: 'l2', topic: 'mac-flood', hypotheses: ['mac-flood'], hosts: [], ...span(ctx, nos), evidence: nos,
    signals: [sig('many', `${once.length} different source MACs each appeared once or twice. Real devices keep talking, so these are invented to overflow the switch.`, { 'mac-flood': 4, benign: -2 }, nos)], benign: [],
    facts: { count: once.length },
  }];
}
