import { T } from '../thresholds';
import type { Ctx, Flow } from '../context';
import type { BenignCheck, Candidate, Pkt, Signal } from '../types';

const uniq = <X,>(a: X[]) => [...new Set(a)];
const cap = (a: number[], n = 40) => a.slice(0, n);
const sig = (id: string, label: string, weights: Record<string, number>, packets: number[]): Signal => ({ id, label, weights, packets: cap(packets) });
const check = (id: string, label: string, matched: boolean, packets: number[] = []): BenignCheck => ({ id, label, matched, packets: cap(packets) });
function span(ctx: Ctx, nos: number[]) { const ts = nos.map((n) => ctx.get(n).ts); return { t0: Math.min(...ts), t1: Math.max(...ts) }; }
const median = (a: number[]) => { const s = [...a].sort((x, y) => x - y); return s[s.length >> 1] ?? 0; };

export function ipNum(ip: string) { const p = ip.split('.').map(Number); return ((p[0]! << 24) | (p[1]! << 16) | (p[2]! << 8) | p[3]!) >>> 0; }
export const isPrivate = (ip: string) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(ip);
const sameNet = (a: string, b: string, mask = '255.255.255.0') => { const m = ipNum(mask); return ((ipNum(a) & m) >>> 0) === ((ipNum(b) & m) >>> 0); };

// Consumer router vendors. A first-three-bytes hint only, never proof.
const CONSUMER_OUI: Record<string, string> = { '50:c7:bf': 'TP-Link', 'c0:25:e9': 'TP-Link', '00:14:6c': 'Netgear', 'a0:40:a0': 'Netgear', '00:1d:7e': 'Linksys', '14:cc:20': 'TP-Link', 'f8:1a:67': 'TP-Link', '00:26:5a': 'D-Link', '28:10:7b': 'D-Link', '74:da:88': 'TP-Link' };
const WELL_KNOWN = /(^|\.)(google|gstatic|youtube|facebook|apple|microsoft|windowsupdate|cloudflare|amazon|netflix|github|bank|paypal|icloud)\.[a-z.]+$/i;
const SCANNER_UA = /(nessus|qualys|openvas|greenbone|nmap scripting|rapid7|tenable)/i;

export function identity(ctx: Ctx): Candidate[] {
  const out: Candidate[] = [];
  const decline = ctx.pkts.filter((p) => p.dhcp?.msgType === 4);
  for (const [ip, macs] of ctx.ipMac) {
    if (macs.size < 2) {
      const only = [...macs.values()][0]!, base = ctx.baseline?.ipMac[ip];
      if (!base || base === only.mac) continue;
    }
    const list = [...macs.values()].sort((a, b) => a.first - b.first);
    const base = ctx.baseline?.ipMac[ip];
    const old = (base && list.find((m) => m.mac === base)) || list[0]!;
    const rival = list.find((m) => m !== old) ?? list[0]!;
    const nos = list.flatMap((m) => m.pkts);
    const signals: Signal[] = [];
    const isGw = ctx.gateways.has(ip);
    if (isGw) signals.push(sig('gw-claim', `A second MAC (${rival.mac}) claims the gateway address ${ip}.`, { 'arp-spoof': 2, 'duplicate-ip': -0.5 }, rival.pkts));
    if (rival.unsolicited >= T.ARP_REPLY_RATE) signals.push(sig('unsolicited', `${rival.mac} sent ${rival.unsolicited} ARP replies nobody asked for.`, { 'arp-spoof': 2.5, benign: -1 }, rival.pkts));
    const others = [...(ctx.macIps.get(rival.mac) ?? [])].filter((x) => x !== ip);
    const conflictOthers = others.filter((x) => (ctx.ipMac.get(x)?.size ?? 0) > 1);
    if (others.length) signals.push(sig('has-own-ip', `${rival.mac} already has its own address (${others[0]}), yet it also claims ${ip}.`, { 'arp-spoof': 2.5, 'duplicate-ip': -1.5 }, rival.pkts));
    if (conflictOthers.length) signals.push(sig('multi-claim', `The same MAC also fights for ${conflictOthers.join(', ')}.`, { 'arp-spoof': 1.5, 'duplicate-ip': -1 }, rival.pkts));

    const seq = nos.slice().sort((a, b) => a - b).map((n) => ctx.get(n).arp!.sha);
    const flips = seq.filter((m, i) => i && m !== seq[i - 1]).length;
    if (flips >= 3) signals.push(sig('flips', `The owner of ${ip} flipped ${flips} times between MACs.`, { 'arp-spoof': 1, 'duplicate-ip': 1, benign: -1.5 }, nos));

    const relayed = ctx.pkts.filter((p) => p.ipv === 4 && p.dstMac === rival.mac && p.dst !== undefined && !others.includes(p.dst) && p.dst !== ip && p.ts >= rival.first).slice(0, 40).map((p) => p.no);
    if (relayed.length >= 3) signals.push(sig('intercept', `Traffic for other hosts now passes through ${rival.mac}, the claimant.`, { 'arp-spoof': 2.5, 'duplicate-ip': -1 }, relayed));

    const acked = ctx.pkts.find((p) => p.dhcp?.msgType === 5 && p.dhcp.yiaddr === ip && (p.dhcp.chaddr === rival.mac || p.dhcp.chaddr === old.mac));
    if (acked) signals.push(sig('dhcp-lease', `DHCP handed ${ip} to ${acked.dhcp!.chaddr} while another device was already using it.`, { 'duplicate-ip': 3, 'arp-spoof': -1.5 }, [acked.no]));
    const dec = decline.filter((p) => p.dhcp!.requested === ip);
    if (dec.length) signals.push(sig('decline', `A client refused ${ip} because it found the address in use.`, { 'duplicate-ip': 2.5, 'arp-spoof': -1 }, dec.map((p) => p.no)));
    if (rival.unsolicited < T.ARP_REPLY_RATE && !isGw && !others.length) signals.push(sig('quiet', 'Both devices only speak ARP normally, with no burst of forged replies.', { 'duplicate-ip': 1.5, 'arp-spoof': -1 }, nos));
    if (base && base !== rival.mac) signals.push(sig('off-baseline', `Your saved baseline says ${ip} belongs to ${base}.`, { 'arp-spoof': 1.5, benign: -2 }, rival.pkts));

    const after = old.last <= rival.first + T.FAILOVER_WINDOW_S;
    const failover = after && flips <= 1 && !others.length && rival.announces >= 1;
    const benign = [check('failover', `Failover: ${old.mac} went silent and ${rival.mac} announced itself once`, failover, rival.pkts)];
    if (failover) signals.push(sig('failover', `${old.mac} stopped talking when ${rival.mac} took over, the pattern of a redundant pair failing over.`, { benign: 4, 'arp-spoof': -2.5, 'duplicate-ip': -2 }, rival.pkts));

    out.push({
      detector: 'identity', topic: 'identity', hypotheses: ['arp-spoof', 'duplicate-ip'], hosts: [ip, ...others], ...span(ctx, nos), evidence: cap(nos.sort((a, b) => a - b), 60), signals, benign,
      facts: { ip, macA: old.mac, macB: rival.mac, attackerIp: others[0] ?? '', isGateway: isGw ? 'yes' : '', flips, unsolicited: rival.unsolicited },
    });
  }
  return out;
}

export function rogueDhcp(ctx: Ctx): Candidate[] {
  const offers = ctx.pkts.filter((p) => p.dhcp && (p.dhcp.msgType === 2 || p.dhcp.msgType === 5));
  const servers = new Map<string, Pkt[]>();
  for (const p of offers) { const s = p.dhcp!.server ?? p.src!; (servers.get(s) ?? servers.set(s, []).get(s)!).push(p); }
  const relayed = offers.filter((p) => p.dhcp!.giaddr !== '0.0.0.0');
  const baseSrv = ctx.baseline?.dhcpServers;

  if (servers.size === 1) {
    const [srv] = [...servers.keys()];
    if (baseSrv?.length && !baseSrv.includes(srv!)) {
      const pk = servers.get(srv!)!;
      return [{ detector: 'dhcp', topic: 'dhcp', hypotheses: ['rogue-dhcp-attack', 'rogue-dhcp-misconfig'], hosts: [srv!], ...span(ctx, pk.map((p) => p.no)), evidence: cap(pk.map((p) => p.no)), signals: [sig('off-baseline', `DHCP server ${srv} is not in your saved baseline.`, { 'rogue-dhcp-attack': 1.5, 'rogue-dhcp-misconfig': 1.5, benign: -2 }, pk.map((p) => p.no))], benign: [], facts: { server: srv!, legit: baseSrv[0]!, router: pk[0]!.dhcp!.router ?? '', dns: pk[0]!.dhcp!.dns.join(', ') } }];
    }
    if (relayed.length) {
      const nos = relayed.map((p) => p.no);
      return [{ detector: 'dhcp', topic: 'dhcp', hypotheses: [], hosts: [srv!, relayed[0]!.dhcp!.giaddr], ...span(ctx, nos), evidence: cap(nos), signals: [sig('relay', `Offers come through relay ${relayed[0]!.dhcp!.giaddr} but all carry one server identity, ${srv}.`, { benign: 3 }, nos)], benign: [check('relay', 'DHCP relay forwarding for one server', true, nos)], facts: { server: srv!, relay: relayed[0]!.dhcp!.giaddr, benignKind: 'DHCP relay' } }];
    }
    return [];
  }
  if (servers.size < 2) return [];

  const ranked = [...servers.entries()].sort((a, b) => {
    if (baseSrv?.includes(a[0])) return -1;
    if (baseSrv?.includes(b[0])) return 1;
    const ra = (ctx.dhcpRouters.get(a[1][0]!.dhcp!.router ?? '') ?? 0), rb = (ctx.dhcpRouters.get(b[1][0]!.dhcp!.router ?? '') ?? 0);
    return a[1][0]!.no - b[1][0]!.no || rb - ra;
  });
  const [legit, legitPk] = ranked[0]!;
  const out: Candidate[] = [];
  for (const [srv, pk] of ranked.slice(1)) {
    const d = pk[0]!.dhcp!, nos = pk.map((p) => p.no), signals: Signal[] = [];
    const legitD = legitPk[0]!.dhcp!;
    signals.push(sig('second-server', `Two DHCP servers answer on this network: ${legit} and ${srv}.`, { 'rogue-dhcp-attack': 1, 'rogue-dhcp-misconfig': 1, benign: -3 }, nos));
    const srcMac = pk[0]!.srcMac ?? '';
    const vendor = CONSUMER_OUI[srcMac.slice(0, 8)];
    if (vendor) signals.push(sig('consumer-oui', `Its network card is made by ${vendor}, a home-router brand.`, { 'rogue-dhcp-misconfig': 2, 'rogue-dhcp-attack': -0.5 }, [nos[0]!]));
    const selfGw = d.router === srv && d.dns.every((x) => x === srv);
    if (selfGw && d.router && isPrivate(d.router)) signals.push(sig('self-contained', `It offers itself as gateway and DNS, in a private range. Home routers do this by default.`, { 'rogue-dhcp-misconfig': 1.5 }, [nos[0]!]));
    const foreignDns = d.dns.filter((x) => !legitD.dns.includes(x) && x !== srv);
    if (foreignDns.length) signals.push(sig('foreign-dns', `It points clients at DNS server ${foreignDns[0]}, which the real server never mentions.`, { 'rogue-dhcp-attack': 2.5, 'rogue-dhcp-misconfig': -1 }, [nos[0]!]));
    const gwForeign = d.router && d.router !== srv && d.router !== legitD.router;
    if (gwForeign) signals.push(sig('foreign-gw', `It names ${d.router} as the gateway, an address that is neither server.`, { 'rogue-dhcp-attack': 2, 'rogue-dhcp-misconfig': -0.5 }, [nos[0]!]));
    const gwClient = d.router && !ctx.gateways.has(d.router) ? false : d.router !== legitD.router && d.router === srv && !vendor;
    if (gwClient) signals.push(sig('client-gw', `It names itself as gateway, yet its hardware is not a known router brand.`, { 'rogue-dhcp-attack': 1.5, 'rogue-dhcp-misconfig': -0.5 }, [nos[0]!]));
    const dnsIps = new Set([...foreignDns, ...(d.dns.includes(srv) ? [srv] : [])]);
    const odd = ctx.pkts.filter((p) => p.dns?.qr && p.dns.kind === 'dns' && dnsIps.has(p.src!) && p.ts >= pk[0]!.ts && WELL_KNOWN.test(p.dns.qname) && p.dns.answers.some((a) => a.type === 1));
    if (odd.length) signals.push(sig('odd-answers', `After the offer, ${odd[0]!.src} answered for ${odd[0]!.dns!.qname} with ${odd[0]!.dns!.answers[0]?.data}.`, { 'rogue-dhcp-attack': 3, 'rogue-dhcp-misconfig': -2 }, odd.map((p) => p.no)));
    else if (vendor) signals.push(sig('no-dns-tamper', 'No DNS answers were altered afterwards.', { 'rogue-dhcp-misconfig': 1.5, 'rogue-dhcp-attack': -1.5 }, [nos[0]!]));
    const clients = uniq(pk.map((p) => p.dhcp!.chaddr));
    out.push({
      detector: 'dhcp', topic: 'dhcp', hypotheses: ['rogue-dhcp-attack', 'rogue-dhcp-misconfig'], hosts: [srv, ...foreignDns], ...span(ctx, nos), evidence: cap(nos.concat(legitPk.slice(0, 3).map((p) => p.no)).sort((a, b) => a - b)), signals,
      benign: [check('relay', 'Both offers share one server identity (DHCP relay)', false)],
      facts: { server: srv, legit, router: d.router ?? '', dns: d.dns.join(', '), serverMac: srcMac, vendor: vendor ?? '', clients, legitRouter: legitD.router ?? '' },
    });
  }
  return out;
}

export function dhcpFailure(ctx: Ctx): Candidate[] {
  const by = new Map<string, Pkt[]>();
  for (const p of ctx.pkts) if (p.dhcp?.msgType === 1) (by.get(p.dhcp.chaddr) ?? by.set(p.dhcp.chaddr, []).get(p.dhcp.chaddr)!).push(p);
  const out: Candidate[] = [];
  const naks = ctx.pkts.filter((p) => p.dhcp?.msgType === 6);
  for (const [m, list] of by) {
    const got = ctx.pkts.some((p) => p.dhcp?.msgType === 2 && p.dhcp.chaddr === m);
    if (got || list.length < T.DHCP_DISCOVER_MIN) continue;
    const nos = list.map((p) => p.no);
    out.push({ detector: 'dhcp-health', topic: 'dhcp-health', hypotheses: ['dhcp-failure'], hosts: [m], ...span(ctx, nos), evidence: cap(nos), signals: [sig('no-offer', `${m} asked for an address ${list.length} times and no server answered.`, { 'dhcp-failure': 3, benign: -2 }, nos)], benign: [], facts: { mac: m, tries: list.length } });
  }
  if (naks.length >= 3) { const nos = naks.map((p) => p.no); out.push({ detector: 'dhcp-health', topic: 'dhcp-health', hypotheses: ['dhcp-failure'], hosts: [naks[0]!.src!], ...span(ctx, nos), evidence: cap(nos), signals: [sig('nak', `The server refused ${naks.length} requests.`, { 'dhcp-failure': 3, benign: -2 }, nos)], benign: [], facts: { mac: naks[0]!.dhcp!.chaddr, tries: naks.length } }); }
  return out;
}

export function dnsHijack(ctx: Ctx): Candidate[] {
  const q = new Map<string, Pkt>(), replies = new Map<string, Pkt[]>();
  const signals: Signal[] = [], hosts = new Set<string>(), bad: number[] = [];
  const dns = ctx.pkts.filter((p) => p.dns?.kind === 'dns');
  const key = (p: Pkt) => `${p.dns!.id}|${p.dns!.qname.toLowerCase()}`;
  for (const p of dns) {
    if (!p.dns!.qr) q.set(key(p), p);
    else (replies.get(key(p)) ?? replies.set(key(p), []).get(key(p))!).push(p);
  }
  let facts: Candidate['facts'] = {};
  for (const [k, rs] of replies) {
    const ask = q.get(k);
    if (ask && rs.length > 1) {
      const ans = uniq(rs.map((r) => r.dns!.answers.filter((a) => a.type === 1).map((a) => a.data).sort().join(',')));
      if (ans.length > 1) {
        const nos = rs.map((r) => r.no);
        signals.push(sig('race', `Two different answers raced for ${ask.dns!.qname}: ${ans.join(' and ')}.`, { 'dns-hijack': 3, benign: -2 }, nos.concat(ask.no)));
        bad.push(...nos); hosts.add(ask.src!);
        facts = { qname: ask.dns!.qname, victim: ask.src!, forged: rs.at(-1)!.dns!.answers[0]?.data ?? '', real: rs[0]!.dns!.answers[0]?.data ?? '', resolver: ask.dst!, forger: rs.find((r) => r.src !== ask.dst)?.src ?? '' };
      }
    }
    for (const r of rs) {
      if (ask && ask.dst !== r.src && ask.dst !== '224.0.0.251') {
        signals.push(sig('unqueried', `${r.src} answered a question that was sent to ${ask.dst}.`, { 'dns-hijack': 2.5, benign: -1 }, [ask.no, r.no]));
        bad.push(r.no); hosts.add(r.src!);
        facts.forger ??= r.src!;
      }
      const priv = r.dns!.answers.find((a) => a.type === 1 && isPrivate(a.data));
      if (priv && WELL_KNOWN.test(r.dns!.qname)) {
        signals.push(sig('private-answer', `${r.dns!.qname} was answered with a private address, ${priv.data}. Public sites do not live there.`, { 'dns-hijack': 2.5, benign: -1 }, [r.no]));
        bad.push(r.no); hosts.add(r.dst!);
        facts = { qname: r.dns!.qname, forged: priv.data, victim: r.dst!, resolver: r.src!, ...facts };
      }
    }
  }
  if (!signals.length) return [];
  const uniqSig = uniq(signals.map((s) => s.id)).map((id) => signals.find((s) => s.id === id)!);
  if (ctx.dhcpDns.size) {
    const others = uniq(dns.filter((p) => p.dns!.qr).map((p) => p.src!)).filter((s) => !ctx.dhcpDns.has(s));
    if (others.length) uniqSig.push(sig('off-dhcp', `${others[0]} answers DNS but DHCP never advertised it as a resolver.`, { 'dns-hijack': 1.5 }, bad));
  }
  return [{ detector: 'dns', topic: 'dns-integrity', hypotheses: ['dns-hijack'], hosts: [...hosts], ...span(ctx, bad), evidence: cap(uniq(bad)), signals: uniqSig, benign: [check('split', 'Internal split-horizon DNS for a company domain', false)], facts }];
}

export function dnsHealth(ctx: Ctx): Candidate[] {
  const byServer = new Map<string, Pkt[]>();
  for (const p of ctx.pkts) if (p.dns?.kind === 'dns' && !p.dns.qr && p.dst) (byServer.get(p.dst) ?? byServer.set(p.dst, []).get(p.dst)!).push(p);
  const out: Candidate[] = [];
  for (const [srv, qs] of byServer) {
    const answered = new Map<string, Pkt>();
    for (const p of ctx.pkts) if (p.dns?.qr && p.dns.kind === 'dns' && p.src === srv) answered.set(`${p.dns.id}|${p.dns.qname}`, p);
    const fails: number[] = [], lost: number[] = [], slow: number[] = [];
    let nx = 0, sv = 0;
    for (const q of qs) {
      const r = answered.get(`${q.dns!.id}|${q.dns!.qname}`);
      if (!r) lost.push(q.no);
      else {
        if (r.dns!.rcode === 3) { nx++; fails.push(r.no); }
        if (r.dns!.rcode === 2 || r.dns!.rcode === 5) { sv++; fails.push(r.no); }
        if (r.ts - q.ts > T.DNS_SLOW_S) slow.push(r.no);
      }
    }
    const bad = fails.length + lost.length, ratio = bad / qs.length;
    if (bad < T.DNS_FAIL_MIN || ratio < T.DNS_FAIL_RATIO) continue;
    const nos = uniq([...lost, ...fails, ...slow]).sort((a, b) => a - b);
    const signals: Signal[] = [sig('ratio', `${bad} of ${qs.length} lookups to ${srv} failed (${Math.round(ratio * 100)}%).`, { 'dns-failure': 2.5, benign: -2 }, nos)];
    if (lost.length) signals.push(sig('timeout', `${lost.length} lookups got no reply at all.`, { 'dns-failure': 1 }, lost));
    if (sv) signals.push(sig('servfail', `The server said it could not answer ${sv} times.`, { 'dns-failure': 1 }, fails));
    if (nx && !sv && !lost.length) signals.push(sig('nx', `${nx} names do not exist, which can be a typo or a stale setting.`, { 'dns-failure': 0.5 }, fails));
    const clients = uniq(qs.map((p) => p.src!));
    const names = uniq(qs.map((p) => p.dns!.qname));
    out.push({ detector: 'dns-health', topic: 'dns-health', hypotheses: ['dns-failure'], hosts: [srv, ...clients.slice(0, 8)], ...span(ctx, nos), evidence: cap(nos), signals, benign: [], facts: { server: srv, failed: bad, total: qs.length, sample: names[0]!, clients, timeouts: lost.length, servfail: sv, nxdomain: nx } });
  }
  return out;
}

const pair = (f: Flow) => [f.a, f.b].sort().join('|');

export function tcpHealth(ctx: Ctx, skip: Set<string>): Candidate[] {
  const out: Candidate[] = [];
  const groups = new Map<string, Flow[]>();
  for (const f of ctx.flows) if (f.proto === 'TCP' && f.retrans.length) (groups.get(pair(f)) ?? groups.set(pair(f), []).get(pair(f))!).push(f);
  for (const fs of groups.values()) {
    const r = fs.flatMap((f) => f.retrans), pk = fs.reduce((n, f) => n + f.pkts, 0);
    if (r.length < T.RETRANS_MIN || r.length / pk < T.RETRANS_RATE) continue;
    const nos = r.map((x) => x.no), f0 = fs[0]!;
    if (fs.every((f) => f.largeRetrans === f.retrans.length)) continue; // the MTU detector owns these
    const rto = r.filter((x) => x.gap >= T.RTO_GAP_S), fast = r.filter((x) => x.fast);
    const gaps = rto.map((x) => x.gap);
    const backoff = gaps.length >= 3 && gaps.slice(1).filter((g, i) => g > gaps[i]! * 1.5).length >= gaps.length / 3;
    const signals = [sig('rate', `${r.length} of ${pk} packets between ${f0.a} and ${f0.b} were sent twice (${(100 * r.length / pk).toFixed(1)}%).`, { 'tcp-loss': 3, benign: -2 }, nos)];
    if (fast.length) signals.push(sig('fast', `${fast.length} repeats followed duplicate ACKs: the receiver saw a gap.`, { 'tcp-loss': 1 }, fast.map((x) => x.no)));
    if (rto.length) signals.push(sig('rto', `${rto.length} repeats came after a timeout.`, { 'tcp-loss': 0.5 }, rto.map((x) => x.no)));
    if (backoff) signals.push(sig('backoff', 'Waits between repeats doubled, the shape of TCP backing off from a real problem.', { 'tcp-loss': 1 }, rto.map((x) => x.no)));
    out.push({ detector: 'tcp', topic: `tcp-loss`, hypotheses: ['tcp-loss'], hosts: [f0.a, f0.b], ...span(ctx, nos), evidence: cap(nos), signals, benign: [], facts: { a: f0.a, b: f0.b, port: f0.pb, count: r.length, rate: +(100 * r.length / pk).toFixed(1), fast: fast.length, rto: rto.length, domain: f0.domain ?? '' } });
  }
  const zero = ctx.flows.filter((f) => f.zeroWin.length >= T.ZERO_WINDOW_MIN);
  for (const f of zero) {
    const who = ctx.get(f.zeroWin[0]!).src!;
    out.push({ detector: 'tcp', topic: 'zero-window', hypotheses: ['zero-window'], hosts: [f.a, f.b], ...span(ctx, f.zeroWin), evidence: cap(f.zeroWin), signals: [sig('zw', `${who} told its peer ${f.zeroWin.length} times to stop sending: its buffer is full.`, { 'zero-window': 3, benign: -2 }, f.zeroWin)], benign: [], facts: { host: who, peer: who === f.a ? f.b : f.a, port: f.pb, count: f.zeroWin.length } });
  }
  const rsts = new Map<string, Flow[]>();
  for (const f of ctx.flows) if (f.rst.length && !skip.has(f.a)) { const k = `${f.b}:${f.pb}`; (rsts.get(k) ?? rsts.set(k, []).get(k)!).push(f); }
  for (const fs of rsts.values()) {
    const all = fs.flatMap((f) => f.rst);
    if (all.length < T.RST_MIN) continue;
    const nos = all.map((x) => x.no), early = all.filter((x) => x.early), mid = all.filter((x) => !x.early), f0 = fs[0]!;
    const signals = [sig('count', `${all.length} connections to ${f0.b} port ${f0.pb} were reset.`, { 'tcp-reset': 2.5, benign: -2 }, nos)];
    if (early.length) signals.push(sig('closed', `${early.length} were refused immediately: nothing is listening on that port.`, { 'tcp-reset': 1 }, early.map((x) => x.no)));
    if (mid.length) signals.push(sig('abort', `${mid.length} were cut off mid-conversation.`, { 'tcp-reset': 1 }, mid.map((x) => x.no)));
    if (all.length >= T.RST_STORM_MIN) signals.push(sig('storm', 'Resets arrived as a storm.', { 'tcp-reset': 0.5 }, nos));
    out.push({ detector: 'tcp', topic: 'tcp-reset', hypotheses: ['tcp-reset'], hosts: [f0.b, ...uniq(fs.map((f) => f.a)).slice(0, 8)], ...span(ctx, nos), evidence: cap(nos), signals, benign: [], facts: { server: f0.b, port: f0.pb, count: all.length, early: early.length, mid: mid.length, clients: uniq(fs.map((f) => f.a)) } });
  }
  return out;
}

export function scans(ctx: Ctx): { cands: Candidate[]; sources: Set<string> } {
  const bySrc = new Map<string, Flow[]>();
  for (const f of ctx.flows) if (f.proto === 'TCP' && f.syn.length) (bySrc.get(f.a) ?? bySrc.set(f.a, []).get(f.a)!).push(f);
  const out: Candidate[] = [], sources = new Set<string>();
  for (const [src, fs] of bySrc) {
    const perHost = new Map<string, Set<number>>(), perPort = new Map<number, Set<string>>();
    for (const f of fs) {
      (perHost.get(f.b) ?? perHost.set(f.b, new Set()).get(f.b)!).add(f.pb);
      (perPort.get(f.pb) ?? perPort.set(f.pb, new Set()).get(f.pb)!).add(f.b);
    }
    const vert = [...perHost.entries()].sort((a, b) => b[1].size - a[1].size)[0]!;
    const horiz = [...perPort.entries()].sort((a, b) => b[1].size - a[1].size)[0]!;
    const isV = vert[1].size >= T.SCAN_PORTS, isH = horiz[1].size >= T.SCAN_HOSTS;
    if (!isV && !isH) continue;
    sources.add(src);
    const nos = fs.map((f) => f.first).sort((a, b) => a - b);
    const synOnly = fs.filter((f) => !f.est).length / fs.length;
    const dur = Math.max(0.001, ctx.get(nos.at(-1)!).ts - ctx.get(nos[0]!).ts), rate = fs.length / dur;
    const ports = fs.map((f) => f.pb);
    const sequential = ports.slice(1).filter((p, i) => p === ports[i]! + 1).length > ports.length * 0.5;
    const signals = [sig('fanout', isV ? `${src} tried ${vert[1].size} ports on ${vert[0]}.` : `${src} tried port ${horiz[0]} on ${horiz[1].size} hosts.`, { 'port-scan': 3, benign: -0.5 }, nos)];
    if (synOnly >= T.SCAN_SYN_ONLY) signals.push(sig('syn-only', `${Math.round(synOnly * 100)}% of attempts never finished a handshake: it is probing, not connecting.`, { 'port-scan': 2, benign: -1 }, nos));
    if (rate > 20) signals.push(sig('rate', `${Math.round(rate)} attempts per second, faster than any person.`, { 'port-scan': 1 }, nos));
    if (sequential) signals.push(sig('sequential', 'Ports were tried in order, one after another.', { 'port-scan': 0.5 }, nos));
    const uas = fs.map((f) => f.ua).filter(Boolean) as string[];
    const known = uas.find((u) => SCANNER_UA.test(u));
    const uaPkts = fs.filter((f) => f.ua).map((f) => f.first);
    const benign = [check('known-scanner', known ? `Identifies itself as a vulnerability scanner: "${known}"` : 'Identifies itself as a known vulnerability scanner', !!known, uaPkts)];
    if (known) signals.push(sig('known-scanner', `It announces itself as a vulnerability scanner (${known}) and completes real connections.`, { benign: 6, 'port-scan': -2 }, uaPkts));
    const open = uniq(fs.filter((f) => f.synAck.length).map((f) => f.pb)).sort((a, b) => a - b);
    out.push({ detector: 'scan', topic: 'scan', hypotheses: ['port-scan'], hosts: [src, ...(isV ? [vert[0]] : [...horiz[1]].slice(0, 12))], ...span(ctx, nos), evidence: cap(nos), signals, benign, facts: { source: src, target: isV ? vert[0] : `${horiz[1].size} hosts`, targetIp: isV ? vert[0] : '', mode: isV ? 'vertical' : 'horizontal', ports: isV ? vert[1].size : 1, hosts: isV ? 1 : horiz[1].size, open: open.slice(0, 20).map(String), benignKind: known ? 'Authorised-looking vulnerability scanner' : '' } });
  }
  return { cands: out, sources };
}

export function reachability(ctx: Ctx, skip: Set<string>): Candidate[] {
  const bySvc = new Map<string, Flow[]>();
  for (const f of ctx.flows) if (f.proto === 'TCP' && f.syn.length && !f.est && !f.rst.length && !skip.has(f.a)) { const k = `${f.b}:${f.pb}`; (bySvc.get(k) ?? bySvc.set(k, []).get(k)!).push(f); }
  const out: Candidate[] = [];
  for (const fs of bySvc.values()) {
    const f0 = fs[0]!, syns = fs.flatMap((f) => f.syn.map((s) => s.no));
    if (syns.length < T.OUTAGE_MIN_SYN) continue;
    const sources = uniq(fs.map((f) => f.a));
    const answered = fs.filter((f) => f.synAck.length);
    const earlier = ctx.flows.filter((f) => f.b === f0.b && f.pb === f0.pb && f.est);
    const lastOk = earlier.length ? Math.max(...earlier.map((f) => f.t1)) : 0;
    const backoffs = fs.filter((f) => f.syn.length >= 3 && f.syn.slice(2).every((s, i) => s.ts - f.syn[i + 1]!.ts > (f.syn[i + 1]!.ts - f.syn[i]!.ts) * 1.4));
    const icmp = ctx.pkts.filter((p) => p.icmp?.type === 3 && p.icmp.code !== 4 && p.icmp.innerDst === f0.b);
    const dur = Math.max(0.01, ctx.get(syns.at(-1)!).ts - ctx.get(syns[0]!).ts), rate = syns.length / dur;
    const signals: Signal[] = [];
    const isFlood = sources.length >= T.FLOOD_SOURCES && syns.length >= T.FLOOD_HALF_OPEN;
    if (isFlood) signals.push(sig('many-sources', `${syns.length} half-open attempts from ${sources.length} sources hit ${f0.b} port ${f0.pb}.`, { 'syn-flood': 3, 'server-outage': -1, benign: -2 }, syns));
    if (rate > 50) signals.push(sig('rate', `${Math.round(rate)} attempts per second.`, { 'syn-flood': 1.5, 'server-outage': -1 }, syns));
    if (answered.length >= fs.length * 0.5 && isFlood) signals.push(sig('half-open', `The server answered ${answered.length} SYNs and the sources never finished: they did not want a connection.`, { 'syn-flood': 2.5, 'server-outage': -2 }, answered.flatMap((f) => f.synAck)));
    if (backoffs.length) signals.push(sig('backoff', `${backoffs.length} clients retried with doubling waits, as real software does.`, { 'server-outage': 2, 'syn-unanswered': 1, 'syn-flood': -2 }, backoffs.flatMap((f) => f.syn.map((s) => s.no))));
    if (earlier.length && !answered.length) signals.push(sig('was-working', `${earlier.length} connections worked before the server went quiet.`, { 'server-outage': 3, 'syn-unanswered': -1 }, earlier.slice(0, 5).map((f) => f.first)));
    if (!earlier.length && !answered.length) signals.push(sig('never-worked', 'No connection to this service ever worked in this capture, so a filter or wrong address is as likely as a dead server.', { 'syn-unanswered': 2.5, 'server-outage': 0.5 }, syns));
    if (icmp.length) signals.push(sig('icmp', `A router reported ${f0.b} as unreachable.`, { 'server-outage': 1.5, 'syn-unanswered': 1, 'syn-flood': -1 }, icmp.map((p) => p.no)));
    out.push({ detector: 'reach', topic: 'reachability', hypotheses: ['syn-flood', 'server-outage', 'syn-unanswered'], hosts: [f0.b, ...sources.slice(0, 10)], ...span(ctx, syns), evidence: cap(syns), signals, benign: [check('load-balancer', 'Health checks from a load balancer', false)], facts: { server: f0.b, port: f0.pb, sources: sources.length, sourceList: sources.slice(0, 12), attempts: syns.length, lastOk: lastOk || 0 } });
  }
  return out;
}

export function mtu(ctx: Ctx): Candidate[] {
  const icmp = ctx.pkts.filter((p) => p.icmp?.type === 3 && p.icmp.code === 4);
  const flows = ctx.flows.filter((f) => f.largeRetrans >= T.MTU_RETRANS_MIN);
  if (!icmp.length && !flows.length) return [];
  const nos = [...icmp.map((p) => p.no), ...flows.flatMap((f) => f.retrans.slice(0, 20).map((r) => r.no))].sort((a, b) => a - b);
  const signals: Signal[] = [];
  const nh = icmp[0]?.icmp?.nextMtu;
  if (icmp.length) signals.push(sig('icmp-frag', `Router ${icmp[0]!.src} said packets must be ${nh} bytes or smaller.`, { 'mtu-blackhole': 3, benign: -1 }, icmp.map((p) => p.no)));
  const f0 = flows[0];
  if (f0) {
    signals.push(sig('large-repeats', `${f0.largeRetrans} full-size packets marked "do not fragment" were resent and never acknowledged.`, { 'mtu-blackhole': 3, benign: -2 }, f0.retrans.map((r) => r.no)));
    const small = ctx.get(f0.first);
    if (f0.est) signals.push(sig('small-ok', 'The handshake and small packets on the same connection worked fine.', { 'mtu-blackhole': 1.5 }, [small.no]));
    if (!icmp.length) signals.push(sig('no-icmp', 'No router ever reported the problem: something is dropping the warning too.', { 'mtu-blackhole': 1 }, f0.retrans.slice(0, 5).map((r) => r.no)));
  }
  const a = f0?.a ?? icmp[0]!.icmp!.innerSrc ?? icmp[0]!.dst!, b = f0?.b ?? icmp[0]!.icmp!.innerDst ?? '';
  const large = ctx.pkts.find((p) => p.len >= 1400 && p.df && p.src === a);
  return [{ detector: 'mtu', topic: 'mtu', hypotheses: ['mtu-blackhole'], hosts: [a, b].filter(Boolean), ...span(ctx, nos), evidence: cap(nos), signals, benign: [], facts: { host: a, peer: b, nextMtu: nh ?? 0, router: icmp[0]?.src ?? '', size: large?.len ?? 1500, mss: f0?.mss ?? 0, port: f0?.pb ?? 0, suggest: nh ? nh - 40 : 1360 } }];
}

export function delay(ctx: Ctx): Candidate[] {
  const out: Candidate[] = [];
  const rtts = ctx.flows.filter((f) => f.rtt !== undefined);
  if (rtts.length >= T.DELAY_MIN_SAMPLES) {
    const vals = rtts.map((f) => f.rtt!), med = median(vals);
    const mad = median(vals.map((v) => Math.abs(v - med))) || 1e-3;
    const slow = rtts.filter((f) => f.rtt! >= T.DELAY_MIN_S && 0.6745 * (f.rtt! - med) / mad >= T.MAD_Z);
    if (slow.length) {
      const nos = slow.flatMap((f) => f.synAck.slice(0, 1)), f0 = slow.sort((a, b) => b.rtt! - a.rtt!)[0]!;
      out.push({ detector: 'delay', topic: 'delay', hypotheses: ['high-latency'], hosts: uniq(slow.flatMap((f) => [f.a, f.b])).slice(0, 8), ...span(ctx, nos), evidence: cap(nos), signals: [sig('rtt', `${slow.length} connections took up to ${Math.round(f0.rtt! * 1000)} ms to answer. Typical here is ${Math.round(med * 1000)} ms.`, { 'high-latency': 3, benign: -1.5 }, nos)], benign: [], facts: { slowMs: Math.round(f0.rtt! * 1000), typicalMs: Math.round(med * 1000), a: f0.a, b: f0.b, port: f0.pb, count: slow.length } });
    }
  }
  return out;
}

export function nameSpoof(ctx: Ctx): Candidate[] {
  const local = ctx.pkts.filter((p) => p.dns && (p.dns.kind === 'llmnr' || p.dns.kind === 'nbns'));
  const answers = local.filter((p) => p.dns!.qr && p.dns!.answers.length);
  if (!answers.length) return [];
  const by = new Map<string, Pkt[]>();
  for (const p of answers) (by.get(p.src!) ?? by.set(p.src!, []).get(p.src!)!).push(p);
  const out: Candidate[] = [];
  for (const [src, rs] of by) {
    const names = uniq(rs.map((p) => p.dns!.qname.toLowerCase()));
    const nos = rs.map((p) => p.no);
    const signals = [sig('answers-all', `${src} answered for ${names.length} different names: ${names.slice(0, 3).join(', ')}.`, names.length >= 3 ? { 'llmnr-poison': 3, benign: -2 } : { benign: 1 }, nos)];
    const self = rs.filter((p) => p.dns!.answers.some((a) => a.data === src));
    if (self.length === rs.length && names.length >= 2) signals.push(sig('points-self', 'Every answer pointed back at the answerer.', { 'llmnr-poison': 1.5 }, nos));
    const after = ctx.flows.filter((f) => f.b === src && [445, 139, 80].includes(f.pb) && f.t0 >= rs[0]!.ts);
    if (after.length) signals.push(sig('capture', `Victims then connected to ${src} on port ${after[0]!.pb}, where credentials change hands.`, { 'llmnr-poison': 2.5 }, after.map((f) => f.first)));
    const victims = uniq(rs.map((p) => p.dst!));
    out.push({ detector: 'names', topic: 'names', hypotheses: ['llmnr-poison'], hosts: [src, ...victims], ...span(ctx, nos), evidence: cap(nos), signals, benign: [check('single-host', 'One device answering only for its own name', names.length === 1, nos)], facts: { source: src, names, victims, mac: rs[0]!.srcMac ?? '' } });
  }
  return out;
}

export function entropy(s: string) {
  const c = new Map<string, number>();
  for (const ch of s) c.set(ch, (c.get(ch) ?? 0) + 1);
  let e = 0;
  for (const n of c.values()) { const p = n / s.length; e -= p * Math.log2(p); }
  return e;
}
export const parentOf = (name: string) => name.split('.').slice(-2).join('.').toLowerCase();

export function dnsTunnel(ctx: Ctx): Candidate[] {
  const by = new Map<string, Pkt[]>();
  for (const p of ctx.pkts) {
    if (p.dns?.kind !== 'dns' || p.dns.qr) continue;
    const l = p.dns.qname.split('.')[0] ?? '';
    if (l.length >= T.TUNNEL_LABEL && entropy(l) >= T.TUNNEL_ENTROPY) { const k = parentOf(p.dns.qname); (by.get(k) ?? by.set(k, []).get(k)!).push(p); }
  }
  const out: Candidate[] = [];
  for (const [dom, ps] of by) {
    if (ps.length < T.TUNNEL_MIN_QUERIES) continue;
    const nos = ps.map((p) => p.no);
    const bytes = ps.reduce((n, p) => n + p.dns!.qname.length, 0);
    out.push({ detector: 'tunnel', topic: 'tunnel', hypotheses: ['dns-tunnel'], hosts: uniq(ps.map((p) => p.src!)), ...span(ctx, nos), evidence: cap(nos), signals: [sig('long-labels', `${ps.length} lookups under ${dom} carry long random-looking labels, about ${bytes} bytes hidden in names.`, { 'dns-tunnel': 4, benign: -2 }, nos)], benign: [], facts: { domain: dom, count: ps.length, bytes, host: ps[0]!.src!, resolver: ps[0]!.dst! } });
  }
  return out;
}

export function dgaScore(name: string) {
  const l = name.split('.').slice(0, -1).join('').toLowerCase();
  if (l.length < T.DGA_MIN_LEN) return false;
  const vowels = (l.match(/[aeiou]/g) ?? []).length / l.length;
  return entropy(l) >= T.DGA_ENTROPY && vowels < 0.3;
}

export function behaviour(ctx: Ctx): Candidate[] {
  const out: Candidate[] = [];
  const nx = new Map<string, Pkt[]>();
  for (const p of ctx.pkts) if (p.dns?.kind === 'dns' && !p.dns.qr && dgaScore(p.dns.qname)) (nx.get(p.src!) ?? nx.set(p.src!, []).get(p.src!)!).push(p);
  for (const [src, ps] of nx) {
    const names = uniq(ps.map((p) => p.dns!.qname));
    // One parent with many children is a tunnel; DGA spreads across many parents.
    if (names.length < 5 || new Set(names.map(parentOf)).size < 5) continue;
    const nos = ps.map((p) => p.no);
    out.push({ detector: 'behaviour', topic: 'dga', hypotheses: ['dga-domain'], hosts: [src], ...span(ctx, nos), evidence: cap(nos), signals: [sig('dga', `${src} looked up ${names.length} random-looking domains such as ${names[0]}.`, { 'dga-domain': 3.5, benign: -2 }, nos)], benign: [], facts: { host: src, count: names.length, sample: names[0]! } });
  }
  const conv = new Map<string, Flow[]>();
  for (const f of ctx.flows) if (f.proto === 'TCP' && f.syn.length) { const k = `${f.a}|${f.b}|${f.pb}`; (conv.get(k) ?? conv.set(k, []).get(k)!).push(f); }
  for (const fs of conv.values()) {
    if (fs.length < T.BEACON_MIN) continue;
    const ts = fs.map((f) => f.t0).sort((a, b) => a - b), gaps = ts.slice(1).map((t, i) => t - ts[i]!);
    const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    const sd = Math.sqrt(gaps.reduce((a, g) => a + (g - mean) ** 2, 0) / gaps.length);
    const f0 = fs[0]!;
    if (mean < T.BEACON_MIN_S || sd / mean > T.BEACON_JITTER) continue;
    const nos = fs.map((f) => f.first);
    if (f0.pb === 123 || (f0.domain && /(ntp|time\.|windowsupdate|apple\.com|gstatic)/.test(f0.domain))) continue;
    out.push({ detector: 'behaviour', topic: 'beacon', hypotheses: ['beaconing'], hosts: [f0.a, f0.b], ...span(ctx, nos), evidence: cap(nos), signals: [sig('rhythm', `${f0.a} called ${f0.domain ?? f0.b} ${fs.length} times, every ${mean.toFixed(1)} s with only ${(100 * sd / mean).toFixed(1)}% jitter. People are not this regular.`, { beaconing: 3.5, benign: -1.5 }, nos)], benign: [check('known-service', 'A well-known update or time service', false)], facts: { host: f0.a, peer: f0.b, port: f0.pb, every: +mean.toFixed(1), count: fs.length, domain: f0.domain ?? '' } });
  }
  return out;
}

export function evasion(ctx: Ctx, fileAnomalies: Map<string, number>): Candidate[] {
  const hits = ctx.pkts.filter((p) => p.anomalies?.length);
  const frags = new Map<string, Pkt[]>();
  for (const p of ctx.pkts) if (p.mf || p.fragOff) { const k = `${p.src}|${p.dst}|${p.ipId}`; (frags.get(k) ?? frags.set(k, []).get(k)!).push(p); }
  for (const list of frags.values()) {
    const sorted = list.slice().sort((a, b) => (a.fragOff ?? 0) - (b.fragOff ?? 0));
    for (let i = 1; i < sorted.length; i++) {
      const prev = sorted[i - 1]!, end = (prev.fragOff ?? 0) + (prev.ipLen ?? 20) - 20;
      if ((sorted[i]!.fragOff ?? 0) < end) { const p = sorted[i]!; (p.anomalies ??= []).push('Overlapping IP fragments'); if (!hits.includes(p)) hits.push(p); }
    }
  }
  if (!hits.length) return [];
  const nos = hits.map((p) => p.no).sort((a, b) => a - b);
  const kinds = new Map<string, number[]>();
  for (const p of hits) for (const a of p.anomalies!) (kinds.get(a) ?? kinds.set(a, []).get(a)!).push(p.no);
  const signals = [...kinds].map(([k, n]) => sig(k, `${n.length} packets: ${k}.`, { 'parser-evasion': 2, benign: -0.5 }, n));
  if (fileAnomalies.size) signals.push(sig('file', `The file structure itself is also damaged: ${[...fileAnomalies.keys()][0]}.`, { 'parser-evasion': 0.5, benign: 0.5 }, nos.slice(0, 1)));
  return [{ detector: 'evasion', topic: 'evasion', hypotheses: ['parser-evasion'], hosts: uniq(hits.map((p) => p.src ?? '').filter(Boolean)).slice(0, 8), ...span(ctx, nos), evidence: cap(nos), signals, benign: [check('damaged', 'Ordinary capture damage from a truncated file', false)], facts: { count: hits.length, kinds: [...kinds.keys()], host: hits[0]!.src ?? '' } }];
}

export function runDetectors(ctx: Ctx, fileAnomalies: Map<string, number>): Candidate[] {
  const { cands, sources } = scans(ctx);
  return [
    ...identity(ctx), ...rogueDhcp(ctx), ...dhcpFailure(ctx), ...dnsHijack(ctx), ...dnsHealth(ctx), ...cands, ...tcpHealth(ctx, sources),
    ...reachability(ctx, sources), ...mtu(ctx), ...delay(ctx), ...nameSpoof(ctx), ...dnsTunnel(ctx), ...behaviour(ctx), ...evasion(ctx, fileAnomalies),
  ];
}
