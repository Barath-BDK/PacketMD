import { BUDGET } from '../thresholds';
import { safeText } from '../sanitize';
import { md5 } from '../hash';
import type { Dhcp, Dns, DnsAnswer, Pkt, RawPacket, TreeNode } from '../types';

class Overrun extends Error {}

/** Bounds-checked reads: an overrun throws, it never returns junk. */
class Cur {
  constructor(public b: Uint8Array, public p = 0, public end = b.length) {}
  left() { return this.end - this.p; }
  need(n: number) { if (n < 0 || this.p + n > this.end) throw new Overrun(); }
  u8() { this.need(1); return this.b[this.p++]!; }
  u16() { this.need(2); const v = (this.b[this.p]! << 8) | this.b[this.p + 1]!; this.p += 2; return v; }
  u32() { const h = this.u16(); return h * 65536 + this.u16(); }
  skip(n: number) { this.need(n); this.p += n; }
  bytes(n: number) { this.need(n); const s = this.b.subarray(this.p, this.p + n); this.p += n; return s; }
}

const mac = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(':');
const ip4 = (b: Uint8Array) => `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
function ip6(b: Uint8Array) {
  const g: string[] = [];
  for (let i = 0; i < 16; i += 2) g.push(((b[i]! << 8) | b[i + 1]!).toString(16));
  return g.join(':').replace(/(^|:)0(:0)+(:|$)/, '::');
}
const ascii = (b: Uint8Array) => safeText(String.fromCharCode(...b.subarray(0, BUDGET.maxString)));

type Tree = TreeNode[] | null;
function node(t: Tree, label: string, start?: number, len?: number): Tree {
  if (!t) return null;
  const n: TreeNode = { label: safeText(label, 200), start, len, children: [] };
  t.push(n);
  return n.children!;
}

export const QTYPE: Record<number, string> = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS', 255: 'ANY' };
const RCODE: Record<number, string> = { 0: 'No error', 1: 'Format error', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'Refused' };
export const DHCP_MSG: Record<number, string> = { 1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 4: 'DECLINE', 5: 'ACK', 6: 'NAK', 7: 'RELEASE', 8: 'INFORM' };

function dnsName(c: Cur, msgStart: number, pkt: Pkt): string {
  const labels: string[] = [];
  let p = c.p, jumped = false, jumps = 0, total = 0;
  for (;;) {
    if (p >= c.end) throw new Overrun();
    const l = c.b[p]!;
    if ((l & 0xc0) === 0xc0) {
      if (p + 1 >= c.end) throw new Overrun();
      const target = msgStart + (((l & 0x3f) << 8) | c.b[p + 1]!);
      if (!jumped) { c.p = p + 2; jumped = true; }
      if (++jumps > BUDGET.maxDnsPointers || target >= p) { anomaly(pkt, 'DNS compression loop'); break; }
      p = target;
    } else if (l === 0) {
      if (!jumped) c.p = p + 1;
      break;
    } else if (l > 63) {
      anomaly(pkt, 'DNS label length invalid');
      if (!jumped) c.p = p + 1;
      break;
    } else {
      if (p + 1 + l > c.end) throw new Overrun();
      total += l + 1;
      if (total > BUDGET.maxString) {
        anomaly(pkt, 'DNS name longer than the 255 byte limit');
        if (!jumped) { let q = p; while (q < c.end && c.b[q]! !== 0 && (c.b[q]! & 0xc0) !== 0xc0) q += 1 + c.b[q]!; c.p = Math.min(q + 1, c.end); }
        break;
      }
      labels.push(String.fromCharCode(...c.b.subarray(p + 1, p + 1 + l)));
      p += 1 + l;
    }
  }
  return safeText(labels.join('.'));
}

function decodeDns(c: Cur, kind: Dns['kind'], pkt: Pkt, t: Tree) {
  const start = c.p;
  const id = c.u16(), fl = c.u16(), qd = c.u16(), an = c.u16(), ns = c.u16(), ar = c.u16();
  const tn = node(t, kind.toUpperCase(), start, c.end - start);
  node(tn, `Transaction ID: 0x${id.toString(16).padStart(4, '0')}`, start, 2);
  node(tn, `Flags: ${(fl & 0x8000) ? 'response' : 'query'}, rcode ${RCODE[fl & 15] ?? fl & 15}`, start + 2, 2);
  const dns: Dns = { id, qr: !!(fl & 0x8000), rcode: fl & 15, qname: '', qtype: 0, aa: !!(fl & 0x400), answers: [], kind };
  if (qd + an + ns + ar > BUDGET.maxDnsRecords) anomaly(pkt, 'DNS record count far beyond a real message');
  let budget = BUDGET.maxDnsRecords;
  for (let i = 0; i < qd && budget-- > 0; i++) {
    const s = c.p, name = dnsName(c, start, pkt), qt = c.u16();
    c.u16();
    if (i === 0) { dns.qname = name; dns.qtype = qt; }
    node(tn, `Query: ${name} (${QTYPE[qt] ?? qt})`, s, c.p - s);
  }
  for (let i = 0; i < an && budget-- > 0; i++) {
    const s = c.p, name = dnsName(c, start, pkt), type = c.u16();
    c.u16();
    const ttl = c.u32(), rd = c.u16();
    c.need(rd);
    const dStart = c.p;
    let data = '';
    if (type === 1 && rd === 4) data = ip4(c.b.subarray(c.p, c.p + 4));
    else if (type === 28 && rd === 16) data = ip6(c.b.subarray(c.p, c.p + 16));
    else if (type === 5 || type === 12 || type === 2) { const sub = new Cur(c.b, c.p, c.p + rd); sub.end = c.end; data = dnsName(sub, start, pkt); }
    else if (type === 16) data = ascii(c.b.subarray(c.p + 1, c.p + rd));
    c.p = dStart + rd;
    const a: DnsAnswer = { name, type, ttl, data };
    dns.answers.push(a);
    node(tn, `Answer: ${name} ${QTYPE[type] ?? type} ${data} ttl ${ttl}`, s, c.p - s);
  }
  pkt.dns = dns;
  pkt.proto = kind === 'dns' ? 'DNS' : kind === 'mdns' ? 'mDNS' : kind === 'llmnr' ? 'LLMNR' : 'NBNS';
  pkt.info = dns.qr
    ? `${dns.rcode ? RCODE[dns.rcode] ?? 'Error' : 'Response'} ${QTYPE[dns.qtype] ?? ''} ${dns.qname} ${dns.answers.map((a) => a.data).filter(Boolean).slice(0, 3).join(', ')}`.trim()
    : `Query ${QTYPE[dns.qtype] ?? ''} ${dns.qname}`;
}

function decodeNbns(c: Cur, pkt: Pkt, t: Tree) {
  const start = c.p;
  const id = c.u16(), fl = c.u16(), qd = c.u16(), an = c.u16();
  c.skip(4);
  c.u8();
  const enc = c.bytes(32);
  let name = '';
  for (let i = 0; i + 1 < 30; i += 2) name += String.fromCharCode(((enc[i]! - 65) << 4) | (enc[i + 1]! - 65));
  name = safeText(name.trim());
  c.skip(5);
  node(t, `NetBIOS name service: ${name}`, start, c.end - start);
  const dns: Dns = { id, qr: !!(fl & 0x8000), rcode: fl & 15, qname: name, qtype: 32, aa: true, answers: [], kind: 'nbns' };
  if (dns.qr && an && c.left() >= 16) { c.skip(12); dns.answers.push({ name, type: 1, ttl: 0, data: ip4(c.bytes(4)) }); }
  void qd;
  pkt.dns = dns; pkt.proto = 'NBNS';
  pkt.info = `${dns.qr ? 'Answer' : 'Query'} ${name}`;
}

function decodeDhcp(c: Cur, pkt: Pkt, t: Tree) {
  const start = c.p;
  const op = c.u8(); c.u8();
  const hlen = c.u8(); c.u8();
  const xid = c.u32();
  c.skip(8);
  const yi = ip4(c.bytes(4)); c.skip(4);
  const gi = ip4(c.bytes(4));
  const ch = c.bytes(16);
  c.skip(192);
  const cookie = c.u32();
  if (cookie !== 0x63825363) throw new Overrun();
  const d: Dhcp = { op, xid, msgType: 0, chaddr: mac(ch.subarray(0, Math.min(hlen, 6))), yiaddr: yi, giaddr: gi, dns: [] };
  const tn = node(t, 'DHCP', start, c.end - start);
  node(tn, `Transaction ID: 0x${xid.toString(16)}`, start + 4, 4);
  node(tn, `Your address: ${yi}`, start + 16, 4);
  node(tn, `Relay address: ${gi}`, start + 24, 4);
  node(tn, `Client MAC: ${d.chaddr}`, start + 28, 6);
  let guard = 0;
  while (c.left() > 0 && guard++ < 256) {
    const code = c.u8();
    if (code === 255) break;
    if (code === 0) continue;
    const len = c.u8(), s = c.p;
    const v = c.bytes(len);
    let label = `Option ${code}`;
    if (code === 53 && len >= 1) { d.msgType = v[0]!; label = `Message type: ${DHCP_MSG[d.msgType] ?? d.msgType}`; }
    if (code === 54 && len >= 4) { d.server = ip4(v); label = `Server identifier: ${d.server}`; }
    if (code === 3 && len >= 4) { d.router = ip4(v); label = `Router: ${d.router}`; }
    if (code === 1 && len >= 4) { d.mask = ip4(v); label = `Subnet mask: ${d.mask}`; }
    if (code === 6) { for (let i = 0; i + 4 <= len; i += 4) d.dns.push(ip4(v.subarray(i, i + 4))); label = `DNS servers: ${d.dns.join(', ')}`; }
    if (code === 12) { d.hostname = ascii(v); label = `Hostname: ${d.hostname}`; }
    if (code === 51 && len === 4) { d.lease = (v[0]! * 16777216) + ((v[1]! << 16) | (v[2]! << 8) | v[3]!); label = `Lease: ${d.lease}s`; }
    if (code === 50 && len >= 4) { d.requested = ip4(v); label = `Requested address: ${d.requested}`; }
    node(tn, label, s - 2, len + 2);
  }
  pkt.dhcp = d; pkt.proto = 'DHCP';
  pkt.info = `DHCP ${DHCP_MSG[d.msgType] ?? d.msgType} from ${d.chaddr}${d.yiaddr !== '0.0.0.0' ? ' offering ' + d.yiaddr : ''}`;
}

const grease = (v: number) => (v & 0x0f0f) === 0x0a0a && (v >> 8) === (v & 255);

function decodeTls(b: Uint8Array, start: number, end: number, pkt: Pkt, t: Tree) {
  const c = new Cur(b, start, end);
  if (c.u8() !== 22) return;
  c.skip(2);
  const recLen = c.u16();
  if (c.u8() !== 1) return;
  c.skip(3);
  const ver = c.u16();
  c.skip(32);
  c.skip(c.u8());
  const ciphers: number[] = [];
  const cl = c.u16();
  const ce = c.p + cl;
  c.need(cl);
  while (c.p + 2 <= ce) { const v = c.u16(); if (!grease(v)) ciphers.push(v); }
  c.skip(c.u8());
  const exts: number[] = [], curves: number[] = [], pf: number[] = [];
  let sni: string | undefined, ech = false;
  if (c.left() >= 2) {
    const el = c.u16(), ee = Math.min(c.p + el, c.end);
    while (c.p + 4 <= ee) {
      const ty = c.u16(), l = c.u16(), s = c.p;
      c.need(l);
      if (!grease(ty)) exts.push(ty);
      if (ty === 0 && l > 5) { const nl = (b[s + 3]! << 8) | b[s + 4]!; if (s + 5 + nl <= s + l) sni = ascii(b.subarray(s + 5, s + 5 + nl)); }
      if (ty === 0xfe0d || ty === 0xffce) ech = true;
      if (ty === 10) for (let i = s + 2; i + 2 <= s + l; i += 2) { const v = (b[i]! << 8) | b[i + 1]!; if (!grease(v)) curves.push(v); }
      if (ty === 11) for (let i = s + 1; i < s + l; i++) pf.push(b[i]!);
      c.p = s + l;
    }
  }
  const ja3 = md5(`${ver},${ciphers.join('-')},${exts.join('-')},${curves.join('-')},${pf.join('-')}`);
  pkt.tls = { sni, ja3, ech, version: ver };
  pkt.proto = 'TLS';
  pkt.info = `Client Hello${sni ? ' ' + sni : ech ? ' (name hidden by ECH)' : ''}`;
  const tn = node(t, 'TLS Client Hello', start, Math.min(recLen + 5, end - start));
  node(tn, `SNI: ${sni ?? 'none'}`);
  node(tn, `JA3-style hash: ${ja3}`);
}

const METHODS = /^(GET|POST|PUT|HEAD|DELETE|OPTIONS|CONNECT|PATCH) ([^ ]{1,512}) HTTP\/1\.[01]\r?$/;

function decodeHttp(b: Uint8Array, start: number, end: number, pkt: Pkt, t: Tree) {
  const text = String.fromCharCode(...b.subarray(start, Math.min(end, start + 2048)));
  const lines = text.split('\n');
  const m = METHODS.exec(lines[0]!);
  if (!m) return;
  pkt.http = { method: m[1]!, path: safeText(m[2]!) };
  for (const l of lines.slice(1, 40)) {
    const h = /^(host|user-agent): *(.*?)\r?$/i.exec(l);
    if (h) { if (h[1]!.toLowerCase() === 'host') pkt.http.host = safeText(h[2]!); else pkt.http.ua = safeText(h[2]!); }
  }
  pkt.proto = 'HTTP';
  pkt.info = `${m[1]} ${pkt.http.host ?? ''}${pkt.http.path}`;
  node(t, `HTTP: ${pkt.info}`, start, Math.min(end - start, lines[0]!.length));
}

function anomaly(pkt: Pkt, a: string) { (pkt.anomalies ??= []).includes(a) || pkt.anomalies.push(a); }

const TCP_FLAGS: [number, string][] = [[2, 'SYN'], [16, 'ACK'], [1, 'FIN'], [4, 'RST'], [8, 'PSH'], [32, 'URG']];
export const tcpFlagNames = (f: number) => TCP_FLAGS.filter(([b]) => f & b).map(([, n]) => n).join(', ');

function decodeTcp(c: Cur, pkt: Pkt, payloadEnd: number, t: Tree) {
  const s = c.p;
  const sport = c.u16(), dport = c.u16(), seq = c.u32(), ack = c.u32();
  const off = c.u8() >> 4, flags = c.u8(), win = c.u16();
  c.skip(4);
  const hl = off * 4;
  const tn = node(t, `TCP ${sport} to ${dport}`, s, Math.max(hl, 20));
  node(tn, `Source port: ${sport}`, s, 2);
  node(tn, `Destination port: ${dport}`, s + 2, 2);
  node(tn, `Sequence: ${seq}`, s + 4, 4);
  node(tn, `Acknowledgement: ${ack}`, s + 8, 4);
  node(tn, `Flags: ${tcpFlagNames(flags) || 'none'}`, s + 13, 1);
  node(tn, `Window: ${win}`, s + 14, 2);
  pkt.proto = 'TCP';
  if (hl < 20) { anomaly(pkt, 'TCP data offset below 20 bytes'); throw new Overrun(); }
  if (s + hl > payloadEnd) { anomaly(pkt, 'TCP data offset past end of packet'); throw new Overrun(); }
  let mss: number | undefined;
  let p = s + 20, opts = 0;
  while (p < s + hl) {
    const k = c.b[p]!;
    if (k === 0) break;
    if (k === 1) { p++; continue; }
    if (p + 1 >= s + hl) { anomaly(pkt, 'TCP option list overruns its header'); break; }
    const l = c.b[p + 1]!;
    if (l < 2 || p + l > s + hl) { anomaly(pkt, 'TCP option list overruns its header'); break; }
    if (k === 2 && l === 4) mss = (c.b[p + 2]! << 8) | c.b[p + 3]!;
    p += l;
    if (++opts > 40) { anomaly(pkt, 'TCP option list absurdly long'); break; }
  }
  const dataStart = s + hl, payload = Math.max(0, payloadEnd - dataStart);
  pkt.tcp = { sport, dport, seq, ack, flags, win, mss, payload, dataStart };
  pkt.info = `${sport} to ${dport} [${tcpFlagNames(flags)}] seq=${seq} win=${win} len=${payload}${mss ? ' mss=' + mss : ''}`;
  if (payload > 5) {
    const capEnd = Math.min(payloadEnd, c.end);
    if (dport === 53 || sport === 53) return;
    try { decodeTls(c.b, dataStart, capEnd, pkt, t); } catch (e) { if (!(e instanceof Overrun)) throw e; }
    if (!pkt.tls) decodeHttp(c.b, dataStart, capEnd, pkt, t);
  }
}

function decodeUdp(c: Cur, pkt: Pkt, payloadEnd: number, t: Tree) {
  const s = c.p;
  const sport = c.u16(), dport = c.u16(), len = c.u16();
  c.skip(2);
  const tn = node(t, `UDP ${sport} to ${dport}`, s, 8);
  node(tn, `Source port: ${sport}`, s, 2);
  node(tn, `Destination port: ${dport}`, s + 2, 2);
  node(tn, `Length: ${len}`, s + 4, 2);
  pkt.udp = { sport, dport, len, dataStart: c.p };
  pkt.proto = 'UDP';
  pkt.info = `${sport} to ${dport} len=${len}`;
  const has = (p: number) => sport === p || dport === p;
  const u = new Cur(c.b, c.p, Math.min(payloadEnd, c.end));
  // A well-known port does not make the payload that protocol: scanners send junk here, and it is not a crafted header.
  try {
    if (has(53)) decodeDns(u, 'dns', pkt, t);
    else if (has(5353)) decodeDns(u, 'mdns', pkt, t);
    else if (has(5355)) decodeDns(u, 'llmnr', pkt, t);
    else if (has(137)) decodeNbns(u, pkt, t);
    else if (has(67) || has(68)) decodeDhcp(u, pkt, t);
    else if (has(123)) { pkt.ntp = true; pkt.proto = 'NTP'; pkt.info = 'Time sync'; }
  } catch (e) { if (!(e instanceof Overrun)) throw e; }
}

function decodeIcmp(c: Cur, pkt: Pkt, t: Tree) {
  const s = c.p;
  const type = c.u8(), code = c.u8();
  c.skip(2);
  const r1 = c.u16(), r2 = c.u16();
  pkt.proto = 'ICMP';
  pkt.icmp = { type, code };
  node(t, `ICMP type ${type} code ${code}`, s, 8);
  pkt.info = type === 8 ? 'Echo request' : type === 0 ? 'Echo reply' : type === 3 ? `Destination unreachable (code ${code})` : type === 11 ? 'Time exceeded' : `Type ${type} code ${code}`;
  if (type === 3 && code === 4) {
    pkt.icmp.nextMtu = r2;
    pkt.info = `Fragmentation needed, next-hop MTU ${r2}`;
  }
  void r1;
  // Past the 16 bytes ping uses for timestamps, real pings repeat one pattern, so differing payloads mean real data.
  if ((type === 8 || type === 0) && c.left() >= 24) { c.skip(16); pkt.icmp.tail = Array.from(c.bytes(Math.min(32, c.left()))).join(','); }
  if (type === 3 && c.left() >= 20) {
    const inner = c.p;
    c.skip(9);
    pkt.icmp.innerProto = c.u8();
    c.skip(2);
    pkt.icmp.innerSrc = ip4(c.bytes(4));
    pkt.icmp.innerDst = ip4(c.bytes(4));
    void inner;
  }
}

function decodeArp(c: Cur, pkt: Pkt, t: Tree) {
  const s = c.p;
  c.skip(6);
  const op = c.u16();
  const sha = mac(c.bytes(6)), spa = ip4(c.bytes(4)), tha = mac(c.bytes(6)), tpa = ip4(c.bytes(4));
  pkt.arp = { op, sha, spa, tha, tpa };
  pkt.proto = 'ARP';
  pkt.src = spa; pkt.dst = tpa;
  pkt.info = op === 1 ? (spa === tpa ? `Announcement: ${spa} is at ${sha}` : `Who has ${tpa}? Tell ${spa}`) : `${spa} is at ${sha}`;
  const tn = node(t, `ARP ${op === 1 ? 'request' : 'reply'}`, s, 28);
  node(tn, `Opcode: ${op}`, s + 6, 2);
  node(tn, `Sender MAC: ${sha}`, s + 8, 6);
  node(tn, `Sender IP: ${spa}`, s + 14, 4);
  node(tn, `Target MAC: ${tha}`, s + 18, 6);
  node(tn, `Target IP: ${tpa}`, s + 24, 4);
}

function decodeIp4(c: Cur, pkt: Pkt, t: Tree) {
  const s = c.p;
  const vh = c.u8(), ihl = (vh & 15) * 4;
  pkt.ipv = 4;
  if (ihl < 20) { anomaly(pkt, 'IPv4 header length below 20 bytes'); pkt.proto = 'IPv4'; pkt.info = 'Malformed IPv4 header'; c.skip(11); pkt.src = ip4(c.bytes(4)); pkt.dst = ip4(c.bytes(4)); return; }
  c.u8();
  const total = c.u16(), id = c.u16(), ff = c.u16(), ttl = c.u8(), proto = c.u8();
  c.skip(2);
  pkt.src = ip4(c.bytes(4)); pkt.dst = ip4(c.bytes(4));
  pkt.ttl = ttl; pkt.ipProto = proto; pkt.ipId = id; pkt.ipLen = total;
  pkt.df = !!(ff & 0x4000); pkt.mf = !!(ff & 0x2000); pkt.fragOff = (ff & 0x1fff) * 8;
  const tn = node(t, `IPv4 ${pkt.src} to ${pkt.dst}`, s, ihl);
  node(tn, `Total length: ${total}`, s + 2, 2);
  node(tn, `Identification: ${id}`, s + 4, 2);
  node(tn, `Flags: ${pkt.df ? 'DF ' : ''}${pkt.mf ? 'MF' : ''}`, s + 6, 2);
  node(tn, `TTL: ${ttl}`, s + 8, 1);
  node(tn, `Protocol: ${proto}`, s + 9, 1);
  node(tn, `Source: ${pkt.src}`, s + 12, 4);
  node(tn, `Destination: ${pkt.dst}`, s + 16, 4);
  c.skip(ihl - 20);
  const end = s + total;
  if (total < ihl) anomaly(pkt, 'IPv4 total length shorter than its header');
  if (end > c.end + 4096) anomaly(pkt, 'IPv4 total length past end of packet');
  pkt.proto = 'IPv4'; pkt.info = `IP protocol ${proto}`;
  if (pkt.fragOff) { pkt.info = `Fragment at offset ${pkt.fragOff}`; return; }
  const payloadEnd = total >= ihl ? Math.min(end, c.end) : c.end;
  if (proto === 6) decodeTcp(c, pkt, Math.min(end, c.end + 65535), t);
  else if (proto === 17) decodeUdp(c, pkt, payloadEnd, t);
  else if (proto === 1) decodeIcmp(c, pkt, t);
}

function decodeIp6(c: Cur, pkt: Pkt, t: Tree) {
  const s = c.p;
  c.skip(4);
  const pl = c.u16(), nh = c.u8(), hop = c.u8();
  pkt.ipv = 6; pkt.src = ip6(c.bytes(16)); pkt.dst = ip6(c.bytes(16)); pkt.ttl = hop; pkt.ipProto = nh;
  node(t, `IPv6 ${pkt.src} to ${pkt.dst}`, s, 40);
  pkt.proto = 'IPv6'; pkt.info = `Next header ${nh}`;
  const end = Math.min(c.p + pl, c.end);
  if (nh === 6) decodeTcp(c, pkt, c.p + pl, t);
  else if (nh === 17) decodeUdp(c, pkt, end, t);
  else if (nh === 58) { pkt.proto = 'ICMPv6'; pkt.info = 'ICMPv6'; if (c.left() > 0) pkt.icmp6 = c.u8(); }
}

/** Decodes one packet. With a tree array it also records each field's byte range. */
export function decode(raw: RawPacket, tree: Tree = null): Pkt {
  const pkt: Pkt = { no: raw.no, ts: raw.ts, len: raw.origLen, capLen: raw.capLen, recordOffset: raw.recordOffset, dataOffset: raw.dataOffset, blockType: raw.blockType, proto: 'Unknown', info: '' };
  const c = new Cur(raw.data);
  try {
    let et: number;
    if (raw.linkType === 1) {
      const s = c.p;
      pkt.dstMac = mac(c.bytes(6)); pkt.srcMac = mac(c.bytes(6)); et = c.u16();
      const tn = node(tree, `Ethernet ${pkt.srcMac} to ${pkt.dstMac}`, s, 14);
      node(tn, `Destination: ${pkt.dstMac}`, s, 6);
      node(tn, `Source: ${pkt.srcMac}`, s + 6, 6);
      node(tn, `Type: 0x${et.toString(16)}`, s + 12, 2);
      let depth = 0;
      while ((et === 0x8100 || et === 0x88a8) && depth++ < 4) {
        const vs = c.p;
        pkt.vlan = c.u16() & 0xfff; et = c.u16();
        node(tree, `VLAN ${pkt.vlan}`, vs, 4);
      }
      if (depth > 1) pkt.vlanDepth = depth;
    } else if (raw.linkType === 101) {
      et = ((raw.data[0] ?? 0) >> 4) === 6 ? 0x86dd : 0x0800;
    } else if (raw.linkType === 113) {
      c.skip(14); et = c.u16();
    } else if (raw.linkType === 0) {
      c.skip(4); et = ((raw.data[4] ?? 0) >> 4) === 6 ? 0x86dd : 0x0800;
    } else {
      pkt.info = `Unsupported link type ${raw.linkType}`;
      return pkt;
    }
    if (et === 0x0806) decodeArp(c, pkt, tree);
    else if (et === 0x0800) decodeIp4(c, pkt, tree);
    else if (et === 0x86dd) decodeIp6(c, pkt, tree);
    else { pkt.proto = `0x${et.toString(16)}`; pkt.info = `EtherType 0x${et.toString(16)}`; }
  } catch (e) {
    if (!(e instanceof Overrun)) throw e;
    anomaly(pkt, 'Packet shorter than its own headers claim');
    pkt.info ||= 'Malformed packet';
  }
  pkt.info = safeText(pkt.info);
  return pkt;
}
