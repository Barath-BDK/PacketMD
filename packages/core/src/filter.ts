import type { Finding, PacketRow } from './types';

export class FilterError extends Error {}
type Test = (r: PacketRow) => boolean;
type Env = { findings: Finding[] };

const tok = (s: string) => s.match(/"[^"]*"|\(|\)|&&|\|\||==|[^\s()=]+/g) ?? [];

const FIELDS: Record<string, (v: string, env: Env) => Test> = {
  'ip.addr': (v) => (r) => r.src === v || r.dst === v,
  'ip.src': (v) => (r) => r.src === v,
  'ip.dst': (v) => (r) => r.dst === v,
  'tcp.port': (v) => (r) => r.proto !== 'UDP' && (r.sport === +v || r.dport === +v),
  'udp.port': (v) => (r) => r.sport === +v || r.dport === +v,
  proto: (v) => (r) => r.proto.toLowerCase() === v.toLowerCase(),
  mac: (v) => (r) => r.srcMac === v.toLowerCase() || r.dstMac === v.toLowerCase(),
  domain: (v) => (r) => (r.domain ?? '').toLowerCase().includes(v.toLowerCase()),
  host: (v) => (r) => r.src === v || r.dst === v || (r.domain ?? '') === v,
  flag: (v) => (r) => !!r.flags?.includes(v),
  'frame.number': (v) => (r) => r.no === +v,
};

/** Own filter language. Everything is compiled to closures, nothing is ever evaluated as code. */
export function parseFilter(src: string, env: Env): Test {
  const t = tok(src.trim());
  if (!t.length) return () => true;
  let i = 0;
  const peek = () => t[i]?.toLowerCase();
  const or = (): Test => { let a = and(); while (peek() === 'or' || peek() === '||') { i++; const x = a, y = and(); a = (r) => x(r) || y(r); } return a; };
  const and = (): Test => { let a = not(); while (peek() === 'and' || peek() === '&&') { i++; const x = a, y = not(); a = (r) => x(r) && y(r); } return a; };
  const not = (): Test => { if (peek() === 'not' || peek() === '!') { i++; const x = not(); return (r) => !x(r); } return atom(); };
  const atom = (): Test => {
    const w = t[i++];
    if (!w) throw new FilterError('The filter ends too early.');
    if (w === '(') { const x = or(); if (t[i++] !== ')') throw new FilterError('A bracket was opened but never closed.'); return x; }
    if (w.startsWith('finding:')) {
      const f = env.findings.find((x) => x.id.toLowerCase() === w.slice(8).toLowerCase());
      if (!f) throw new FilterError(`There is no finding called ${w.slice(8)}.`);
      const set = new Set(f.evidence.map((e) => e.no));
      return (r) => set.has(r.no);
    }
    if (w.startsWith('flag:')) return FIELDS.flag!(w.slice(5), env);
    if (peek() === 'contains' && (w === 'dns.qry.name' || w === 'domain')) {
      i++;
      const v = (t[i++] ?? '').replace(/"/g, '').toLowerCase();
      return (r) => (w === 'domain' ? r.domain ?? '' : r.qname ?? '').toLowerCase().includes(v);
    }
    if (w === 'frame.number' && peek() === 'in') {
      i++;
      const m = /^(\d+)-(\d+)$/.exec(t[i++] ?? '');
      if (!m) throw new FilterError('Write a range like frame.number in 10-20.');
      return (r) => r.no >= +m[1]! && r.no <= +m[2]!;
    }
    if (t[i] !== '==') throw new FilterError(`"${w}" needs a value, for example ip.addr == 10.0.0.1.`);
    i++;
    const v = t[i++];
    if (v === undefined) throw new FilterError(`"${w}" has no value.`);
    const mk = FIELDS[w];
    if (!mk) throw new FilterError(`PacketMD does not know the field "${w}".`);
    return mk(v.replace(/"/g, ''), env);
  };
  const res = or();
  if (i < t.length) throw new FilterError(`Unexpected "${t[i]}".`);
  return res;
}
