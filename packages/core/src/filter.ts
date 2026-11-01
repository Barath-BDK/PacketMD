import { safeText } from './sanitize';
import type { Finding, PacketRow } from './types';

export class FilterError extends Error {}
type Test = (r: PacketRow) => boolean;
type Env = { findings: Finding[] };

// The token limit also bounds bracket and "not" nesting, so a filter can never run the stack out.
export const FILTER_MAX_CHARS = 512;
const MAX_TOKENS = 100, FLAGS = new Set(['retransmit', 'rst', 'zerowin']);
const show = (s: string) => safeText(s, 40);
const number = (v: string, max: number, what: string) => {
  if (!/^\d{1,10}$/.test(v) || +v > max) throw new FilterError(`${what} must be a whole number up to ${max}.`);
  return +v;
};
const port = (v: string) => number(v, 65535, 'A port');
const frame = (v: string) => number(v, 4294967295, 'A packet number');

const tok = (s: string) => s.match(/"[^"]*"|\(|\)|&&|\|\||==|[^\s()=]+/g) ?? [];

const FIELDS: Record<string, (v: string, env: Env) => Test> = {
  'ip.addr': (v) => (r) => r.src === v || r.dst === v,
  'ip.src': (v) => (r) => r.src === v,
  'ip.dst': (v) => (r) => r.dst === v,
  'tcp.port': (v) => { const n = port(v); return (r) => r.proto !== 'UDP' && (r.sport === n || r.dport === n); },
  'udp.port': (v) => { const n = port(v); return (r) => r.sport === n || r.dport === n; },
  proto: (v) => (r) => r.proto.toLowerCase() === v.toLowerCase(),
  mac: (v) => (r) => r.srcMac === v.toLowerCase() || r.dstMac === v.toLowerCase(),
  domain: (v) => (r) => (r.domain ?? '').toLowerCase().includes(v.toLowerCase()),
  host: (v) => (r) => r.src === v || r.dst === v || (r.domain ?? '') === v,
  flag: (v) => {
    if (!FLAGS.has(v)) throw new FilterError('Use flag:retransmit, flag:rst or flag:zerowin.');
    return (r) => !!r.flags?.includes(v);
  },
  'frame.number': (v) => { const n = frame(v); return (r) => r.no === n; },
};

/** Own filter language. Everything is compiled to closures, nothing is ever evaluated as code. */
export function parseFilter(src: string, env: Env): Test {
  if (src.length > FILTER_MAX_CHARS) throw new FilterError(`That filter is too long. Keep it under ${FILTER_MAX_CHARS} characters.`);
  const t = tok(safeText(src.trim()));
  if (t.length > MAX_TOKENS) throw new FilterError('That filter has too many parts. Try a shorter one.');
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
      if (!f) throw new FilterError(`There is no finding called ${show(w.slice(8))}.`);
      const set = new Set(f.evidence.map((e) => e.no));
      return (r) => set.has(r.no);
    }
    if (w.startsWith('flag:')) return FIELDS.flag!(w.slice(5), env);
    if (peek() === 'contains' && (w === 'dns.qry.name' || w === 'domain')) {
      i++;
      const v = (t[i++] ?? '').replace(/"/g, '').toLowerCase();
      if (!v) throw new FilterError(`"${w} contains" needs some text to look for.`);
      return (r) => (w === 'domain' ? r.domain ?? '' : r.qname ?? '').toLowerCase().includes(v);
    }
    if (w === 'frame.number' && peek() === 'in') {
      i++;
      const m = /^(\d{1,10})-(\d{1,10})$/.exec(t[i++] ?? '');
      if (!m) throw new FilterError('Write a range like frame.number in 10-20.');
      const from = frame(m[1]!), to = frame(m[2]!);
      return (r) => r.no >= from && r.no <= to;
    }
    if (t[i] !== '==') throw new FilterError(`"${show(w)}" needs a value, for example ip.addr == 10.0.0.1.`);
    i++;
    const v = t[i++];
    if (v === undefined) throw new FilterError(`"${show(w)}" has no value.`);
    // Own keys only: "constructor" and "__proto__" exist on every object.
    const mk = Object.prototype.hasOwnProperty.call(FIELDS, w) ? FIELDS[w] : undefined;
    if (!mk) throw new FilterError(`PacketMD does not know the field "${show(w)}".`);
    return mk(v.replace(/"/g, ''), env);
  };
  const res = or();
  if (i < t.length) throw new FilterError(`Unexpected "${show(t[i]!)}".`);
  return res;
}
