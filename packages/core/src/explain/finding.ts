import type { Ctx } from '../context';
import type { Evidence, Finding, StoryStep } from '../types';
import type { Case } from '../verdict/engine';
import { HYPOTHESES } from '../verdict/catalog';
import { nextCapture, TEMPLATES } from './templates';

const ROOTS = ['arp-spoof', 'rogue-dhcp-attack', 'rogue-dhcp-misconfig', 'dns-hijack', 'mtu-blackhole', 'server-outage', 'syn-flood', 'duplicate-ip'];
const SYMPTOMS = ['tcp-loss', 'dns-failure', 'high-latency', 'tcp-reset', 'syn-unanswered'];
const dedupe = (a: number[]) => [...new Set(a)].sort((x, y) => x - y);

function evidenceOf(ctx: Ctx, nos: number[]): Evidence[] {
  return nos.slice(0, 60).map((n) => { const p = ctx.get(n); return { no: n, ts: p.ts, proto: p.proto, info: p.info, recordOffset: p.recordOffset, dataOffset: p.dataOffset, capLen: p.capLen, blockType: p.blockType }; });
}

const pct = (p: number) => `${(p * 100).toFixed(1)}%`;
function sureWords(p: number) { return p > 0.95 ? 'almost certain' : p > 0.75 ? 'very likely' : p > 0.5 ? 'likely' : 'only possible'; }

function levelsOf(c: Case, f: Finding): Finding['levels'] {
  const [a, b] = c.hypotheses;
  const led = c.signals.map((s) => `${s.id}: ${Object.entries(s.weights).map(([k, v]) => `${k} ${v > 0 ? '+' : ''}${v}`).join(', ')}`).join('; ');
  const score = c.hypotheses.map((h) => `${h.id} score=${h.score} p=${h.prob.toFixed(4)}`).join('; ');
  return {
    beginner: { what: f.plain, why: f.cause, rule: f.whyNotTheOther, sure: `We think this is ${sureWords(a!.prob)}.${b ? ` The next best idea, "${b.title.toLowerCase()}", is ${sureWords(b.prob)}.` : ''}` },
    technical: { what: f.technical, why: `${f.cause} ${c.signals.slice(0, 3).map((s) => s.label).join(' ')}`, rule: `${f.whyNotTheOther} ${a!.title} ${pct(a!.prob)}${b ? ` against ${b.title} ${pct(b.prob)}` : ''}.`, sure: `Margin ${Math.round(c.margin * 100)} points across ${c.signals.length} signals.` },
    analyst: { what: f.analyst, why: led, rule: score, sure: `margin=${c.margin} lane=${c.lane} benign_checks=${c.benign.length} matched=${c.benign.filter((x) => x.matched).length}` },
  };
}

function gapOf(c: Case) {
  if (c.topic === 'identity') return 'A saved baseline showing who really owns this address, or a capture from the gateway port showing whether traffic is being relayed. Either one settles it.';
  if (c.topic === 'dhcp') return 'A baseline naming your real DHCP server, or DNS traffic from a client that took this lease.';
  if (c.topic === 'reachability') return 'A view from the server side showing whether the requests arrive at all.';
  return 'More traffic from the moment the problem happens, ideally closer to the affected host.';
}

function story(ctx: Ctx, c: Case, f: Finding): StoryStep[] {
  const t = TEMPLATES[f.hypothesis]!, facts = c.facts;
  const lines = (nos: number[]) => nos.slice(0, 5).map((n) => `#${n} ${ctx.get(n).proto} ${ctx.get(n).info}`).join(' | ');
  const edge = (pn: number, bad = true) => { const p = ctx.get(pn); return { from: p.src ?? p.srcMac ?? '?', to: p.dst ?? p.dstMac ?? '?', label: p.proto, bad }; };
  const make = (key: string, title: string, caption: string, technical: string, packets: number[], bad = true): StoryStep => ({ key, title, caption, technical, analyst: lines(packets) || technical, packets, edges: packets.slice(0, 6).map((n) => edge(n, bad)) });
  const forH = (h: string) => c.signals.filter((s) => (s.weights[h] ?? 0) > 0).sort((x, y) => (y.weights[h] ?? 0) - (x.weights[h] ?? 0));
  const seen = f.evidence.map((e) => e.no).slice(0, 8);

  if (f.lane === 'BENIGN') {
    const [, rival] = c.hypotheses;
    const fine = forH('benign'), flag = c.signals.filter((s) => !fine.includes(s));
    const pass = c.benign.filter((b) => b.matched);
    return [
      make('seen', 'What caught our eye', flag[0]?.label ?? fine[0]?.label ?? f.evidence[0]!.info, f.technical, seen, false),
      make('flag', 'Why it raised a question', rival ? `At first glance this can look like ${rival.title.toLowerCase()}, so PacketMD checked it.` : 'Unusual traffic always gets checked before it is cleared.', flag.map((s) => s.label).join(' '), (flag[0]?.packets ?? seen).slice(0, 6), false),
      make('cleared', 'Why it is harmless', fine.map((s) => s.label).join(' ') || pass.map((b) => b.label).join('. ') || 'The attack signals never appeared.', pass.map((b) => `Matched: ${b.label}`).join('. '), (fine[0]?.packets ?? pass[0]?.packets ?? seen).slice(0, 6), false),
      make('verdict', 'Verdict: nothing to do', f.cause, `${c.hypotheses[0]!.title} ${pct(c.hypotheses[0]!.prob)}`, [], false),
    ];
  }

  if (f.lane === 'INCONCLUSIVE') {
    const [a, b] = c.hypotheses;
    const sa = forH(a!.id), sb = forH(b!.id);
    return [
      make('seen', 'What we saw', `${seen.length} packets around ${c.hosts[0] ?? 'this host'} do not fit normal behaviour.`, f.evidence[0]?.info ?? '', seen, false),
      make('case-a', `The case for ${a!.title.toLowerCase()}`, sa.map((s) => s.label).join(' ') || 'Nothing points here strongly.', `${a!.title}: ${pct(a!.prob)}`, (sa[0]?.packets ?? []).slice(0, 6)),
      make('case-b', `The case for ${b!.title.toLowerCase()}`, sb.map((s) => s.label).join(' ') || 'Nothing points here strongly.', `${b!.title}: ${pct(b!.prob)}`, (sb[0]?.packets ?? []).slice(0, 6), b!.family === 'attack'),
      make('gap', 'What is missing', `Both explanations fit the evidence, with only ${Math.round(c.margin * 100)} points between them. ${gapOf(c)}`, `Margin ${c.margin}, a verdict needs at least 0.2.`, []),
      make('next', 'What to capture next', f.nextCapture ?? gapOf(c), 'Open the new capture here and the verdict updates.', []),
    ];
  }
  const evNos = f.evidence.map((e) => e.no);
  // The story starts at the packet behind the strongest signal, which may come after earlier innocent evidence.
  const strongest = [...c.signals].sort((x, y) => (y.weights[f.hypothesis] ?? 0) - (x.weights[f.hypothesis] ?? 0))[0];
  const startNo = strongest?.packets.length ? Math.min(...strongest.packets) : f.evidence[0]?.no;
  const first = startNo ? evidenceOf(ctx, [startNo])[0] : undefined;
  const before = ctx.flows.filter((x) => x.t0 < c.t0 && (c.hosts.includes(x.a) || c.hosts.includes(x.b))).slice(0, 4);
  const steps: StoryStep[] = [
    { key: 'before', title: 'Normal before it started', caption: before.length ? `${before.length} ordinary conversations were running between these hosts.` : 'Not visible in this capture: it starts when the problem is already underway.', technical: before.map((x) => `${x.a} to ${x.b}:${x.pb}`).join('; '), analyst: lines(before.map((x) => x.first)), packets: before.map((x) => x.first), edges: before.map((x) => ({ from: x.a, to: x.b, label: `${x.proto} ${x.pb}` })) },
  ];
  if (first) steps.push({ key: 'start', title: 'Where it started', caption: `Packet ${first.no} is the first sign: ${first.info}.`, technical: `File offset 0x${first.recordOffset.toString(16)}, capture time ${new Date(first.ts * 1000).toISOString()}`, analyst: lines([first.no]), packets: [first.no], t: first.ts, edges: [edge(first.no)] });
  steps.push({ key: 'how', title: 'How it was done', caption: f.plain, technical: f.technical, analyst: f.analyst, packets: evNos.slice(0, 8), edges: evNos.slice(0, 6).map((n) => edge(n)) });
  steps.push({ key: 'affected', title: 'What is affected', caption: f.blast.length ? `Affected: ${f.blast.join(', ')}.` : 'Not visible in this capture.', technical: `${f.blast.length} hosts in the blast radius`, analyst: f.blast.join(', '), packets: evNos.slice(0, 3), edges: [] });
  steps.push({ key: 'evidence', title: 'Evidence', caption: `${f.signals.length} signals point here, tied to ${f.evidence.length} packets.`, technical: f.signals.map((s) => s.label).join(' '), analyst: lines(evNos), packets: evNos.slice(0, 12), edges: [] });
  steps.push({ key: 'fix', title: 'How to fix it', caption: f.fixSteps.map((s) => s.title).join('. ') || 'No fix needed.', technical: t.verify(facts), analyst: f.fixSteps.map((s) => s.linux ?? s.router ?? s.windows ?? s.title).join(' | '), packets: [], edges: [] });
  return steps;
}

export function toFinding(ctx: Ctx, c: Case, n: number): Finding | null {
  const id = c.lane === 'INCONCLUSIVE' ? c.top : c.lane === 'BENIGN' ? 'benign' : c.top;
  const t = TEMPLATES[id]!;
  const f = c.facts;
  const nos = dedupe(c.candidates.flatMap((x) => x.evidence));
  // Claim-to-packet binding: no proof packets, no finding.
  if (!nos.length) return null;
  const finding: Finding = {
    id: `F${n}`,
    fingerprint: `${id}|${(c.hosts[0] ?? '')}|${f.macB ?? f.server ?? f.source ?? f.qname ?? ''}`,
    lane: c.lane, hypothesis: id, title: c.lane === 'BENIGN' && f.benignKind ? String(f.benignKind) : HYPOTHESES[id]!.title,
    confidence: c.confidence, margin: c.margin, hypotheses: c.hypotheses, signals: c.signals, benign: c.benign,
    hosts: c.hosts, blast: c.hosts, t0: c.t0, t1: c.t1,
    plain: t.plain(f), technical: t.technical(f), analyst: t.analyst(f), cause: t.cause(f), whyNotTheOther: t.whyNot(f), analogy: t.analogy,
    wireshark: t.filter(f), bpf: t.bpf(f), fixSteps: t.fix(f), verifyBy: t.verify(f),
    levels: {} as Finding['levels'], evidence: evidenceOf(ctx, nos), story: [], priority: 0,
  };
  if (c.lane === 'INCONCLUSIVE') {
    const [a, b] = c.hypotheses;
    finding.title = `${a!.title} or ${b!.title}`;
    finding.plain = `The evidence does not settle this. It leans towards "${a!.title.toLowerCase()}" but "${b!.title.toLowerCase()}" fits too, so PacketMD will not label it.`;
    finding.nextCapture = nextCapture(c);
    finding.fixSteps = [];
  }
  finding.levels = levelsOf(c, finding);
  finding.story = story(ctx, c, finding);
  return finding;
}

/** Links symptoms to root causes and orders what to fix first. */
export function chain(fs: Finding[]) {
  for (const s of fs.filter((x) => SYMPTOMS.includes(x.hypothesis))) {
    const roots = fs.filter((r) => r !== s && ROOTS.includes(r.hypothesis) && r.lane !== 'BENIGN' && r.t0 <= s.t1 && r.hosts.some((h) => s.hosts.includes(h)));
    if (roots.length) {
      s.causedBy = roots.map((r) => r.id);
      roots.forEach((r) => { r.blast = [...new Set([...r.blast, ...s.hosts])]; });
    }
  }
  const rank: Record<string, number> = { ATTACK: 3, FAULT: 2, INCONCLUSIVE: 1, BENIGN: 0 };
  fs.forEach((f) => { f.priority = rank[f.lane]! * 100 + (ROOTS.includes(f.hypothesis) ? 50 : 0) + (f.causedBy ? -40 : 0) + f.blast.length; });
  fs.sort((a, b) => b.priority - a.priority);
}

export function headline(fs: Finding[]) {
  const n = (l: string) => fs.filter((f) => f.lane === l).length;
  const a = n('ATTACK'), b = n('FAULT'), c = n('INCONCLUSIVE');
  if (!a && !b && !c) return 'No faults or attacks found in this capture.';
  const parts = [a && `${a} attack${a > 1 ? 's' : ''}`, b && `${b} fault${b > 1 ? 's' : ''}`, c && `${c} unsettled`].filter(Boolean);
  const top = fs.find((f) => f.lane !== 'BENIGN');
  return `${parts.join(', ')}. Deal with ${top!.title.toLowerCase()} first.`;
}
