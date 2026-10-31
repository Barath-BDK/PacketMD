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

function story(ctx: Ctx, c: Case, f: Finding): StoryStep[] {
  const t = TEMPLATES[f.hypothesis]!, facts = c.facts;
  const evNos = f.evidence.map((e) => e.no);
  // The story starts at the packet behind the strongest signal, which may come after earlier innocent evidence.
  const strongest = [...c.signals].sort((x, y) => (y.weights[f.hypothesis] ?? 0) - (x.weights[f.hypothesis] ?? 0))[0];
  const startNo = strongest?.packets.length ? Math.min(...strongest.packets) : f.evidence[0]?.no;
  const first = startNo ? evidenceOf(ctx, [startNo])[0] : undefined;
  const before = ctx.flows.filter((x) => x.t0 < c.t0 && (c.hosts.includes(x.a) || c.hosts.includes(x.b))).slice(0, 4);
  const edgeOf = (pn: number, bad = true) => { const p = ctx.get(pn); return { from: p.src ?? p.srcMac ?? '?', to: p.dst ?? p.dstMac ?? '?', label: p.proto, bad }; };
  const steps: StoryStep[] = [
    { key: 'before', title: 'Normal before it started', caption: before.length ? `${before.length} ordinary conversations were running between these hosts.` : 'Not visible in this capture: it starts when the problem is already underway.', technical: before.map((x) => `${x.a} to ${x.b}:${x.pb}`).join('; '), packets: before.map((x) => x.first), edges: before.map((x) => ({ from: x.a, to: x.b, label: `${x.proto} ${x.pb}` })) },
  ];
  if (first) steps.push({ key: 'start', title: 'Where it started', caption: `Packet ${first.no} is the first sign: ${first.info}.`, technical: `File offset 0x${first.recordOffset.toString(16)}, capture time ${new Date(first.ts * 1000).toISOString()}`, packets: [first.no], t: first.ts, edges: [edgeOf(first.no)] });
  steps.push({ key: 'how', title: 'How it was done', caption: f.plain, technical: f.technical, packets: evNos.slice(0, 8), edges: evNos.slice(0, 6).map((n) => edgeOf(n)) });
  steps.push({ key: 'affected', title: 'What is affected', caption: f.blast.length ? `Affected: ${f.blast.join(', ')}.` : 'Not visible in this capture.', technical: `${f.blast.length} hosts in the blast radius`, packets: evNos.slice(0, 3), edges: [] });
  steps.push({ key: 'evidence', title: 'Evidence', caption: `${f.signals.length} signals point here, tied to ${f.evidence.length} packets.`, technical: f.signals.map((s) => s.label).join(' '), packets: evNos.slice(0, 12), edges: [] });
  steps.push({ key: 'fix', title: 'How to fix it', caption: f.fixSteps.map((s) => s.title).join('. ') || 'No fix needed.', technical: t.verify(facts), packets: [], edges: [] });
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
    evidence: evidenceOf(ctx, nos), story: [], priority: 0,
  };
  if (c.lane === 'INCONCLUSIVE') {
    const [a, b] = c.hypotheses;
    finding.title = `${a!.title} or ${b!.title}`;
    finding.plain = `The evidence does not settle this. It leans towards "${a!.title.toLowerCase()}" but "${b!.title.toLowerCase()}" fits too, so PacketMD will not label it.`;
    finding.nextCapture = nextCapture(c);
    finding.fixSteps = [];
  }
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
