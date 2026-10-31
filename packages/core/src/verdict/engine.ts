import { T } from '../thresholds';
import type { BenignCheck, Candidate, Hypothesis, Lane, Signal } from '../types';
import { HYPOTHESES } from './catalog';

export interface Case {
  topic: string; candidates: Candidate[]; hosts: string[]; t0: number; t1: number;
  hypotheses: Hypothesis[]; signals: Signal[]; benign: BenignCheck[];
  lane: Lane; top: string; margin: number; confidence: 'low' | 'medium' | 'high';
  facts: Candidate['facts'];
}

const overlaps = (a: Candidate, c: { t0: number; t1: number; hosts: Set<string> }) =>
  a.hosts.some((h) => c.hosts.has(h)) && a.t0 <= c.t1 + 60 && a.t1 >= c.t0 - 60;

/** Candidates merge only when they ask the same question about the same hosts at the same time. */
export function cluster(cands: Candidate[]): Candidate[][] {
  const groups: { items: Candidate[]; topic: string; t0: number; t1: number; hosts: Set<string> }[] = [];
  for (const c of [...cands].sort((a, b) => a.t0 - b.t0)) {
    const g = groups.find((x) => x.topic === c.topic && overlaps(c, x));
    if (g) { g.items.push(c); g.t0 = Math.min(g.t0, c.t0); g.t1 = Math.max(g.t1, c.t1); c.hosts.forEach((h) => g.hosts.add(h)); }
    else groups.push({ items: [c], topic: c.topic, t0: c.t0, t1: c.t1, hosts: new Set(c.hosts) });
  }
  return groups.map((g) => g.items);
}

export function softmax(scores: number[]) {
  const m = Math.max(...scores), e = scores.map((s) => Math.exp(s - m)), sum = e.reduce((a, b) => a + b, 0);
  return e.map((v) => v / sum);
}

export function decide(items: Candidate[]): Case {
  const ids = [...new Set(items.flatMap((c) => c.hypotheses)), 'benign'];
  const signals = items.flatMap((c) => c.signals);
  const benign = items.flatMap((c) => c.benign ?? []);
  const scores = ids.map((id) => HYPOTHESES[id]!.prior + signals.reduce((n, s) => n + (s.weights[id] ?? 0), 0));
  const probs = softmax(scores);
  const hypotheses: Hypothesis[] = ids.map((id, i) => ({ id, family: HYPOTHESES[id]!.family, title: HYPOTHESES[id]!.title, score: +scores[i]!.toFixed(2), prob: +probs[i]!.toFixed(4) })).sort((a, b) => b.prob - a.prob);
  const [first, second] = hypotheses as [Hypothesis, Hypothesis | undefined];
  const margin = first.prob - (second?.prob ?? 0);

  let lane: Lane = first.family === 'attack' ? 'ATTACK' : first.family === 'fault' ? 'FAULT' : 'BENIGN';
  // False-alarm guard: an innocent explanation that actually matched blocks the ATTACK label.
  if (lane === 'ATTACK' && (benign.some((b) => b.matched) || first.prob < T.MIN_ATTACK_PROB)) lane = 'INCONCLUSIVE';
  if (margin < T.MARGIN) lane = 'INCONCLUSIVE';
  const confidence = margin >= 0.7 ? 'high' : margin >= 0.4 ? 'medium' : 'low';

  return {
    topic: items[0]!.topic, candidates: items, hosts: [...new Set(items.flatMap((c) => c.hosts))],
    t0: Math.min(...items.map((c) => c.t0)), t1: Math.max(...items.map((c) => c.t1)),
    hypotheses, signals, benign, lane, top: first.id, margin: +margin.toFixed(3), confidence,
    facts: Object.assign({}, ...items.map((c) => c.facts)),
  };
}
