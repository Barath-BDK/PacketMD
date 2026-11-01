'use client';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { Finding, Report, StoryStep } from '@packetmd/core';
import { useCase } from '@/lib/engine';
import { Hv } from '@/shell/Shell';
import { Lane, Proof } from './parts';

type Scene = StoryStep & { finding: Finding };

const STEP_MS = 4200;

function Graph({ s, reduced, known }: { s: Scene; reduced: boolean; known: string[] }) {
  const hosts = known.slice(0, 8);
  const pos = (h: string) => { const i = hosts.indexOf(h), a = (i / Math.max(hosts.length, 1)) * Math.PI * 2 - Math.PI / 2; return [300 + 230 * Math.cos(a), 150 + 110 * Math.sin(a)] as const; };
  const edges = s.edges.filter((e) => hosts.includes(e.from) && hosts.includes(e.to) && e.from !== e.to);
  const dots = useRef<(SVGCircleElement | null)[]>([]);
  useEffect(() => {
    if (reduced) return;
    const anims = edges.map((e, i) => {
      const [x1, y1] = pos(e.from), [x2, y2] = pos(e.to);
      return dots.current[i]?.animate([{ transform: `translate(${x1}px, ${y1}px)`, opacity: 1 }, { transform: `translate(${x2}px, ${y2}px)`, opacity: 1 }], { duration: 1000, delay: i * 180, iterations: Infinity, easing: 'ease-in-out' });
    });
    return () => anims.forEach((a) => a?.cancel());
  }, [s.key, s.finding.id, reduced]);
  const hit = new Set(s.key === 'affected' ? s.finding.blast : []);
  return (
    <svg className="stage-svg" viewBox="0 0 600 320" role="img" aria-label={s.caption}>
      {edges.map((e, i) => { const [x1, y1] = pos(e.from), [x2, y2] = pos(e.to); return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke={e.bad ? 'var(--ac)' : 'var(--bar)'} strokeWidth="1.5" />; })}
      {!reduced && edges.map((e, i) => <circle key={i} ref={(el) => { dots.current[i] = el; }} r="4" fill={e.bad ? 'var(--ac)' : 'var(--fg)'} opacity="0" />)}
      {hosts.map((h) => { const [x, y] = pos(h); return <g key={h}><rect x={x - 6} y={y - 6} width="12" height="12" fill={hit.has(h) ? 'var(--ac)' : 'var(--bg)'} stroke="var(--ac)" strokeWidth="1.5" /><text x={x} y={y + 24} textAnchor="middle">{h}</text></g>; })}
      {!hosts.length && <text x="300" y="160" textAnchor="middle">Not visible in this capture</text>}
    </svg>
  );
}

export function StoryPlayer({ r }: { r: Report }) {
  const c = useCase();
  const told = r.findings;
  const problems = told.filter((f) => f.lane !== 'BENIGN');
  const [sel, setSel] = useState<string>(told[0]?.id ?? 'all');
  const [i, setI] = useState(0);
  const [play, setPlay] = useState(false);
  const reduced = typeof matchMedia !== 'undefined' && matchMedia('(prefers-reduced-motion: reduce)').matches;
  const scenes: Scene[] = useMemo(() => {
    const list = sel === 'all' ? [...problems].sort((a, b) => a.t0 - b.t0) : told.filter((f) => f.id === sel);
    return list.flatMap((f) => f.story.map((s) => ({ ...s, finding: f })));
  }, [sel, r]);
  const bar = useRef<HTMLInputElement>(null), left = useRef<HTMLSpanElement>(null), pos = useRef(0);
  // Painted straight to the DOM, so a 60 fps slider does not re-render the whole story.
  const paint = (p: number) => {
    if (bar.current) { bar.current.value = String(p); bar.current.style.setProperty('--p', `${(p / Math.max(scenes.length, 1)) * 100}%`); }
    if (left.current) left.current.textContent = `${Math.ceil(((scenes.length - p) * STEP_MS) / 1000)} s left`;
  };
  const seek = (p: number) => { pos.current = p; paint(p); setI(Math.min(Math.floor(p), Math.max(scenes.length - 1, 0))); };
  useEffect(() => { setPlay(false); seek(0); }, [sel]);
  useEffect(() => {
    if (!play) return;
    // A timer, not requestAnimationFrame, so the time left stays true in a throttled tab.
    let last = performance.now();
    const id = setInterval(() => {
      const now = performance.now();
      pos.current += (now - last) / STEP_MS;
      last = now;
      if (pos.current >= scenes.length) { clearInterval(id); seek(scenes.length); setPlay(false); return; }
      paint(pos.current);
      const n = Math.floor(pos.current);
      setI((x) => (x === n ? x : n));
    }, 33);
    return () => clearInterval(id);
  }, [play, scenes.length]);
  const s = scenes[i];
  if (!s) return (
    <div className="veil" style={{ padding: 24 }}>
      <h3 className="disp h3">Nothing to tell</h3>
      <p style={{ lineHeight: 1.5, maxWidth: '60ch' }}>Every detector ran across {r.defense.packets} packets and none found a fault, an attack or anything odd enough to explain away.</p>
    </div>
  );
  // Hosts come from this finding's real addresses and edges, never from a template.
  const known = [...new Set([...s.finding.hosts, ...s.finding.story.flatMap((x) => x.edges.flatMap((e) => [e.from, e.to]))])];
  const text = c.level === 'beginner' ? s.caption : c.level === 'technical' ? s.technical || s.caption : s.analyst || s.technical;
  return (
    <div className="story">
      <div className="story-l">
        <p className="sm" style={{ margin: 0 }}>{s.finding.title}, step {i + 1} of {scenes.length}</p>
        <div className="story-g"><Graph s={s} reduced={reduced} known={known} /></div>
        <input ref={bar} type="range" min={0} max={scenes.length} step={0.01} defaultValue={0} aria-label="Story position" onChange={(e) => { setPlay(false); seek(+e.target.value); }} />
        <div className="mono" style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 24, fontSize: 13 }}>
          <Hv onClick={() => seek(Math.max(0, i - 1))}>Back</Hv>
          <Hv onClick={() => { if (pos.current >= scenes.length) seek(0); setPlay(!play); }}>{play ? 'Pause' : 'Play'}</Hv>
          <Hv onClick={() => seek(Math.min(scenes.length - 1, i + 1))}>Next</Hv>
          <span ref={left} className="sm" style={{ marginLeft: 'auto' }} />
        </div>
      </div>
      <div className="story-r" data-lenis-prevent>
        <div style={{ marginBottom: 6 }}><Lane l={s.finding.lane} /></div>
        <h3 className="disp h3 flip" key={`${s.finding.id}${s.key}`} style={{ marginBottom: 10 }}>{s.title}</h3>
        <p style={{ fontSize: 17, lineHeight: 1.5, marginTop: 0, overflowWrap: 'anywhere' }} aria-live="polite">{text}</p>
        {s.packets.length > 0 && <p><Proof nos={s.packets} /></p>}
        <p style={{ lineHeight: 1.5 }}><span className="sm">In real life: </span>{s.finding.analogy}</p>
        {told.length > 1 && <div style={{ marginTop: 16 }}>
          <p className="sm">Choose a story</p>
          {problems.length > 1 && <button type="button" className={`rowbtn pick ${sel === 'all' ? 'on' : ''}`} style={{ gridTemplateColumns: '1fr' }} onClick={() => setSel('all')}>Play whole incident</button>}
          {told.map((f) => <button type="button" key={f.id} className={`rowbtn pick ${sel === f.id ? 'on' : ''}`} style={{ gridTemplateColumns: '1fr' }} onClick={() => setSel(f.id)}>{f.title}</button>)}
        </div>}
      </div>
    </div>
  );
}
