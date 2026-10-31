'use client';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { Finding, Report, StoryStep } from '@packetmd/core';
import { Hv } from '@/shell/Shell';
import { Proof } from './parts';

type Scene = StoryStep & { finding: Finding };

function Graph({ s, reduced, known }: { s: Scene; reduced: boolean; known: string[] }) {
  const hosts = known.slice(0, 8);
  const pos = (h: string) => { const i = hosts.indexOf(h), a = (i / Math.max(hosts.length, 1)) * Math.PI * 2 - Math.PI / 2; return [300 + 220 * Math.cos(a), 170 + 120 * Math.sin(a)] as const; };
  const edges = s.edges.filter((e) => hosts.includes(e.from) && hosts.includes(e.to) && e.from !== e.to);
  const dots = useRef<(SVGCircleElement | null)[]>([]);
  useEffect(() => {
    if (reduced) return;
    const anims = edges.map((e, i) => {
      const [x1, y1] = pos(e.from), [x2, y2] = pos(e.to);
      return dots.current[i]?.animate([{ transform: `translate(${x1}px, ${y1}px)`, opacity: 1 }, { transform: `translate(${x2}px, ${y2}px)`, opacity: 1 }], { duration: 900, delay: i * 180, iterations: Infinity, easing: 'ease-in-out' });
    });
    return () => anims.forEach((a) => a?.cancel());
  }, [s.key, s.finding.id, reduced]);
  const hit = new Set(s.key === 'affected' ? s.finding.blast : []);
  return (
    <svg className="stage-svg" viewBox="0 0 600 340" role="img" aria-label={s.caption}>
      {edges.map((e, i) => { const [x1, y1] = pos(e.from), [x2, y2] = pos(e.to); return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke={e.bad ? 'var(--ac)' : 'var(--bar)'} strokeWidth="1.5" />; })}
      {!reduced && edges.map((e, i) => <circle key={i} ref={(el) => { dots.current[i] = el; }} r="4" fill={e.bad ? 'var(--ac)' : 'var(--fg)'} opacity="0" />)}
      {hosts.map((h) => { const [x, y] = pos(h); return <g key={h}><rect x={x - 6} y={y - 6} width="12" height="12" fill={hit.has(h) ? 'var(--ac)' : 'var(--bg)'} stroke="var(--ac)" strokeWidth="1.5" /><text x={x} y={y + 24} textAnchor="middle">{h}</text></g>; })}
      {!hosts.length && <text x="300" y="170" textAnchor="middle">Not visible in this capture</text>}
    </svg>
  );
}

export function StoryPlayer({ r }: { r: Report }) {
  const told = r.findings.filter((f) => f.lane !== 'BENIGN');
  const [sel, setSel] = useState<string>(told[0]?.id ?? 'all');
  const [i, setI] = useState(0);
  const [play, setPlay] = useState(false);
  const [tech, setTech] = useState(false);
  const reduced = typeof matchMedia !== 'undefined' && matchMedia('(prefers-reduced-motion: reduce)').matches;
  const scenes: Scene[] = useMemo(() => {
    const list = sel === 'all' ? [...told].sort((a, b) => a.t0 - b.t0) : told.filter((f) => f.id === sel);
    return list.flatMap((f) => f.story.map((s) => ({ ...s, finding: f })));
  }, [sel, told]);
  useEffect(() => { setI(0); }, [sel]);
  useEffect(() => {
    if (!play) return;
    const id = setInterval(() => setI((x) => { if (x + 1 >= scenes.length) { setPlay(false); return x; } return x + 1; }), 3800);
    return () => clearInterval(id);
  }, [play, scenes.length]);
  const s = scenes[i];
  if (!s) return <p>No problems to tell a story about in this capture.</p>;
  // Hosts come from this finding's real addresses and edges, never from a template.
  const known = [...new Set([...s.finding.hosts, ...s.finding.story.flatMap((x) => x.edges.flatMap((e) => [e.from, e.to]))])];
  return (
    <div className="grid-side">
      <div className="veil" style={{ padding: 24 }}>
        <p className="sm" style={{ marginTop: 0 }}>{s.finding.title}, step {i + 1} of {scenes.length}</p>
        <h3 className="disp h3 flip" key={`${s.finding.id}${s.key}`}>{s.title}</h3>
        <Graph s={s} reduced={reduced} known={known} />
        <p style={{ fontSize: 17, lineHeight: 1.5 }} aria-live="polite">{tech ? s.technical || s.caption : s.caption}</p>
        {s.packets.length > 0 && <p><Proof nos={s.packets} /></p>}
        <input type="range" min={0} max={scenes.length - 1} value={i} aria-label="Story position" onChange={(e) => { setPlay(false); setI(+e.target.value); }} />
        <div className="mono" style={{ display: 'flex', flexWrap: 'wrap', gap: 24, fontSize: 13, marginTop: 10 }}>
          <Hv onClick={() => setI(Math.max(0, i - 1))}>Back</Hv>
          <Hv onClick={() => setPlay(!play)}>{play ? 'Pause' : 'Play'}</Hv>
          <Hv onClick={() => setI(Math.min(scenes.length - 1, i + 1))}>Next</Hv>
          <Hv aria-pressed={tech} onClick={() => setTech(!tech)}>{tech ? 'Plain words' : 'Technical'}</Hv>
        </div>
      </div>
      <aside aria-label="Stories">
        <p className="sm" style={{ marginTop: 0 }}>In real life</p>
        <p style={{ fontSize: 17, lineHeight: 1.5 }}>{s.finding.analogy}</p>
        {told.length > 1 && <button type="button" className={`rowbtn ${sel === 'all' ? 'on' : ''}`} style={{ gridTemplateColumns: '1fr' }} onClick={() => setSel('all')}>Play whole incident</button>}
        {told.map((f) => <button type="button" key={f.id} className={`rowbtn ${sel === f.id ? 'on' : ''}`} style={{ gridTemplateColumns: '1fr' }} onClick={() => setSel(f.id)}>{f.title}</button>)}
      </aside>
    </div>
  );
}
