'use client';
import { useMemo, useRef, useState } from 'react';
import type { Report } from '@packetmd/core';
import { useCase } from '@/lib/engine';
import { Lane } from './parts';

const DETAIL: [string, number][] = [['Coarse', 40], ['Normal', 80], ['Fine', 160]];
const kb = (n: number) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} B`);

export function TimeChart({ r, compact }: { r: Report; compact?: boolean }) {
  const c = useCase();
  const [metric, setMetric] = useState<'pkts' | 'bytes'>('pkts');
  const [bins, setBins] = useState(80);
  const [focus, setFocus] = useState('all');
  const [view, setView] = useState<[number, number] | null>(null);
  const [tip, setTip] = useState<{ x: number; i: number } | null>(null);
  const [drag, setDrag] = useState<[number, number] | null>(null);
  const area = useRef<HTMLDivElement>(null);
  const span = Math.max(r.t1 - r.t0, 0.001);
  const [a, b] = view ?? [r.t0, r.t0 + span * 1.0001];
  const shown = r.findings.filter((f) => f.lane !== 'BENIGN');

  const data = useMemo(() => {
    const proof = new Set((focus === 'all' ? shown : shown.filter((f) => f.id === focus)).flatMap((f) => f.evidence.map((e) => e.no)));
    const out = Array.from({ length: bins }, () => ({ all: 0, hot: 0, first: 0 }));
    const w = (b - a) / bins;
    const slot = (ts: number) => out[Math.min(bins - 1, Math.floor((ts - a) / w))]!;
    if (r.rows.length) for (const row of r.rows) {
      if (row.ts < a || row.ts >= b) continue;
      const bin = slot(row.ts), v = metric === 'pkts' ? 1 : row.len;
      bin.all += v;
      if (proof.has(row.no)) bin.hot += v;
      bin.first ||= row.no;
    } else {
      // A saved report keeps per-period totals and proof packets, never the packet list.
      for (const t of r.timeline) if (t.t >= a && t.t < b) slot(t.t).all += metric === 'pkts' ? t.pkts : t.bytes;
      if (metric === 'pkts') for (const f of (focus === 'all' ? shown : shown.filter((x) => x.id === focus))) for (const e of f.evidence) if (e.ts >= a && e.ts < b) { const bin = slot(e.ts); bin.hot = Math.min(bin.hot + 1, bin.all); }
    }
    return out;
  }, [r, a, b, bins, metric, focus, shown]);
  const max = Math.max(...data.map((d) => d.all), 1);
  const fmtV = (v: number) => (metric === 'pkts' ? String(v) : kb(v));
  const places = b - a < 10 ? 2 : b - a < 100 ? 1 : 0;
  const stamp = (t: number) => `+${(t - r.t0).toFixed(places)} s`;
  const stampAbs = (t: number) => `+${(t - r.t0).toFixed(span < 10 ? 2 : 1)} s`;
  const pick = (f: Report['findings'][number]) => {
    if (focus === f.id) { setFocus('all'); setView(null); return; }
    const pad = Math.max((f.t1 - f.t0) * 0.1, span * 0.01);
    setFocus(f.id); setView([Math.max(r.t0, f.t0 - pad), Math.min(r.t1 + 0.001, f.t1 + pad)]);
  };
  const frac = (e: React.PointerEvent) => { const q = area.current!.getBoundingClientRect(); return Math.max(0, Math.min(1, (e.clientX - q.left) / q.width)); };
  const up = (e: React.PointerEvent) => {
    if (!drag) return;
    const x = frac(e), lo = Math.min(drag[0], x), hi = Math.max(drag[0], x);
    setDrag(null);
    if (!compact && hi - lo > 0.015) { setView([a + lo * (b - a), a + hi * (b - a)]); return; }
    const row = data[Math.min(bins - 1, Math.floor(x * bins))];
    if (row?.first) { c.setJump(row.first); c.setTab('investigator'); }
  };
  const H = compact ? 120 : 260;
  const tipData = tip && data[tip.i];
  return (
    <div className={compact ? '' : 'veil'} style={compact ? {} : { padding: 20 }}>
      {!compact && (
        <div className="flt" role="toolbar" aria-label="Timeline options" style={{ alignItems: 'center', marginTop: 0 }}>
          <span className="sm">Show</span>
          {([['pkts', 'Packets'], ['bytes', 'Bytes']] as const).map(([k, l]) => <button type="button" key={k} className="btn" aria-pressed={metric === k} onClick={() => setMetric(k)}>{l}</button>)}
          <span className="sm" style={{ marginLeft: 12 }}>Detail</span>
          {DETAIL.map(([l, n]) => <button type="button" key={l} className="btn" aria-pressed={bins === n} onClick={() => setBins(n)}>{l}</button>)}
          {(view || focus !== 'all') && <button type="button" className="btn" style={{ marginLeft: 12 }} onClick={() => { setView(null); setFocus('all'); }}>Show whole capture</button>}
        </div>
      )}
      <div className="chart-grid">
        <div className="dat" aria-hidden="true" style={{ height: H, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', textAlign: 'right' }}><span>{fmtV(max)}</span><span>{fmtV(Math.round(max / 2))}</span><span>0</span></div>
        <div>
          <div ref={area} className="chart" role="img" aria-label={`${metric === 'pkts' ? 'Packets' : 'Bytes'} over time. Red shows proof packets.`} style={{ height: H, borderBottom: '1px solid var(--bar)', borderTop: '1px dashed var(--line)' }}
            onPointerDown={(e) => { const x = frac(e); setDrag([x, x]); e.currentTarget.setPointerCapture(e.pointerId); }}
            onPointerMove={(e) => { const x = frac(e); setTip({ x, i: Math.min(bins - 1, Math.floor(x * bins)) }); if (drag) setDrag([drag[0], x]); }}
            onPointerUp={up} onPointerLeave={() => setTip(null)}>
            <div className="chart-bars">
              {data.map((d, i) => <div key={i}>
                {d.all > d.hot && <i style={{ height: `${((d.all - d.hot) / max) * 100}%` }} />}
                {d.hot > 0 && <i className="hot" style={{ height: `${(d.hot / max) * 100}%` }} />}
              </div>)}
            </div>
            {drag && !compact && <div className="chart-sel" style={{ left: `${Math.min(...drag) * 100}%`, width: `${Math.abs(drag[0] - drag[1]) * 100}%` }} />}
            {tip && tipData && !drag && <div className="chart-tip" style={tip.x > 0.65 ? { right: `${(1 - tip.x) * 100}%` } : { left: `${tip.x * 100}%` }}>{stamp(a + (tip.i / bins) * (b - a))}: {fmtV(tipData.all)}{tipData.hot ? `, ${fmtV(tipData.hot)} proof` : ''}</div>}
          </div>
          <div className="dat axis" aria-hidden="true">{[0, 0.25, 0.5, 0.75, 1].map((f) => <span key={f}>{stamp(a + f * (b - a))}</span>)}</div>
        </div>
      </div>
      <p className="sm" style={{ marginBottom: compact ? 0 : undefined }}>{r.defense.packets} packets over {span.toFixed(1)} s. Red is proof packets. {compact ? (r.rows.length ? 'Click a bar to open its packets.' : '') : `Drag across the chart to zoom in.${r.rows.length ? ' Click a bar to open its packets.' : ''}`}</p>
      {!compact && shown.length > 0 && <div role="group" aria-label="Problems in this capture">
        <h3 className="sm" style={{ margin: '16px 0 4px' }}>Click a problem to focus on it</h3>
        {shown.map((f) => <button type="button" key={f.id} className="tl-prob" aria-pressed={focus === f.id} onClick={() => pick(f)}>
          <span>{f.title}</span><span className="dat">{stampAbs(f.t0)} to {stampAbs(f.t1)}</span><Lane l={f.lane} />
        </button>)}
      </div>}
      {!compact && r.findings.filter((f) => f.lane === 'BENIGN').map((f) => <p key={f.id} className="sm"><Lane l="BENIGN" /> {f.title}: not marked in red.</p>)}
    </div>
  );
}
