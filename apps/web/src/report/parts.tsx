'use client';
import { useState } from 'react';
import { locator, neutralize, toMarkdown, type Evidence, type Finding, type Report } from '@packetmd/core';
import { useCase } from '@/lib/engine';

export function Lane({ l }: { l: string }) { return <span className={`lane lane-${l}`}>{l}</span>; }

export function Copy({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [s, set] = useState(label);
  return <button type="button" className="cr-btn st sm" style={{ borderBottom: '1px solid var(--line)', padding: '2px 0' }} onClick={() => navigator.clipboard.writeText(text).then(() => set('Copied'), () => set('Copy blocked'))}>{s}</button>;
}

export function Proof({ nos }: { nos: number[] }) {
  const c = useCase();
  return <>{nos.slice(0, 10).map((n) => <button type="button" key={n} className="cr-btn chip" aria-label={`Open packet ${n}`} onClick={() => { c.setJump(n); c.setTab('investigator'); }}>#{n}</button>)}{nos.length > 10 && <span className="sm">+{nos.length - 10} more</span>}</>;
}

export function Bars({ r, onPick }: { r: Report; onPick?: (t: number) => void }) {
  const max = Math.max(...r.timeline.map((b) => b.pkts), 1);
  const hot = (t: number) => r.findings.some((f) => f.lane !== 'BENIGN' && t >= f.t0 - 0.5 && t <= f.t1 + 0.5);
  return <div className="bars" role="img" aria-label="Packets over time, with problem periods in the accent colour">{r.timeline.map((b, i) => <i key={i} className={hot(b.t) ? 'hot' : ''} title={`${b.pkts} packets`} onClick={() => onPick?.(b.t)} style={{ height: `${Math.max(2, (b.pkts / max) * 100)}%` }} />)}</div>;
}

const text = (f: Finding, level: string) => (level === 'beginner' ? f.plain : level === 'technical' ? f.technical : f.analyst);

export function Levels() {
  const c = useCase();
  return <div role="group" aria-label="Reading level" className="mono" style={{ display: 'flex', gap: 20, fontSize: 13 }}>{(['beginner', 'technical', 'analyst'] as const).map((l) => <button type="button" key={l} className="cr-btn under st" aria-pressed={c.level === l} onClick={() => c.setLevel(l)} style={{ textTransform: 'capitalize' }}>{l}</button>)}</div>;
}

export function FindingCard({ f, r }: { f: Finding; r: Report }) {
  const c = useCase();
  const causes = (f.causedBy ?? []).map((id) => r.findings.find((x) => x.id === id)?.title).filter(Boolean);
  const first: Evidence | undefined = f.evidence[0];
  return (
    <article className="veil" style={{ padding: '24px', borderLeft: `2px solid ${f.lane === 'ATTACK' ? 'var(--ac)' : 'var(--line)'}`, marginBottom: 24 }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16, alignItems: 'baseline', justifyContent: 'space-between' }}>
        <h3 className="disp h3">{f.title}</h3>
        <span><Lane l={f.lane} /> <span className="sm" style={{ marginLeft: 10 }}>{f.confidence} confidence</span></span>
      </div>
      <p style={{ fontSize: 17, lineHeight: 1.5, maxWidth: '70ch' }}>{text(f, c.level)}</p>
      <p style={{ margin: '6px 0' }}><Proof nos={f.evidence.map((e) => e.no)} /></p>
      {causes.length > 0 && <p className="muted">Likely a side effect of: {causes.join(', ')}.</p>}
      {f.nextCapture && <p><span className="sm">Capture this next</span><br />{f.nextCapture}</p>}
      <div className="grid-2" style={{ marginTop: 16 }}>
        <div><h4 className="sm" style={{ margin: 0 }}>Why it happened</h4><p style={{ lineHeight: 1.5 }}>{f.cause}</p></div>
        <div><h4 className="sm" style={{ margin: 0 }}>Why not the other explanation</h4><p style={{ lineHeight: 1.5 }}>{f.whyNotTheOther}</p></div>
      </div>
      <p style={{ lineHeight: 1.5 }}><span className="sm">In real life: </span>{f.analogy}</p>
      {c.level === 'analyst' && first && <div style={{ display: 'grid', gap: 8, marginTop: 8 }}>
        <p className="dat" style={{ margin: 0 }}>{locator(first)} <Copy text={locator(first)} label="Copy locator" /></p>
        {f.wireshark && <p className="dat" style={{ margin: 0 }}>Wireshark: {f.wireshark} <Copy text={f.wireshark} /></p>}
        {f.bpf && <p className="dat" style={{ margin: 0 }}>BPF: {f.bpf} <Copy text={f.bpf} /></p>}
      </div>}
    </article>
  );
}

export function FixPlan({ r }: { r: Report }) {
  const [os, setOs] = useState<'windows' | 'linux' | 'router'>('windows');
  const [done, setDone] = useState<Record<string, boolean>>({});
  const todo = r.findings.filter((f) => f.fixSteps.length);
  if (!todo.length) return <p>Nothing to fix in this capture.</p>;
  return (
    <div>
      <div role="group" aria-label="Platform" className="mono" style={{ display: 'flex', gap: 20, fontSize: 13, marginBottom: 16 }}>
        {(['windows', 'linux', 'router'] as const).map((o) => <button type="button" key={o} className="cr-btn under st" aria-pressed={os === o} onClick={() => setOs(o)} style={{ textTransform: 'capitalize' }}>{o}</button>)}
      </div>
      {todo.map((f, n) => (
        <section key={f.id} className="veil" style={{ padding: 24, marginBottom: 24 }}>
          <h3 className="disp h3">{n + 1}. {f.title}</h3>
          <ol style={{ listStyle: 'none', padding: 0, margin: '12px 0' }}>
            {f.fixSteps.map((s, i) => {
              const k = `${f.id}.${i}`, cmd = s[os];
              return (
                <li key={k} style={{ padding: '12px 0', borderBottom: '1px solid var(--line)' }}>
                  <label style={{ display: 'flex', gap: 10, alignItems: 'baseline' }}>
                    <input type="checkbox" checked={!!done[k]} onChange={(e) => setDone({ ...done, [k]: e.target.checked })} />
                    <span style={{ fontWeight: 600, textDecoration: done[k] ? 'line-through' : 'none' }}>{s.title}</span>
                  </label>
                  <p className="muted" style={{ margin: '6px 0' }}>{s.why}</p>
                  {cmd ? <><code className="cmd">{cmd}</code><p style={{ margin: '6px 0 0' }}><Copy text={cmd} label="Copy command" /></p></> : <p className="sm">No {os} command for this step.</p>}
                </li>
              );
            })}
          </ol>
          <p><span className="sm">Check it worked: </span>{f.verifyBy}</p>
        </section>
      ))}
    </div>
  );
}

export function Differential({ r }: { r: Report }) {
  const [sel, set] = useState(r.findings[0]?.id);
  const f = r.findings.find((x) => x.id === sel);
  if (!f) return <p>No cases in this capture.</p>;
  return (
    <div className="grid-side">
      <div className="veil" style={{ padding: 24 }}>
        <h3 className="disp h3">{f.title}</h3>
        <p className="sm">Margin between first and second place: {Math.round(f.margin * 100)} points</p>
        {f.hypotheses.map((h, i) => (
          <div key={h.id} style={{ padding: '10px 0' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}><span>{h.title}</span><span className="dat">{(h.prob * 100).toFixed(1)}%</span></div>
            <div className="pbar"><i className={i === 0 ? 'top' : ''} style={{ width: `${h.prob * 100}%` }} /></div>
          </div>
        ))}
        <h4 className="sm" style={{ marginTop: 24 }}>Signal ledger</h4>
        <table className="t"><thead><tr><th scope="col">Signal</th><th scope="col">Pushes towards</th><th scope="col">Proof</th></tr></thead>
          <tbody>{f.signals.map((s, i) => (
            <tr key={i}><td>{s.label}</td><td className="dat">{Object.entries(s.weights).map(([k, v]) => <div key={k}>{v > 0 ? '+' : ''}{v} {k}</div>)}</td><td><Proof nos={s.packets.slice(0, 3)} /></td></tr>
          ))}</tbody></table>
        {f.benign.length > 0 && <><h4 className="sm" style={{ marginTop: 24 }}>Innocent explanations checked</h4>
          {f.benign.map((b) => <p key={b.id} style={{ margin: '6px 0' }}><span className="sm">{b.matched ? 'Matched' : 'Ruled out'}: </span>{b.label}</p>)}</>}
      </div>
      <aside aria-label="Cases">{r.findings.map((x) => <button type="button" key={x.id} className={`rowbtn ${x.id === sel ? 'on' : ''}`} style={{ gridTemplateColumns: '1fr' }} onClick={() => set(x.id)}><span>{x.title}</span><Lane l={x.lane} /></button>)}</aside>
    </div>
  );
}

export function download(name: string, body: string, type: string) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([body], { type }));
  a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
export const exportMd = (r: Report) => download('packetmd-report.md', toMarkdown(r), 'text/markdown');
export const exportJson = (r: Report) => { const { rows: _x, ...rest } = r; download('packetmd-report.json', JSON.stringify(rest, null, 2), 'application/json'); };
export const cell = neutralize;
