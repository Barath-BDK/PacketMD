'use client';
import { useState } from 'react';
import { locator, neutralize, toMarkdown, type Evidence, type Finding, type Report } from '@packetmd/core';
import { useCase } from '@/lib/engine';

export function Lane({ l }: { l: string }) { return <span className={`lane lane-${l}`}>{l}</span>; }

export function Copy({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [s, set] = useState(label);
  const flash = (m: string) => { set(m); setTimeout(() => set(label), 1500); };
  return <button type="button" className="cr-btn st sm" style={{ borderBottom: '1px solid var(--line)', padding: '2px 0' }} onClick={() => navigator.clipboard.writeText(text).then(() => flash('Copied'), () => flash('Copy blocked'))}>{s}</button>;
}

export function Proof({ nos }: { nos: number[] }) {
  const c = useCase();
  return <>{nos.slice(0, 10).map((n) => <button type="button" key={n} className="cr-btn chip" aria-label={`Open packet ${n}`} onClick={() => { c.setJump(n); c.setTab('investigator'); }}>#{n}</button>)}{nos.length > 10 && <span className="sm">+{nos.length - 10} more</span>}</>;
}

export function Levels() {
  const c = useCase();
  return <div role="group" aria-label="Reading level" className="mono levels" style={{ display: 'flex', gap: 16, fontSize: 13 }}>{(['beginner', 'technical', 'analyst'] as const).map((l) => <button type="button" key={l} className="cr-btn under st" aria-pressed={c.level === l} onClick={() => c.setLevel(l)} style={{ textTransform: 'capitalize' }}>{l}</button>)}</div>;
}

const HEAD = {
  beginner: { why: 'Why it happened', rule: 'Why it is not something else', sure: 'How sure are we' },
  technical: { why: 'Root cause', rule: 'Differential', sure: 'Confidence' },
  analyst: { why: 'Signal weights', rule: 'Hypothesis scores', sure: 'Decision state' },
};

export function FindingCard({ f, r }: { f: Finding; r: Report }) {
  const c = useCase(), t = f.levels[c.level], h = HEAD[c.level];
  const causes = (f.causedBy ?? []).map((id) => r.findings.find((x) => x.id === id)?.title).filter(Boolean);
  const first: Evidence | undefined = f.evidence[0];
  const raw = c.level === 'analyst';
  return (
    <article className="veil" style={{ padding: 24, borderLeft: `2px solid ${f.lane === 'ATTACK' ? 'var(--ac)' : 'var(--line)'}`, marginBottom: 24 }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16, alignItems: 'baseline', justifyContent: 'space-between' }}>
        <h3 className="disp h3">{f.title}</h3>
        <span><Lane l={f.lane} /> <span className="sm" style={{ marginLeft: 10 }}>{f.confidence} confidence</span></span>
      </div>
      <p className={raw ? 'dat' : ''} style={{ fontSize: raw ? undefined : 17, lineHeight: 1.5, maxWidth: '76ch', overflowWrap: 'anywhere' }}>{t.what}</p>
      <p style={{ margin: '6px 0' }}><Proof nos={f.evidence.map((e) => e.no)} /></p>
      {causes.length > 0 && <p className="muted">{c.level === 'beginner' ? 'This is probably a side effect of' : 'Caused by'}: {causes.join(', ')}.</p>}
      {f.nextCapture && <p><span className="sm">Capture this next</span><br />{f.nextCapture}</p>}
      <div className="grid-2" style={{ marginTop: 16 }}>
        <div><h4 className="sm" style={{ margin: 0 }}>{h.why}</h4><p className={raw ? 'dat' : ''} style={{ lineHeight: 1.5, overflowWrap: 'anywhere' }}>{t.why}</p></div>
        <div><h4 className="sm" style={{ margin: 0 }}>{h.rule}</h4><p className={raw ? 'dat' : ''} style={{ lineHeight: 1.5, overflowWrap: 'anywhere' }}>{t.rule}</p></div>
      </div>
      <p className={raw ? 'dat' : ''} style={{ lineHeight: 1.5 }}><span className="sm">{h.sure}: </span>{t.sure}</p>
      {c.level === 'beginner' && <p style={{ lineHeight: 1.5 }}><span className="sm">In real life: </span>{f.analogy}</p>}
      {c.level !== 'beginner' && <div style={{ display: 'grid', gap: 8, marginTop: 8 }}>
        {raw && first && <p className="dat" style={{ margin: 0 }}>{locator(first)} <Copy text={locator(first)} label="Copy locator" /></p>}
        {f.wireshark && <p className="dat" style={{ margin: 0 }}>Wireshark: {f.wireshark} <Copy text={f.wireshark} /></p>}
        {f.bpf && <p className="dat" style={{ margin: 0 }}>BPF: {f.bpf} <Copy text={f.bpf} /></p>}
      </div>}
      {raw && <div style={{ overflowX: 'auto', marginTop: 12 }}><table className="t"><thead><tr><th scope="col">No.</th><th scope="col">Proto</th><th scope="col">Offset</th><th scope="col">Info</th></tr></thead>
        <tbody>{f.evidence.slice(0, 8).map((e) => <tr key={e.no}><td className="dat">{e.no}</td><td className="dat">{e.proto}</td><td className="dat">0x{e.dataOffset.toString(16)}</td><td className="dat">{e.info}</td></tr>)}</tbody></table></div>}
    </article>
  );
}

export function FixPlan({ r }: { r: Report }) {
  const c = useCase();
  const [os, setOs] = useState<'windows' | 'linux' | 'router'>('windows');
  const [done, setDone] = useState<Record<string, boolean>>({});
  const todo = r.findings.filter((f) => f.fixSteps.length);
  if (!todo.length) return <p>Nothing to fix in this capture.</p>;
  return (
    <div>
      <div role="group" aria-label="Platform" className="flt" style={{ marginTop: 0 }}>
        {(['windows', 'linux', 'router'] as const).map((o) => <button type="button" key={o} className="btn" aria-pressed={os === o} onClick={() => setOs(o)} style={{ textTransform: 'capitalize' }}>{o}</button>)}
      </div>
      {todo.map((f, n) => (
        <section key={f.id} className="veil" style={{ padding: 24, marginBottom: 24 }}>
          <h3 className="disp h3">{n + 1}. {f.title}</h3>
          <ol style={{ listStyle: 'none', padding: 0, margin: '12px 0' }}>
            {f.fixSteps.map((s, i) => {
              const k = `${f.id}.${i}`, cmd = s[os];
              const box = cmd ? <><code className="cmd">{cmd}</code><p style={{ margin: '6px 0 0' }}><Copy text={cmd} label="Copy command" /></p></> : <p className="sm">No {os} command for this step.</p>;
              return (
                <li key={k} style={{ padding: '12px 0', borderBottom: '1px solid var(--line)' }}>
                  <label style={{ display: 'flex', gap: 10, alignItems: 'baseline' }}>
                    <input type="checkbox" checked={!!done[k]} onChange={(e) => setDone({ ...done, [k]: e.target.checked })} />
                    <span style={{ fontWeight: 600, textDecoration: done[k] ? 'line-through' : 'none' }}>{s.title}</span>
                  </label>
                  {c.level !== 'analyst' && <p className="muted" style={{ margin: '6px 0' }}>{s.why}</p>}
                  {c.level === 'beginner' ? <details style={{ marginTop: 6 }}><summary className="sm">Show the command</summary><div style={{ marginTop: 8 }}>{box}</div></details> : <div style={{ marginTop: 8 }}>{box}</div>}
                </li>
              );
            })}
          </ol>
          <p><span className="sm">Check it worked: </span>{f.verifyBy}</p>
          {c.level === 'analyst' && f.wireshark && <p className="dat" style={{ marginBottom: 0 }}>Re-check with: {f.wireshark} <Copy text={f.wireshark} /></p>}
        </section>
      ))}
    </div>
  );
}

const odds = (p: number) => (p > 0.95 ? 'Almost certain' : p > 0.75 ? 'Very likely' : p > 0.5 ? 'Likely' : p > 0.15 ? 'Possible' : 'Unlikely');

export function Differential({ r }: { r: Report }) {
  const c = useCase();
  const [sel, set] = useState(r.findings[0]?.id);
  const f = r.findings.find((x) => x.id === sel);
  if (!f) return <p>No cases in this capture.</p>;
  const b = c.level === 'beginner', a = c.level === 'analyst';
  return (
    <div className="grid-side">
      <div className="veil" style={{ padding: 24 }}>
        <h3 className="disp h3">{f.title}</h3>
        <p className="sm">{b ? 'Each possible explanation competes on the evidence.' : `Margin between first and second place: ${Math.round(f.margin * 100)} points`}</p>
        {f.hypotheses.map((h, i) => (
          <div key={h.id} style={{ padding: '10px 0' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}><span>{h.title}</span><span className="dat">{b ? odds(h.prob) : a ? `score ${h.score}, p ${h.prob.toFixed(4)}` : `${(h.prob * 100).toFixed(1)}%`}</span></div>
            <div className="pbar"><i className={i === 0 ? 'top' : ''} style={{ width: `${h.prob * 100}%` }} /></div>
          </div>
        ))}
        <h4 className="sm" style={{ marginTop: 24 }}>{b ? 'What we noticed' : 'Signal ledger'}</h4>
        <div style={{ overflowX: 'auto' }}><table className="t"><thead><tr><th scope="col">{b ? 'Clue' : 'Signal'}</th><th scope="col">{b ? 'Points to' : 'Weight'}</th><th scope="col">Proof</th></tr></thead>
          <tbody>{f.signals.map((s, i) => {
            const top = Object.entries(s.weights).sort((x, y) => y[1] - x[1])[0];
            return <tr key={i}><td>{s.label}</td><td className={b ? '' : 'dat'}>{b ? f.hypotheses.find((h) => h.id === top?.[0])?.title ?? '' : Object.entries(s.weights).map(([k, v]) => <div key={k}>{v > 0 ? '+' : ''}{v} {k}</div>)}</td><td><Proof nos={s.packets.slice(0, 3)} /></td></tr>;
          })}</tbody></table></div>
        {f.benign.length > 0 && <><h4 className="sm" style={{ marginTop: 24 }}>Innocent explanations checked</h4>
          {f.benign.map((x) => <p key={x.id} style={{ margin: '6px 0' }}><span className="sm">{x.matched ? 'Matched' : 'Ruled out'}: </span>{x.label}</p>)}</>}
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
