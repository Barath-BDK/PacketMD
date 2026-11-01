'use client';
import { useEffect, useState } from 'react';
import { deleteReport, savedReports, sb, type SavedReport } from '@/lib/backend';
import { Lane } from '@/report/parts';
import { Scan, useShell } from '@/shell/Shell';

const count = (r: SavedReport, lane: string) => r.findings.filter((f) => f.lane === lane).length;
const when = (d: string) => new Date(d).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

function Details({ r, gone }: { r: SavedReport; gone(): void }) {
  const [sure, setSure] = useState(false), [msg, setMsg] = useState('');
  return (
    <div className="flip" style={{ padding: '4px 16px 20px' }}>
      <p className="dat" style={{ overflowWrap: 'anywhere' }}>SHA-256 {r.file_sha256}</p>
      {r.findings.length === 0 && <p style={{ lineHeight: 1.5 }}>No faults or attacks were found in this capture.</p>}
      {r.findings.map((f) => (
        <article key={f.id} className="veil" style={{ padding: 20, marginBottom: 12, borderLeft: `2px solid ${f.lane === 'ATTACK' ? 'var(--ac)' : 'var(--line)'}` }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'baseline', justifyContent: 'space-between' }}>
            <h3 className="disp h3">{f.title}</h3>
            <span><Lane l={f.lane} /> <span className="sm" style={{ marginLeft: 8 }}>{f.confidence} confidence</span></span>
          </div>
          <p style={{ lineHeight: 1.5 }}>{f.plain}</p>
          <p style={{ lineHeight: 1.5 }}><span className="sm">Why it happened: </span>{f.cause}</p>
          <p style={{ lineHeight: 1.5 }}><span className="sm">Why not something else: </span>{f.whyNotTheOther}</p>
          {f.fixTitles.length > 0 && <><p className="sm" style={{ marginBottom: 4 }}>What to fix</p><ol style={{ margin: 0, paddingLeft: 20, lineHeight: 1.6 }}>{f.fixTitles.map((x, i) => <li key={i}>{x}</li>)}</ol></>}
          <p style={{ lineHeight: 1.5, marginBottom: 0 }}><span className="sm">Check it worked: </span>{f.verifyBy}</p>
          {f.proofPackets.length > 0 && <p className="dat" style={{ marginBottom: 0 }}>Proof packets: {f.proofPackets.join(', ')}</p>}
        </article>
      ))}
      <p style={{ marginBottom: 0 }}>
        <button type="button" className="btn" onClick={() => { if (!sure) { setSure(true); return; } void deleteReport(r.id).then((ok) => (ok ? gone() : setMsg('Could not delete this.'))); }}>{sure ? 'Confirm delete' : 'Delete this investigation'}</button>
        {sure && <button type="button" className="btn" style={{ marginLeft: 8 }} onClick={() => setSure(false)}>Keep it</button>}
        <span className="sm" role="status"> {msg}</span>
      </p>
    </div>
  );
}

export default function Investigations() {
  const { go } = useShell();
  const [state, setState] = useState<'loading' | 'guest' | 'ok' | 'error'>('loading');
  const [list, setList] = useState<SavedReport[]>([]);
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const { data } = (await sb?.auth.getSession()) ?? {};
      if (!data?.session) { setState('guest'); return; }
      const rows = await savedReports();
      if (!rows) { setState('error'); return; }
      setList(rows); setState('ok');
    })();
  }, []);

  if (state === 'loading') return <div className="center"><p className="sm">Opening your investigations</p></div>;
  if (state === 'error') return <div className="center"><h1 className="disp h2">Could not load your investigations.</h1><p className="muted">Reload the page to try again.</p></div>;
  if (state === 'guest') return (
    <div className="center">
      <h1 className="disp h2 rise d1">Log in to see your investigations.</h1>
      <p className="muted rise d2" style={{ fontSize: 17 }}>Reports you save to your account appear here.</p>
      <div className="rise d3"><Scan onClick={() => go('/signin')}>Log in</Scan></div>
    </div>
  );
  if (!list.length) return (
    <div className="center">
      <h1 className="disp h2 rise d1">No saved investigations yet.</h1>
      <p className="muted rise d2" style={{ fontSize: 17 }}>Open a capture, then choose Save to account on its Verdict tab.</p>
      <div className="rise d3"><Scan onClick={() => go('/')}>Open a capture</Scan></div>
    </div>
  );
  return (
    <div className="pad">
      <h1 className="disp h2 rise d1">Your investigations</h1>
      <p className="muted rise d2" style={{ maxWidth: '62ch', lineHeight: 1.5 }}>{list.length} saved. These hold findings only, never packets, and addresses are replaced with labels such as host-3.</p>
      <div className="veil" style={{ marginTop: 16 }}>
        {list.map((r) => {
          const on = open === r.id;
          return (
            <div key={r.id} style={{ borderBottom: '1px solid var(--line)' }}>
              <button type="button" className={`inv-row ${on ? 'on' : ''}`} aria-expanded={on} onClick={() => setOpen(on ? null : r.id)}>
                <span style={{ minWidth: 0 }}>
                  <span style={{ display: 'block', fontWeight: 600, overflowWrap: 'anywhere' }}>{r.file_name ?? 'Unnamed capture'}</span>
                  <span className="muted" style={{ display: 'block', fontSize: 15, lineHeight: 1.4, marginTop: 2 }}>{r.summary.headline}</span>
                </span>
                <span className="sm">{count(r, 'ATTACK')} attack, {count(r, 'FAULT')} fault<br />{r.summary.packets} packets</span>
                <span className="sm">{when(r.created_at)}</span>
              </button>
              {on && <Details r={r} gone={() => { setList(list.filter((x) => x.id !== r.id)); setOpen(null); }} />}
            </div>
          );
        })}
      </div>
    </div>
  );
}
