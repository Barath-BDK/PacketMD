'use client';
import { useEffect, useState } from 'react';
import { readShare } from '@/lib/backend';
import { Lane } from '@/report/parts';

interface Shared { summary: { headline: string; packets: number }; findings: { id: string; lane: string; title: string; plain: string; cause: string; fixTitles: string[] }[] }

export default function Share() {
  const [data, set] = useState<Shared | null>(null), [state, setState] = useState<'loading' | 'gone' | 'ok'>('loading');
  useEffect(() => {
    const t = new URLSearchParams(location.search).get('t');
    if (!t || !/^[0-9a-f]{32}$/.test(t)) { setState('gone'); return; }
    readShare(t).then((d) => { if (d) { set(d); setState('ok'); } else setState('gone'); }, () => setState('gone'));
  }, []);
  if (state === 'loading') return <div className="pad"><p className="sm">Opening shared report</p></div>;
  if (state === 'gone' || !data) return <div className="pad"><h1 className="disp h2">This link has expired or does not exist.</h1></div>;
  return (
    <div className="pad">
      <p className="sm">Shared report. Addresses are replaced with labels.</p>
      <h1 className="disp h2 rise d1" style={{ maxWidth: '22ch' }}>{data.summary.headline}</h1>
      {data.findings.map((f) => (
        <article key={f.id} className="veil" style={{ padding: 24, marginTop: 20 }}>
          <h2 className="disp h3">{f.title}</h2><Lane l={f.lane} />
          <p style={{ lineHeight: 1.5 }}>{f.plain}</p><p className="muted">{f.cause}</p>
          <ol style={{ paddingLeft: 18 }}>{f.fixTitles.map((x, i) => <li key={i}>{x}</li>)}</ol>
        </article>
      ))}
    </div>
  );
}
