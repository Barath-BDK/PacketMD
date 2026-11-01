// The logo's heartbeat trace, drawn as a monitor reading: a flatline for a lost page, a spike for a crash.
export function Trace({ kind }: { kind: 'lost' | 'crash' }) {
  const d = kind === 'lost' ? 'M0 40h150l10-18 12 34 9-16h40M221 40h179' : 'M0 40h140l12-30 18 62 14-52 12 34 10-14h194';
  return <svg className="trace" viewBox="0 0 400 80" preserveAspectRatio="none" aria-hidden="true"><path pathLength={1} d={d} /></svg>;
}

export function StatusPage({ code, title, text, kind, children }: { code: string; title: string; text: string; kind: 'lost' | 'crash'; children: React.ReactNode }) {
  return (
    <div className="center status">
      <p className="status-code rise d1" aria-hidden="true">{code}</p>
      <Trace kind={kind} />
      <h1 className="disp h2 rise d2">{title}</h1>
      <p className="muted rise d2" style={{ fontSize: 17 }}>{text}</p>
      <div className="status-acts rise d3">{children}</div>
    </div>
  );
}
