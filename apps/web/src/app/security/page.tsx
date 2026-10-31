'use client';
import { useState } from 'react';
import { useCase, runFile, startWorker } from '@/lib/engine';
import { Scan } from '@/shell/Shell';

interface Hostile { file: string; uploadName: string; attack: string; expect: string }
interface Result extends Hostile { pass: boolean; got: string }

export default function Security() {
  const c = useCase();
  const [rows, setRows] = useState<Result[]>([]);
  const [running, setRunning] = useState(false);
  const [sandbox, setSandbox] = useState<boolean | null>(c.sandboxed);

  const run = async () => {
    setRunning(true); setRows([]);
    setSandbox((await startWorker().then(({ w, sandboxed }) => { w.terminate(); return sandboxed; })));
    const list = await fetch('/hostile/manifest.json').then((r) => r.json()) as Hostile[];
    for (const h of list) {
      const blob = await fetch(`/hostile/${h.file}`).then((r) => r.blob());
      // Each file gets a new Worker through the same path as a real upload.
      const o = await runFile(new File([blob], h.uploadName));
      const got = o.kind === 'rejected' ? 'Refused at the gate' : o.kind === 'crashed' ? 'Worker stopped, page safe' : o.report.findings.some((f) => f.hypothesis === 'parser-evasion') ? 'Reported as parser evasion' : `Parsed safely, ${o.report.defense.packets} packets, ${o.report.defense.skipped} skipped`;
      const pass = h.expect === 'rejected' ? o.kind === 'rejected' : h.expect === 'evasion' ? o.kind === 'done' && o.report.findings.some((f) => f.hypothesis === 'parser-evasion') : o.kind === 'done';
      setRows((r) => [...r, { ...h, pass, got }]);
    }
    setRunning(false);
  };
  const ok = rows.filter((r) => r.pass).length, d = c.report?.defense;
  return (
    <div className={rows.length || running || d ? 'pad' : 'center'}>
      <h1 className="disp h2 rise d1" style={{ maxWidth: '18ch' }}>A capture file is <span className="ac">an attack surface.</span></h1>
      <p className="muted rise d2" style={{ maxWidth: '62ch', lineHeight: 1.5, fontSize: 17 }}>This page attacks PacketMD with files built to break parsers. They go through the real gate and the real Worker, in your browser, right now.</p>
      <div className="rise d3" style={{ display: 'flex', flexWrap: 'wrap', gap: 24, alignItems: 'center', justifyContent: rows.length || running || d ? undefined : 'center', margin: '20px 0' }}>
        <Scan onClick={() => void run()} disabled={running}>{running ? `Running ${rows.length + 1}` : 'Run the red-team self-test'}</Scan>
        <span className="dat" role="status">{rows.length > 0 && `${ok} of ${rows.length} passed`}</span>
      </div>
      {sandbox !== null && <p role="status" style={{ marginTop: 0 }}><span className="sm">Sandbox check: </span>{sandbox ? 'The Worker tried to make a network request and the browser blocked it.' : <span className="ac">The Worker reached the network. The sandbox header is missing.</span>}</p>}
      {rows.length > 0 && (
        <div className="veil" style={{ padding: 16, overflowX: 'auto' }}>
          <table className="t"><thead><tr><th scope="col">Attack</th><th scope="col">What happened</th><th scope="col">Result</th></tr></thead>
            <tbody>{rows.map((r) => <tr key={r.file}><td>{r.attack}</td><td className="dat">{r.got}</td><td className={r.pass ? '' : 'ac'} style={{ fontWeight: 600 }}>{r.pass ? 'Pass' : 'Fail'}</td></tr>)}</tbody></table>
        </div>
      )}
      {d && (
        <section className="veil" style={{ padding: 24, marginTop: 32 }}>
          <h2 className="disp h3">File defense report</h2>
          <p className="dat" style={{ overflowWrap: 'anywhere' }}>{d.fileName}<br />SHA-256 {d.sha256}</p>
          <p className="dat">{d.packets} packets read, {d.skipped} skipped, {d.parseMs} ms</p>
          <table className="t"><tbody>{d.checks.map((x) => <tr key={x.label}><td>{x.label}</td><td className={x.ok ? 'dat' : 'ac'}>{x.detail}</td></tr>)}</tbody></table>
        </section>
      )}
    </div>
  );
}
