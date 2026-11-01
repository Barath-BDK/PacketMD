'use client';
import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { safeName, techniqueOf, type Finding, type FixStep, type Report } from '@packetmd/core';

const LANE: Record<string, string> = { ATTACK: 'Attack', FAULT: 'Fault', INCONCLUSIVE: 'Unresolved', BENIGN: 'Harmless' };
const MEANS: Record<string, string> = { ATTACK: 'Someone did this on purpose.', FAULT: 'Something broke.', INCONCLUSIVE: 'The evidence fits more than one explanation.', BENIGN: 'Looked odd, turned out fine.' };
const size = (n: number) => (n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.ceil(n / 1024)} KB`);
const utc = (t: number) => `${new Date(t * 1000).toISOString().slice(0, 19).replace('T', ' ')} UTC`;
const secs = (t: number) => `+${t.toFixed(2)} s`;
const PLATFORMS: [keyof FixStep, string][] = [['windows', 'Windows'], ['linux', 'Linux'], ['router', 'Router']];

function Chart({ r }: { r: Report }) {
  const bars = r.timeline, peak = Math.max(1, ...bars.map((b) => b.pkts)), w = 1000 / Math.max(1, bars.length);
  return (
    <svg className="pr-chart" viewBox="0 0 1000 110" preserveAspectRatio="none" role="img" aria-label="Packets over time, with proof packets in red">
      {bars.map((b, i) => {
        const h = (b.pkts / peak) * 104, red = (b.bad / Math.max(1, b.pkts)) * h;
        return <g key={i}><rect x={i * w} y={110 - h} width={Math.max(1, w - 1.5)} height={h} fill="#C9CCD1" />{b.bad > 0 && <rect x={i * w} y={110 - Math.max(red, 4)} width={Math.max(1, w - 1.5)} height={Math.max(red, 4)} fill="#C8102E" />}</g>;
      })}
    </svg>
  );
}

function Section({ f, r, n }: { f: Finding; r: Report; n: number }) {
  const tech = techniqueOf(f.hypothesis), causes = (f.causedBy ?? []).map((id) => r.findings.find((x) => x.id === id)?.title).filter(Boolean);
  return (
    <section className="pr-finding">
      <header className="pr-fhead">
        <p className={`pr-tag pr-${f.lane}`}>{LANE[f.lane]}</p>
        <h2>{n}. {f.title}</h2>
        <p className="pr-meta">
          {f.confidence} confidence, seen {secs(f.t0 - r.t0)} for {(f.t1 - f.t0).toFixed(2)} s{f.hosts.length > 0 && `, involves ${f.hosts.slice(0, 4).join(', ')}${f.hosts.length > 4 ? ` and ${f.hosts.length - 4} more` : ''}`}
        </p>
        {tech && <p className="pr-meta">MITRE ATT&amp;CK {f.lane === 'INCONCLUSIVE' ? 'if confirmed' : ''} {tech.id}, {tech.name}</p>}
      </header>
      <p className="pr-lead">{f.plain}</p>
      {causes.length > 0 && <p className="pr-note">Probably a side effect of: {causes.join(', ')}.</p>}
      <h3>Why it happened</h3>
      <p>{f.cause}</p>
      {f.whyNotTheOther && <><h3>Why it is not something else</h3><p>{f.whyNotTheOther}</p></>}
      {f.signals.length > 0 && <><h3>What the evidence shows</h3><ul>{f.signals.slice(0, 6).map((s, i) => <li key={i}>{s.label}</li>)}</ul></>}
      {f.nextCapture && <><h3>Capture this next</h3><p>{f.nextCapture}</p></>}
      <h3>Proof packets</h3>
      <table className="pr-table pr-proof">
        <thead><tr><th>No.</th><th>Time</th><th>Proto</th><th>Detail</th></tr></thead>
        <tbody>{f.evidence.slice(0, 6).map((e) => <tr key={e.no}><td>{e.no}</td><td>{secs(e.ts - r.t0)}</td><td>{e.proto}</td><td>{e.info}</td></tr>)}</tbody>
      </table>
      {f.evidence.length > 6 && <p className="pr-note">And {f.evidence.length - 6} more proof packets.</p>}
      {f.fixSteps.length > 0 && <div className="pr-fix">
        <h3>{f.fixIf ? `If this turns out to be ${f.fixIf}` : 'How to fix it'}</h3>
        {f.fixIf && <p className="pr-note">Inconclusive. It may be harmless, so check first and only then do these.</p>}
        <ol>{f.fixSteps.map((s, i) => (
          <li key={i}>
            <p className="pr-step">{s.title}</p>
            <p className="pr-why">{s.why}</p>
            {PLATFORMS.map(([k, label]) => (s[k] ? <div className="pr-cmd" key={k}><span>{label}</span><code>{s[k]}</code></div> : null))}
          </li>
        ))}</ol>
        <p className="pr-check"><b>Check it worked:</b> {f.verifyBy}</p>
      </div>}
    </section>
  );
}

/** A document of its own, not a picture of the screen. It only ever appears when printing. */
export function PrintReport({ r, archived }: { r: Report; archived: boolean }) {
  const [on, set] = useState(false);
  useEffect(() => {
    set(true);
    // The browser offers the page title as the PDF's file name.
    const title = document.title, before = () => { document.title = `PacketMD report ${safeName(r.defense.fileName).replace(/\.[^.]+$/, '')}`; }, after = () => { document.title = title; };
    addEventListener('beforeprint', before); addEventListener('afterprint', after);
    return () => { removeEventListener('beforeprint', before); removeEventListener('afterprint', after); after(); };
  }, [r]);
  if (!on) return null;
  const [first, ...rest] = r.headline.split('. ');
  const steps = r.findings.filter((f) => !f.fixIf).flatMap((f) => f.fixSteps.slice(0, 1).map((s) => ({ s, f }))).slice(0, 5);
  return createPortal(
    <article className="print-doc">
      <header className="pr-top">
        <div className="pr-brand">
          <svg viewBox="0 0 32 32" aria-hidden="true"><path d="M3 10V3h7M22 3h7v7M29 22v7h-7M10 29H3v-7" fill="none" stroke="#C8102E" strokeWidth="2.6" /><path d="M6 17h5.5l2.5-7.5 4 14 2.6-6.5H26" fill="none" stroke="#111" strokeWidth="2.6" strokeLinejoin="round" strokeLinecap="round" /></svg>
          <span>packet<b>MD</b><i /></span>
        </div>
        <div className="pr-kind"><p>Network incident report</p><p>{new Date().toLocaleDateString(undefined, { dateStyle: 'long' })}</p></div>
      </header>

      <h1>{first!.replace(/\.$/, '')}.{rest.length > 0 && <span> {rest.join('. ')}</span>}</h1>

      <dl className="pr-facts">
        <div><dt>File</dt><dd>{r.defense.fileName}</dd></div>
        <div><dt>Size</dt><dd>{size(r.defense.size)}, {r.defense.packets} packets</dd></div>
        <div><dt>Captured</dt><dd>{utc(r.t0)}</dd></div>
        <div><dt>Duration</dt><dd>{(r.t1 - r.t0).toFixed(1)} s</dd></div>
        <div className="wide"><dt>SHA-256</dt><dd>{r.defense.sha256}</dd></div>
      </dl>

      {archived && <p className="pr-note">From a saved investigation. Addresses are shown as labels such as host-3, so swap in the real values before running any command.</p>}
      {r.defense.truncated && <p className="pr-note">This capture was too large to read in full, so anything after the limit was not analysed.</p>}

      {r.timeline.length > 0 && <figure><Chart r={r} /><figcaption>Traffic across the capture. Red marks the packets that prove a finding.</figcaption></figure>}

      <h2 className="pr-sec">Findings at a glance</h2>
      {r.findings.length === 0
        ? <p>Every detector ran across {r.defense.packets} packets and found no fault, attack or anything unusual.</p>
        : <table className="pr-table">
          <thead><tr><th /><th>Verdict</th><th>Finding</th><th>Confidence</th><th>ATT&amp;CK</th></tr></thead>
          <tbody>{r.findings.map((f, i) => <tr key={f.id}><td>{i + 1}</td><td><span className={`pr-tag pr-${f.lane}`}>{LANE[f.lane]}</span></td><td>{f.title}{f.causedBy ? ' (side effect)' : ''}</td><td>{f.confidence}</td><td>{techniqueOf(f.hypothesis)?.id ?? 'None'}</td></tr>)}</tbody>
        </table>}

      {steps.length > 0 && <>
        <h2 className="pr-sec">Do these first</h2>
        <ol className="pr-first">{steps.map(({ s, f }) => <li key={f.id}><b>{s.title}.</b> {s.why}</li>)}</ol>
      </>}

      {r.findings.map((f, i) => <Section key={f.id} f={f} r={r} n={i + 1} />)}

      <section className="pr-end">
        <h2 className="pr-sec">How to read this report</h2>
        {r.findings.length > 0 && <>
          <dl className="pr-key">{Object.keys(LANE).filter((l) => r.findings.some((f) => f.lane === l)).map((l) => <div key={l}><dt>{LANE[l]}</dt><dd>{MEANS[l]}</dd></div>)}</dl>
          <p>Each finding is tied to the exact packets that prove it. ATT&amp;CK labels follow MITRE ATT&amp;CK v20 and appear only where MITRE describes the behaviour. They are a reference, not a claim about who did this.</p>
        </>}
        <p>PacketMD reads what a capture shows and nothing more. It cannot see inside encrypted traffic, and a clean result means nothing it knows how to detect was found, never that a network is safe. Detection was measured on lab captures only. Check every command before running it.</p>
      </section>
    </article>,
    document.body,
  );
}
