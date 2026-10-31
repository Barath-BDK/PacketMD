'use client';
import { useMemo, useRef, useState } from 'react';
import { diffReports, type Report } from '@packetmd/core';
import { runFile, useCase } from '@/lib/engine';
import { hasBackend, saveReport, shareReport } from '@/lib/backend';
import { Hv, Scan, useShell } from '@/shell/Shell';
import { Bars, Copy, Differential, exportJson, exportMd, FindingCard, FixPlan, Lane, Levels, Proof } from '@/report/parts';
import { StoryPlayer } from '@/report/Story';
import { Investigator } from '@/report/Investigator';

const TABS: [string, string][] = [['verdict', 'Verdict'], ['findings', 'Findings'], ['differential', 'Differential'], ['story', 'Story'], ['fix', 'Fix plan'], ['verify', 'Verify fix'], ['timeline', 'Timeline'], ['hosts', 'Hosts'], ['activity', 'Activity'], ['investigator', 'Investigator']];
const LANES = ['ATTACK', 'FAULT', 'INCONCLUSIVE', 'BENIGN'] as const;
const LANE_TEXT: Record<string, string> = { ATTACK: 'Someone did this on purpose', FAULT: 'Something broke', INCONCLUSIVE: 'Not settled yet', BENIGN: 'Looked odd, turned out fine' };
const kb = (n: number) => (n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.ceil(n / 1024)} KB`);

function Verdict({ r }: { r: Report }) {
  const c = useCase();
  const [share, setShare] = useState('');
  return (
    <div>
      <Bars r={r} />
      <p className="sm">{r.defense.packets} packets over {(r.t1 - r.t0).toFixed(1)} s. Red marks problem periods.</p>
      {LANES.map((l) => {
        const fs = r.findings.filter((f) => f.lane === l);
        return (
          <section key={l} className="veil" style={{ padding: '20px 24px', marginBottom: 12 }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16, alignItems: 'baseline' }}><Lane l={l} /><span className="muted">{LANE_TEXT[l]}</span><span className="dat" style={{ marginLeft: 'auto' }}>{fs.length}</span></div>
            {fs.map((f) => (
              <button type="button" key={f.id} className="rowbtn" style={{ gridTemplateColumns: 'minmax(0,1fr) auto' }} onClick={() => c.setTab('findings')}>
                <span>{f.title}{f.causedBy ? <span className="muted"> (side effect)</span> : null}</span><span className="sm">{f.confidence} confidence</span>
              </button>
            ))}
          </section>
        );
      })}
      <div className="grid-2" style={{ marginTop: 24 }}>
        <div>
          <h3 className="sm">Protocol mix</h3>
          <table className="t"><tbody>{r.protocols.slice(0, 8).map((p) => <tr key={p.name}><td>{p.name}</td><td className="dat">{p.pkts}</td><td className="dat">{kb(p.bytes)}</td></tr>)}</tbody></table>
        </div>
        <div>
          <h3 className="sm">Take this with you</h3>
          <div className="mono" style={{ display: 'flex', flexWrap: 'wrap', gap: 20, fontSize: 13 }}>
            <Hv onClick={() => exportMd(r)}>Markdown</Hv><Hv onClick={() => exportJson(r)}>JSON</Hv><Hv onClick={() => window.print()}>Print to PDF</Hv>
            <Hv onClick={() => c.setBaseline(r.baseline)}>{c.baseline ? 'Baseline saved' : 'Save as known-good baseline'}</Hv>
            {hasBackend && <Hv onClick={() => saveReport(r).then(setShare)}>Save to account</Hv>}
            {hasBackend && <Hv onClick={() => shareReport(r).then((t) => setShare(`${location.origin}/share?t=${t}`), (e) => setShare((e as Error).message))}>Create share link</Hv>}
          </div>
          {share && <p className="dat" role="status" style={{ overflowWrap: 'anywhere' }}>{share} {share.startsWith('http') && <Copy text={share} />}</p>}
          <p className="muted" style={{ fontSize: 14, lineHeight: 1.5 }}>Share links carry findings with addresses replaced, never packets.</p>
        </div>
      </div>
    </div>
  );
}

function Timeline({ r }: { r: Report }) {
  const events = [...r.findings].sort((a, b) => a.t0 - b.t0);
  return (
    <div>
      <Bars r={r} />
      <table className="t" style={{ marginTop: 24 }}><thead><tr><th scope="col">When</th><th scope="col">What</th><th scope="col">Verdict</th><th scope="col">First proof</th></tr></thead>
        <tbody>{events.map((f) => <tr key={f.id}><td className="dat">+{(f.t0 - r.t0).toFixed(2)} s</td><td>{f.title}</td><td><Lane l={f.lane} /></td><td><Proof nos={f.evidence.slice(0, 2).map((e) => e.no)} /></td></tr>)}</tbody></table>
    </div>
  );
}

function Hosts({ r }: { r: Report }) {
  const dom = useMemo(() => { const m = new Map<string, string>(); r.conversations.forEach((c) => { if (c.domain) m.set(c.b, `${c.domain} via ${c.domainSource}, pkt ${c.domainPacket}`); }); return m; }, [r]);
  return (
    <div className="veil" style={{ padding: 16 }}>
      <h3 className="sm" style={{ marginTop: 0 }}>Hosts</h3>
      <div style={{ overflowX: 'auto' }}><table className="t"><thead><tr><th scope="col">Address</th><th scope="col">MAC</th><th scope="col">Name</th><th scope="col">Role</th><th scope="col">Packets</th><th scope="col">Sent</th><th scope="col">Received</th></tr></thead>
        <tbody>{r.hosts.slice(0, 100).map((h) => <tr key={h.ip}><td className="dat">{h.ip}{dom.get(h.ip) ? <div className="muted">{dom.get(h.ip)}</div> : null}</td><td className="dat">{h.macs.join(', ')}</td><td>{h.names.join(', ')}</td><td>{h.role}</td><td className="dat">{h.pkts}</td><td className="dat">{kb(h.bytesOut)}</td><td className="dat">{kb(h.bytesIn)}</td></tr>)}</tbody></table></div>
      <h3 className="sm" style={{ marginTop: 32 }}>Conversations</h3>
      <div style={{ overflowX: 'auto' }}><table className="t"><thead><tr><th scope="col">From</th><th scope="col">To</th><th scope="col">Domain</th><th scope="col">State</th><th scope="col">Packets</th><th scope="col">Bytes</th></tr></thead>
        <tbody>{r.conversations.slice(0, 200).map((c) => <tr key={c.id}><td className="dat">{c.a}:{c.aPort}</td><td className="dat">{c.b}:{c.bPort}</td><td>{c.domain ?? ''}</td><td>{c.state}</td><td className="dat">{c.pkts}</td><td className="dat">{kb(c.bytes)}</td></tr>)}</tbody></table></div>
    </div>
  );
}

function Activity({ r }: { r: Report }) {
  return (
    <div className="veil" style={{ padding: 16 }}>
      <p className="muted" style={{ marginTop: 0, maxWidth: '70ch', lineHeight: 1.5 }}>A capture holds no process names or user accounts, so these are inferred classes with the basis shown. Checks here are offline only: nothing leaves your browser.</p>
      <div style={{ overflowX: 'auto' }}><table className="t"><thead><tr><th scope="col">Domain</th><th scope="col">How we know</th><th scope="col">Class</th><th scope="col">Down / up</th><th scope="col">Connections</th><th scope="col">Trouble</th><th scope="col">Rating</th></tr></thead>
        <tbody>{r.activity.map((a) => <tr key={a.domain}><td>{a.domain}</td><td className="dat">{a.source}, <Proof nos={[a.sourcePacket]} /></td><td>{a.klass}<div className="sm">{a.basis.join(', ')}</div></td><td className="dat">{kb(a.bytesIn)} / {kb(a.bytesOut)}</td><td className="dat">{a.requests}</td><td className="dat">{a.health}</td><td className={a.rating === 'Clean-looking' || a.rating === 'Unknown' ? '' : 'ac'}>{a.rating}{a.reasons.length ? <div className="sm">{a.reasons.join('. ')}</div> : null}</td></tr>)}</tbody></table></div>
    </div>
  );
}

function VerifyFix({ r }: { r: Report }) {
  const input = useRef<HTMLInputElement>(null);
  const [rows, setRows] = useState<ReturnType<typeof diffReports> | null>(null);
  const [msg, setMsg] = useState('');
  const check = async (f: File) => {
    setMsg('Scanning the second capture'); setRows(null);
    const o = await runFile(f);
    if (o.kind === 'done') { setRows(diffReports(r, o.report)); setMsg(''); } else setMsg(o.kind === 'rejected' ? o.gate.reason ?? 'Refused.' : o.message);
  };
  return (
    <div className="veil" style={{ padding: 24 }}>
      <p style={{ marginTop: 0, maxWidth: '60ch', lineHeight: 1.5 }}>Applied the fixes? Capture the same spot again and open it here. Each finding is marked as resolved, still present or new.</p>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 24, alignItems: 'center' }}>
        <Scan tight onClick={() => input.current?.click()}>Open the after capture</Scan>
        <Hv onClick={async () => { const b = await fetch('/samples/mixed-incident-after-fix.pcap').then((x) => x.blob()); void check(new File([b], 'mixed-incident-after-fix.pcap')); }}>Use the lab after-fix sample</Hv>
      </div>
      <input ref={input} type="file" accept=".pcap,.pcapng" hidden aria-label="Choose the second capture" onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ''; if (f) void check(f); }} />
      {msg && <p className="sm" role="status">{msg}</p>}
      {rows && <table className="t" style={{ marginTop: 16 }}><thead><tr><th scope="col">Finding</th><th scope="col">Result</th></tr></thead><tbody>{rows.map((x, i) => <tr key={i}><td>{x.title}</td><td className={x.status === 'RESOLVED' ? '' : 'ac'} style={{ fontWeight: 600 }}>{x.status}</td></tr>)}{!rows.length && <tr><td colSpan={2}>Neither capture has a finding.</td></tr>}</tbody></table>}
    </div>
  );
}

export default function ReportPage() {
  const c = useCase(), { go } = useShell(), r = c.report;
  if (!r) return (
    <div className="pad"><h1 className="disp h2 rise d1" style={{ maxWidth: '16ch' }}>No capture open yet.</h1>
      <p className="muted rise d2">Open a file or a lab sample first. Reports live only in this tab.</p>
      <div className="rise d3"><Scan onClick={() => go('/')}>Open a capture</Scan></div></div>
  );
  const n = (l: string) => r.findings.filter((f) => f.lane === l).length;
  const [head, ...rest] = r.headline.split('. ');
  return (
    <div className="pad">
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'flex-end', justifyContent: 'space-between', gap: 20, marginBottom: 12 }}>
        <div>
          <p className="sm" style={{ margin: '0 0 8px' }}>{r.defense.fileName}, SHA-256 {r.defense.sha256.slice(0, 16)}...</p>
          <h1 className="disp h2 rise d1" style={{ maxWidth: '22ch' }}>{head}. {rest.length > 0 && <span className="ac">{rest.join('. ')}</span>}</h1>
        </div>
        <Levels />
      </div>
      <div role="tablist" aria-label="Report sections" className="tabs">
        {TABS.map(([id, label]) => <Hv key={id} role="tab" className="tab" aria-selected={c.tab === id} onClick={() => c.setTab(id)}>{label}{id === 'findings' ? ` ${n('ATTACK') + n('FAULT') + n('INCONCLUSIVE')}` : ''}</Hv>)}
      </div>
      <div className="flip" key={c.tab} role="tabpanel" style={{ paddingTop: 20 }}>
        {c.tab === 'verdict' && <Verdict r={r} />}
        {c.tab === 'findings' && (r.findings.length ? r.findings.map((f) => <FindingCard key={f.id} f={f} r={r} />) : <p>No findings. Every detector ran and found nothing to report.</p>)}
        {c.tab === 'differential' && <Differential r={r} />}
        {c.tab === 'story' && <StoryPlayer r={r} />}
        {c.tab === 'fix' && <FixPlan r={r} />}
        {c.tab === 'verify' && <VerifyFix r={r} />}
        {c.tab === 'timeline' && <Timeline r={r} />}
        {c.tab === 'hosts' && <Hosts r={r} />}
        {c.tab === 'activity' && <Activity r={r} />}
        {c.tab === 'investigator' && <Investigator r={r} />}
      </div>
    </div>
  );
}
