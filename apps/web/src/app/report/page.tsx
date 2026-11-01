'use client';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { diffReports, type Report } from '@packetmd/core';
import { runFile, useCase } from '@/lib/engine';
import { hasBackend, saveReport, shareReport } from '@/lib/backend';
import { Hv, Scan, useShell } from '@/shell/Shell';
import { Copy, Differential, exportJson, exportMd, FindingCard, FixPlan, Lane, Levels, Proof, useInk } from '@/report/parts';
import { StoryPlayer } from '@/report/Story';
import { Investigator } from '@/report/Investigator';
import { TimeChart } from '@/report/TimeChart';

const TABS: [string, string][] = [['verdict', 'Verdict'], ['findings', 'Findings'], ['differential', 'Differential'], ['story', 'Story'], ['fix', 'Fix plan'], ['verify', 'Verify fix'], ['timeline', 'Timeline'], ['hosts', 'Hosts'], ['activity', 'Activity'], ['investigator', 'Investigator']];
const LANES = ['ATTACK', 'FAULT', 'INCONCLUSIVE', 'BENIGN'] as const;
const LANE_TEXT: Record<string, string> = { ATTACK: 'Someone did this on purpose', FAULT: 'Something broke', INCONCLUSIVE: 'Not settled yet', BENIGN: 'Looked odd, turned out fine' };
const kb = (n: number) => (n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.ceil(n / 1024)} KB`);

function Verdict({ r }: { r: Report }) {
  const c = useCase();
  const [share, setShare] = useState('');
  const b = c.level === 'beginner';
  return (
    <div>
      <div className="veil" style={{ padding: 16, marginBottom: 20 }}><TimeChart r={r} compact /></div>
      {r.findings.length === 0 && <div className="veil" style={{ padding: 24 }}><h3 className="disp h3">All clear</h3><p style={{ marginBottom: 0, lineHeight: 1.5 }}>Every detector ran across {r.defense.packets} packets and found no fault, attack or anything unusual.</p></div>}
      <div className="lanes">
        {LANES.flatMap((l) => r.findings.filter((f) => f.lane === l).map((f) => (
          <button type="button" key={f.id} className={`lane-row ${l}`} onClick={() => c.setTab('findings')}>
            <span><Lane l={l} />{b && <span className="sm" style={{ display: 'block', marginTop: 4 }}>{LANE_TEXT[l]}</span>}</span>
            <span>
              <span style={{ fontWeight: 600 }}>{f.title}</span>{f.causedBy ? <span className="muted"> (side effect)</span> : null}
              <span className="muted" style={{ display: 'block', marginTop: 4, fontSize: 15, lineHeight: 1.45, overflowWrap: 'anywhere' }}>{c.level === 'analyst' ? f.technical : f.levels[c.level].what}</span>
              {c.level === 'analyst' && f.levels.analyst.fields && <span className="dat" style={{ display: 'block', marginTop: 4, overflowWrap: 'anywhere' }}>{f.levels.analyst.fields}</span>}
            </span>
            <span className="sm">{f.confidence} confidence</span>
          </button>
        )))}
      </div>
      <div className="export">
        <div><h3>Download</h3><div className="acts">
          <button type="button" className="btn" onClick={() => exportMd(r)}>Markdown</button>
          <button type="button" className="btn" onClick={() => exportJson(r)}>JSON</button>
          <button type="button" className="btn" onClick={() => window.print()}>Print to PDF</button>
        </div></div>
        <div><h3>Keep</h3><div className="acts">
          <button type="button" className="btn" aria-pressed={!!c.baseline} onClick={() => c.setBaseline(c.baseline ? null : r.baseline)}>{c.baseline ? 'Baseline saved' : 'Save as known-good baseline'}</button>
          {hasBackend && <button type="button" className="btn" onClick={() => saveReport(r).then(setShare)}>Save to my investigations</button>}
        </div></div>
        {hasBackend && <div><h3>Share</h3><div className="acts">
          <button type="button" className="btn" onClick={() => shareReport(r).then((t) => setShare(`${location.origin}/share?t=${t}`), (e) => setShare((e as Error).message))}>Create share link</button>
        </div></div>}
        {(share || hasBackend) && <p style={{ flexBasis: '100%', margin: 0, fontSize: 15, lineHeight: 1.5, overflowWrap: 'anywhere' }} role="status">{share ? <>{share} {share.startsWith('http') && <Copy text={share} />}</> : <span className="muted">Share links carry findings with addresses replaced, never packets.</span>}</p>}
      </div>
      {c.level !== 'beginner' && <div className="veil" style={{ padding: 16, marginTop: 24 }}>
        <h3 className="sm" style={{ marginTop: 0 }}>Protocol mix</h3>
        <table className="t"><tbody>{r.protocols.slice(0, 8).map((p) => <tr key={p.name}><td>{p.name}</td><td className="dat">{p.pkts}</td><td className="dat">{kb(p.bytes)}</td></tr>)}</tbody></table>
      </div>}
    </div>
  );
}

function Timeline({ r }: { r: Report }) {
  const c = useCase();
  const events = [...r.findings].sort((a, b) => a.t0 - b.t0), a = c.level === 'analyst';
  return (
    <div>
      <TimeChart r={r} />
      {events.length > 0 && <div className="veil" style={{ padding: 16, marginTop: 20, overflowX: 'auto' }}><table className="t"><thead><tr><th scope="col">When</th><th scope="col">What</th>{c.level !== 'beginner' && <th scope="col">Lasted</th>}<th scope="col">Verdict</th><th scope="col">First proof</th></tr></thead>
        <tbody>{events.map((f) => <tr key={f.id}><td className="dat">{a ? new Date(f.t0 * 1000).toISOString() : `+${(f.t0 - r.t0).toFixed(2)} s`}</td><td>{f.title}</td>{c.level !== 'beginner' && <td className="dat">{(f.t1 - f.t0).toFixed(2)} s</td>}<td><Lane l={f.lane} /></td><td><Proof nos={f.evidence.slice(0, 2).map((e) => e.no)} /></td></tr>)}</tbody></table></div>}
    </div>
  );
}

function Hosts({ r }: { r: Report }) {
  const c = useCase(), b = c.level === 'beginner', a = c.level === 'analyst';
  const dom = useMemo(() => { const m = new Map<string, string>(); r.conversations.forEach((x) => { if (x.domain) m.set(x.b, b ? x.domain : `${x.domain} via ${x.domainSource}, pkt ${x.domainPacket}`); }); return m; }, [r, b]);
  return (
    <div className="veil" style={{ padding: 16 }}>
      <h3 className="sm" style={{ marginTop: 0 }}>{b ? 'Devices seen' : 'Hosts'}</h3>
      <div style={{ overflowX: 'auto' }}><table className="t"><thead><tr><th scope="col">Address</th>{!b && <th scope="col">MAC</th>}<th scope="col">Name</th><th scope="col">Role</th>{!b && <th scope="col">Packets</th>}<th scope="col">Sent</th><th scope="col">Received</th>{a && <th scope="col">First seen</th>}</tr></thead>
        <tbody>{r.hosts.slice(0, 100).map((h) => <tr key={h.ip}><td className="dat">{h.ip}{dom.get(h.ip) ? <div className="muted">{dom.get(h.ip)}</div> : null}</td>{!b && <td className="dat">{h.macs.join(', ')}</td>}<td>{h.names.join(', ')}</td><td>{h.role}</td>{!b && <td className="dat">{h.pkts}</td>}<td className="dat">{kb(h.bytesOut)}</td><td className="dat">{kb(h.bytesIn)}</td>{a && <td className="dat">+{(h.firstSeen - r.t0).toFixed(3)} s</td>}</tr>)}</tbody></table></div>
      <h3 className="sm" style={{ marginTop: 32 }}>{b ? 'Who talked to whom' : 'Conversations'}</h3>
      <div style={{ overflowX: 'auto' }}><table className="t"><thead><tr><th scope="col">From</th><th scope="col">To</th><th scope="col">Domain</th><th scope="col">State</th>{!b && <th scope="col">Packets</th>}<th scope="col">Bytes</th>{a && <th scope="col">Proto</th>}</tr></thead>
        <tbody>{r.conversations.slice(0, 200).map((x) => <tr key={x.id}><td className="dat">{b ? x.a : `${x.a}:${x.aPort}`}</td><td className="dat">{b ? x.b : `${x.b}:${x.bPort}`}</td><td>{x.domain ?? ''}</td><td>{x.state}</td>{!b && <td className="dat">{x.pkts}</td>}<td className="dat">{kb(x.bytes)}</td>{a && <td className="dat">{x.proto}</td>}</tr>)}</tbody></table></div>
    </div>
  );
}

function Activity({ r }: { r: Report }) {
  const c = useCase(), b = c.level === 'beginner', a = c.level === 'analyst';
  if (!r.activity.length) return <p>No connections to attribute in this capture.</p>;
  return (
    <div className="veil" style={{ padding: 16 }}>
      <p className="muted" style={{ marginTop: 0, maxWidth: '70ch', lineHeight: 1.5 }}>A capture holds no process names or user accounts, so these are inferred classes with the basis shown. Checks here are offline only: nothing leaves your browser.</p>
      <div style={{ overflowX: 'auto' }}><table className="t"><thead><tr><th scope="col">{b ? 'Site or service' : 'Domain'}</th>{!b && <th scope="col">How we know</th>}<th scope="col">{b ? 'Looks like' : 'Class'}</th><th scope="col">Down / up</th>{!b && <th scope="col">Connections</th>}{!b && <th scope="col">Trouble</th>}<th scope="col">Rating</th></tr></thead>
        <tbody>{r.activity.map((x) => <tr key={x.domain}><td><button type="button" className="cr-btn st link" onClick={() => { c.setFilter(x.conv.length && x.source.startsWith('No name') ? `host == ${x.domain}` : `domain == ${x.domain}`); c.setTab('investigator'); }}>{x.domain}</button></td>{!b && <td className="dat">{x.source}, <Proof nos={[x.sourcePacket]} /></td>}<td>{x.klass}{a && <div className="sm">{x.basis.join(', ')}</div>}</td><td className="dat">{kb(x.bytesIn)} / {kb(x.bytesOut)}</td>{!b && <td className="dat">{x.requests}</td>}{!b && <td className="dat">{x.health}</td>}<td className={x.rating === 'Clean-looking' || x.rating === 'Unknown' ? '' : 'ac'}>{x.rating}{x.reasons.length ? <div className="sm">{x.reasons.join('. ')}</div> : null}</td></tr>)}</tbody></table></div>
    </div>
  );
}

function VerifyFix({ r }: { r: Report }) {
  const input = useRef<HTMLInputElement>(null);
  // Only captures with a true before and after pair offer the one-click comparison.
  const after = ({ 'mixed-incident.pcap': 'mixed-incident-after-fix.pcap' } as Record<string, string>)[r.defense.fileName];
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
        {after && <Hv onClick={async () => { const b = await fetch(`/samples/${after}`).then((x) => x.blob()); void check(new File([b], after)); }}>Use the lab after-fix sample</Hv>}
      </div>
      <input ref={input} type="file" accept=".pcap,.pcapng" hidden aria-label="Choose the second capture" onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ''; if (f) void check(f); }} />
      {msg && <p className="sm" role="status">{msg}</p>}
      {rows && <table className="t" style={{ marginTop: 16 }}><thead><tr><th scope="col">Finding</th><th scope="col">Result</th></tr></thead><tbody>{rows.map((x, i) => <tr key={i}><td>{x.title}</td><td className={x.status === 'RESOLVED' ? '' : 'ac'} style={{ fontWeight: 600 }}>{x.status}</td></tr>)}{!rows.length && <tr><td colSpan={2}>Neither capture has a finding.</td></tr>}</tbody></table>}
    </div>
  );
}

export default function ReportPage() {
  const c = useCase(), { go } = useShell(), r = c.report;
  const { jump } = useShell();
  const anchor = useRef<HTMLDivElement>(null);
  const { box, ink } = useInk(c.tab);
  const [shown, setShown] = useState(c.tab);
  const [leaving, setLeaving] = useState(false);
  const dir = useRef(1), mounted = useRef(false);
  // The old section fades out, the page moves while nothing is visible, then the new one eases in.
  useEffect(() => {
    if (c.tab === shown) return;
    const order = TABS.map(([id]) => id);
    dir.current = order.indexOf(c.tab) >= order.indexOf(shown) ? 1 : -1;
    setLeaving(true);
    const id = setTimeout(() => { setShown(c.tab); setLeaving(false); }, matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 130);
    return () => clearTimeout(id);
  }, [c.tab, shown]);
  // Runs after the new section is in the DOM, so the scroll height is the real one.
  useLayoutEffect(() => {
    if (!mounted.current) { mounted.current = true; return; }
    jump(shown === 'verdict' ? null : anchor.current);
  }, [shown, jump]);
  if (!r) return (
    <div className="center"><h1 className="disp h2 rise d1">No capture open yet.</h1>
      <p className="muted rise d2" style={{ fontSize: 17 }}>Open a file or a lab sample first. Reports live only in this tab.</p>
      <div className="rise d3"><Scan onClick={() => go('/')}>Open a capture</Scan></div></div>
  );
  const n = r.findings.filter((f) => f.lane !== 'BENIGN').length;
  const [head, ...rest] = r.headline.split('. ');
  return (
    <div className="pad" style={{ paddingTop: 36 }}>
      <p className="sm" style={{ margin: '0 0 6px' }}>{r.defense.fileName}, SHA-256 {r.defense.sha256.slice(0, 16)}...</p>
      <h1 className="disp report-title rise d1">{head}. {rest.length > 0 && <span className="ac">{rest.join('. ')}</span>}</h1>
      <div>
        <div ref={anchor} style={{ height: 12 }} />
        <div className="tabbar">
        <div ref={box} role="tablist" aria-label="Report sections" className="tabs ink-wrap">
          <i ref={ink as React.RefObject<HTMLElement>} className="ink" />
          {TABS.map(([id, label]) => <Hv key={id} role="tab" className="tab" aria-selected={c.tab === id} onClick={() => c.setTab(id)}>{label}{id === 'findings' && n ? ` ${n}` : ''}</Hv>)}
        </div>
          <Levels />
        </div>
        <div className={`panel ${leaving ? 'leaving' : 'entering'}`} key={shown} role="tabpanel" style={{ paddingTop: 16, '--dx': `${dir.current * 16}px` } as React.CSSProperties}>
          {shown === 'verdict' && <Verdict r={r} />}
          {shown === 'findings' && (r.findings.length ? r.findings.map((f) => <FindingCard key={f.id} f={f} r={r} />) : <p>No findings. Every detector ran and found nothing to report.</p>)}
          {shown === 'differential' && <Differential r={r} />}
          {shown === 'story' && <StoryPlayer r={r} />}
          {shown === 'fix' && <FixPlan r={r} />}
          {shown === 'verify' && <VerifyFix r={r} />}
          {shown === 'timeline' && <Timeline r={r} />}
          {shown === 'hosts' && <Hosts r={r} />}
          {shown === 'activity' && <Activity r={r} />}
          {shown === 'investigator' && <Investigator r={r} />}
        </div>
      </div>
    </div>
  );
}
