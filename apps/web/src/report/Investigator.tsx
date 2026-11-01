'use client';
import { useEffect, useMemo, useRef, useState } from 'react';
import { FILTER_MAX_CHARS, FilterError, locator, parseFilter, type Evidence, type PacketRow, type Report, type TreeNode } from '@packetmd/core';
import { useCase } from '@/lib/engine';
import { Copy } from './parts';

const VIEW = 600;

function Tree({ nodes, sel, pick }: { nodes: TreeNode[]; sel: TreeNode | null; pick(n: TreeNode): void }) {
  return <ul>{nodes.map((n, i) => <li key={i}><button type="button" className={`cr-btn ${sel === n ? 'on' : ''}`} onClick={() => pick(n)}>{n.label}</button>{n.children?.length ? <Tree nodes={n.children} sel={sel} pick={pick} /> : null}</li>)}</ul>;
}

function Hex({ bytes, start, len }: { bytes: number[]; start?: number; len?: number }) {
  const lines = [];
  const on = (i: number) => start !== undefined && len !== undefined && i >= start && i < start + len;
  for (let o = 0; o < bytes.length && o < 4096; o += 16) {
    const cells = bytes.slice(o, o + 16);
    lines.push(
      <div key={o}>{o.toString(16).padStart(4, '0')}{'  '}
        {cells.map((b, i) => { const h = b.toString(16).padStart(2, '0'); return on(o + i) ? <span key={i}><b>{h}</b> </span> : <span key={i}>{h} </span>; })}
        {' '.repeat((16 - cells.length) * 3)}{' '}
        {cells.map((b, i) => { const ch = b >= 32 && b < 127 ? String.fromCharCode(b) : '.'; return on(o + i) ? <b key={i}>{ch}</b> : <span key={i}>{ch}</span>; })}
      </div>,
    );
  }
  return <div className="hex" style={{ overflow: 'auto' }}>{lines}</div>;
}

const conv = (a: PacketRow, b: PacketRow) => a.proto !== 'ARP' && ((a.src === b.src && a.dst === b.dst && a.sport === b.sport && a.dport === b.dport) || (a.src === b.dst && a.dst === b.src && a.sport === b.dport && a.dport === b.sport));
const wsFilter = (r: PacketRow) => r.sport ? `ip.addr == ${r.src} and ip.addr == ${r.dst} and tcp.port == ${r.dport}` : r.proto === 'ARP' ? `arp and eth.addr == ${r.srcMac}` : `ip.addr == ${r.src}`;
const bpf = (r: PacketRow) => r.sport ? `host ${r.src} and host ${r.dst} and port ${r.dport}` : r.proto === 'ARP' ? `arp and ether host ${r.srcMac}` : `host ${r.src}`;

export function Investigator({ r }: { r: Report }) {
  const c = useCase();
  const [q, setQ] = useState('');
  const [err, setErr] = useState('');
  const [top, setTop] = useState(0);
  const [cur, setCur] = useState<PacketRow | null>(null);
  const [det, setDet] = useState<{ tree: TreeNode[]; bytes: number[] } | null>(null);
  const [field, setField] = useState<TreeNode | null>(null);
  const [stream, setStream] = useState<{ parts: { fromA: boolean; text: string }[]; truncated: boolean } | null>(null);
  const [goTo, setGoTo] = useState('');
  const [wall, setWall] = useState(false);
  const list = useRef<HTMLDivElement>(null);
  const [phone, setPhone] = useState(false);
  useEffect(() => {
    const m = matchMedia('(max-width: 860px)'), on = () => setPhone(m.matches);
    on();
    m.addEventListener('change', on);
    return () => m.removeEventListener('change', on);
  }, []);
  // These match the row height in globals.css, because the list only draws the rows on screen.
  const ROW = phone ? 46 : 26, DETAIL = phone ? 560 : 400;

  const rows = useMemo(() => {
    try { const t = parseFilter(q, { findings: r.findings }); setErr(''); return r.rows.filter(t); }
    catch (e) { setErr(e instanceof FilterError ? e.message : 'That filter could not be read.'); return r.rows; }
  }, [q, r]);

  const open = rows.findIndex((x) => x.no === cur?.no);
  const yOf = (i: number) => i * ROW + (open >= 0 && i > open ? DETAIL : 0);

  const toggle = (row: PacketRow) => {
    setField(null); setStream(null);
    if (cur?.no === row.no) { setCur(null); setDet(null); return; }
    setCur(row); setDet(null);
    c.packet(row).then(setDet, () => setDet(null));
  };
  const jumpTo = (n: number) => {
    const row = r.rows[n - 1];
    if (!row) return;
    setQ('');
    setField(null); setStream(null); setCur(row); setDet(null);
    c.packet(row).then(setDet, () => setDet(null));
    setTimeout(() => { if (list.current) list.current.scrollTop = Math.max(0, (n - 2) * ROW); }, 0);
  };
  useEffect(() => { if (c.jump) { jumpTo(c.jump); c.setJump(null); } }, [c.jump]);
  useEffect(() => { if (c.filter !== null) { setQ(c.filter); c.setFilter(null); } }, [c.filter]);

  const follow = () => {
    if (!cur) return;
    const parts = r.rows.filter((x) => conv(x, cur) && x.sport !== undefined).slice(0, 400);
    const a = parts[0];
    if (!a) return;
    c.stream(parts.map((row) => ({ row, fromA: row.src === a.src, start: Math.min(row.capLen, 54) }))).then(setStream, () => setStream(null));
  };

  const firstIdx = (() => {
    if (open < 0) return Math.floor(top / ROW);
    if (top < (open + 1) * ROW) return Math.floor(top / ROW);
    if (top < (open + 1) * ROW + DETAIL) return open + 1;
    return Math.floor((top - DETAIL) / ROW);
  })();
  const slice = rows.slice(firstIdx, firstIdx + Math.ceil(VIEW / ROW) + 2);
  if (open >= 0 && open < firstIdx && top < (open + 1) * ROW + DETAIL) slice.unshift(rows[open]!);
  const ev = cur as unknown as Evidence | null;
  const loc = ev ? locator(ev, field?.start !== undefined && field.len ? { start: field.start, len: field.len, label: field.label } : undefined) : '';
  const proofOf = cur ? r.findings.filter((f) => f.evidence.some((e) => e.no === cur.no)) : [];
  const quick: [string, string][] = [...r.findings.filter((f) => f.lane !== 'BENIGN').map((f) => [f.title, `finding:${f.id}`] as [string, string]), ['Repeated packets', 'flag:retransmit'], ['Resets', 'flag:rst'], ['ARP', 'proto == ARP'], ['DNS', 'proto == DNS']];

  return (
    <div className="veil" style={{ padding: 16 }}>
      <datalist id="pk-fields">{['ip.addr == ', 'ip.src == ', 'ip.dst == ', 'tcp.port == ', 'udp.port == ', 'proto == ', 'mac == ', 'domain == ', 'host == ', 'dns.qry.name contains ', 'frame.number in ', 'flag:retransmit', 'flag:rst', 'flag:zerowin', ...r.findings.map((f) => `finding:${f.id}`)].map((x) => <option key={x} value={x} />)}</datalist>
      <div className="inv-top">
        <div>
          <label className="sm" htmlFor="pk-filter">Filter packets</label>
          <input id="pk-filter" list="pk-fields" className="cr-input mono" maxLength={FILTER_MAX_CHARS} aria-invalid={!!err} placeholder="ip.addr == 192.168.1.66" value={q} spellCheck={false} onChange={(e) => { setQ(e.target.value); setTop(0); if (list.current) list.current.scrollTop = 0; }} style={{ fontSize: 14 }} />
        </div>
        <form onSubmit={(e) => { e.preventDefault(); jumpTo(+goTo); }}>
          <label className="sm" htmlFor="pk-go">Go to packet</label>
          <input id="pk-go" className="cr-input mono" inputMode="numeric" maxLength={10} placeholder="137" value={goTo} onChange={(e) => setGoTo(e.target.value.replace(/\D/g, ''))} style={{ fontSize: 14 }} />
        </form>
      </div>
      <div className="flt" role="group" aria-label="Quick filters">{quick.map(([l, f]) => <button type="button" key={f} className="btn" aria-pressed={q === f} onClick={() => { setQ(q === f ? '' : f); setTop(0); if (list.current) list.current.scrollTop = 0; }}>{l}</button>)}</div>
      <p className={err ? 'ac sm' : 'sm'} role="status" style={{ margin: '6px 0' }}>{err || `${rows.length} of ${r.rows.length} packets. Pick a packet to open its details.`}</p>
      <div style={{ overflowX: 'auto' }}>
        <div className="pk-wide">
          <div className="pk pk-head" style={{ color: 'var(--small)' }}><span /><span>No.</span><button type="button" className="cr-btn st" aria-label="Switch time format" onClick={() => setWall(!wall)} style={{ pointerEvents: 'auto', textAlign: 'left' }}>{wall ? 'Clock' : 'Time'}</button><span>Source</span><span>Destination</span><span>Proto</span><span>Len</span><span>Info</span></div>
          <div ref={list} data-lenis-prevent onScroll={(e) => setTop(e.currentTarget.scrollTop)} style={{ height: 'min(' + VIEW + 'px, calc(100vh - 300px))', minHeight: 320, overflowY: 'auto', position: 'relative' }}>
            <div style={{ height: rows.length * ROW + (open >= 0 ? DETAIL : 0), position: 'relative' }}>
              {slice.map((p) => {
                const idx = rows.indexOf(p), isOpen = idx === open;
                return (
                  <button type="button" aria-expanded={isOpen} key={p.no} className={`pk ${isOpen ? 'on' : ''} ${p.flags?.length ? 'bad' : ''}`} onClick={() => toggle(p)} style={{ position: 'absolute', left: 0, right: 0, top: idx * ROW, transform: `translateY(${yOf(idx) - idx * ROW}px)` }}>
                    <span className="tw" aria-hidden="true">{'>'}</span><span>{p.no}</span><span>{wall ? new Date(p.ts * 1000).toISOString().slice(11, 23) : (p.ts - r.t0).toFixed(4)}</span><span>{p.src}</span><span>{p.dst}</span><span>{p.proto}</span><span>{p.len}</span><span>{p.info}</span>
                  </button>
                );
              })}
              {cur && open >= 0 && (
                <div className="pk-detail" data-lenis-prevent style={{ top: (open + 1) * ROW, height: DETAIL }}>
                  {!det && <p className="sm">Reading packet {cur.no}</p>}
                  {det && <>
                    <div className="tree" style={{ overflow: 'auto', minWidth: 0 }}>
                      <h4 className="sm" style={{ marginTop: 0 }}>Decoded packet {cur.no}</h4>
                      {proofOf.length > 0 && <p style={{ margin: '0 0 8px', fontSize: 14 }}><span className="sm">Proof for: </span>{proofOf.map((f) => f.title).join(', ')}</p>}
                      {cur.domain && <p style={{ margin: '0 0 8px', fontSize: 14 }}><span className="sm">Domain: </span>{cur.domain}</p>}
                      <Tree nodes={det.tree} sel={field} pick={setField} />
                    </div>
                    <div style={{ overflow: 'auto', minWidth: 0 }}>
                      <h4 className="sm" style={{ marginTop: 0 }}>Where it is in the file</h4>
                      <p className="dat" style={{ marginTop: 0, overflowWrap: 'anywhere' }}>{loc}</p>
                      {stream ? <div className="hex" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
                        <p className="sm" style={{ marginTop: 0 }}>Stream as inert text{stream.truncated ? ', cut at the size limit' : ''}</p>
                        {stream.parts.filter((p) => p.text).slice(0, 200).map((p, i) => <div key={i} className={p.fromA ? '' : 'ac'}>{p.text}</div>)}
                      </div> : <Hex bytes={det.bytes} start={field?.start} len={field?.len} />}
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16, marginTop: 12 }}>
                        <Copy text={loc} label="Copy locator" />
                        <Copy text={wsFilter(cur)} label="Copy Wireshark filter" />
                        <Copy text={bpf(cur)} label="Copy BPF" />
                        {cur.sport !== undefined && <button type="button" className="cr-btn st sm" onClick={() => (stream ? setStream(null) : follow())} style={{ borderBottom: '1px solid var(--line)', padding: '2px 0' }}>{stream ? 'Back to bytes' : 'Follow stream'}</button>}
                      </div>
                    </div>
                  </>}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
