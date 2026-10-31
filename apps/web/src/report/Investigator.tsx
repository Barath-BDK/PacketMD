'use client';
import { useEffect, useMemo, useRef, useState } from 'react';
import { FilterError, locator, parseFilter, type Evidence, type PacketRow, type Report, type TreeNode } from '@packetmd/core';
import { useCase } from '@/lib/engine';
import { Copy } from './parts';

const ROW = 26, VIEW = 360;

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
  return <div className="hex" data-lenis-prevent style={{ overflow: 'auto', maxHeight: 300 }}>{lines}</div>;
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
  const list = useRef<HTMLDivElement>(null);

  const rows = useMemo(() => {
    try { const t = parseFilter(q, { findings: r.findings }); setErr(''); return r.rows.filter(t); }
    catch (e) { setErr(e instanceof FilterError ? e.message : 'That filter could not be read.'); return r.rows; }
  }, [q, r]);

  const select = (row: PacketRow) => {
    setCur(row); setField(null); setStream(null);
    c.packet(row).then(setDet, () => setDet(null));
  };
  const jumpTo = (n: number) => {
    const row = r.rows[n - 1];
    if (!row) return;
    setQ('');
    select(row);
    setTimeout(() => { if (list.current) list.current.scrollTop = Math.max(0, (n - 4) * ROW); }, 0);
  };
  useEffect(() => { if (c.jump) { jumpTo(c.jump); c.setJump(null); } }, [c.jump]);

  const follow = () => {
    if (!cur) return;
    const parts = r.rows.filter((x) => conv(x, cur) && (x.sport !== undefined)).slice(0, 400);
    const a = parts[0];
    if (!a) return;
    c.stream(parts.map((row) => ({ row, fromA: row.src === a.src, start: Math.min(row.capLen, 54) }))).then(setStream, () => setStream(null));
  };

  const first = Math.floor(top / ROW), vis = rows.slice(first, first + Math.ceil(VIEW / ROW) + 2);
  const ev = cur as unknown as Evidence | null;
  const dom = cur?.domain && <p className="sm">{cur.dst} is {cur.domain}</p>;
  return (
    <div>
      <div className="veil" style={{ padding: 16 }}>
        <label className="sm" htmlFor="pk-filter">Filter, for example ip.addr == 192.168.1.66 and flag:retransmit or finding:F1</label>
        <input id="pk-filter" className="cr-input mono" value={q} spellCheck={false} onChange={(e) => { setQ(e.target.value); setTop(0); if (list.current) list.current.scrollTop = 0; }} style={{ fontSize: 14 }} />
        <p className={err ? 'ac sm' : 'sm'} role="status" style={{ margin: '6px 0' }}>{err || `${rows.length} of ${r.rows.length} packets`}</p>
        <div style={{ overflowX: 'auto' }}>
          <div style={{ minWidth: 760 }}>
            <div className="pk" aria-hidden="true" style={{ color: 'var(--small)' }}><span>No.</span><span>Time</span><span>Source</span><span>Destination</span><span>Proto</span><span className="hide-sm">Len</span><span>Info</span></div>
            <div ref={list} data-lenis-prevent role="listbox" aria-label="Packets" onScroll={(e) => setTop(e.currentTarget.scrollTop)} style={{ height: VIEW, overflowY: 'auto', position: 'relative' }}>
              <div style={{ height: rows.length * ROW, position: 'relative' }}>
                <div style={{ position: 'absolute', top: first * ROW, left: 0, right: 0 }}>
                  {vis.map((p) => (
                    <button type="button" role="option" aria-selected={cur?.no === p.no} key={p.no} className={`pk ${cur?.no === p.no ? 'on' : ''} ${p.flags?.length ? 'bad' : ''}`} onClick={() => select(p)}>
                      <span>{p.no}</span><span>{(p.ts - r.t0).toFixed(4)}</span><span>{p.src}</span><span>{p.dst}</span><span>{p.proto}</span><span className="hide-sm">{p.len}</span><span>{p.info}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <form className="mono" onSubmit={(e) => { e.preventDefault(); jumpTo(+goTo); }} style={{ display: 'flex', gap: 12, alignItems: 'center', fontSize: 13, margin: '12px 0' }}>
        <label htmlFor="pk-go" className="sm">Go to packet</label>
        <input id="pk-go" className="cr-input" inputMode="numeric" value={goTo} onChange={(e) => setGoTo(e.target.value.replace(/\D/g, ''))} style={{ width: 90, padding: '4px 0' }} />
      </form>
      {cur && det && (
        <div className="grid-2" style={{ marginTop: 8 }}>
          <div className="veil tree" style={{ padding: 16 }}>
            <h4 className="sm" style={{ marginTop: 0 }}>Decoded packet {cur.no}</h4>
            <Tree nodes={det.tree} sel={field} pick={setField} />
            {dom}
          </div>
          <div className="veil" style={{ padding: 16 }}>
            <h4 className="sm" style={{ marginTop: 0 }}>Source Locator</h4>
            <p className="dat" style={{ marginTop: 0 }}>{ev && locator(ev, field?.start !== undefined && field.len ? { start: field.start, len: field.len, label: field.label } : undefined)}</p>
            <Hex bytes={det.bytes} start={field?.start} len={field?.len} />
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16, marginTop: 12 }}>
              {ev && <Copy text={locator(ev, field?.start !== undefined && field.len ? { start: field.start, len: field.len, label: field.label } : undefined)} label="Copy locator" />}
              <Copy text={wsFilter(cur)} label="Copy Wireshark filter" />
              <Copy text={bpf(cur)} label="Copy BPF" />
              {cur.sport !== undefined && <button type="button" className="cr-btn st sm" onClick={follow} style={{ borderBottom: '1px solid var(--line)', padding: '2px 0' }}>Follow stream</button>}
            </div>
          </div>
        </div>
      )}
      {stream && (
        <div className="veil" style={{ padding: 16, marginTop: 24 }}>
          <h4 className="sm" style={{ marginTop: 0 }}>Stream, as inert text{stream.truncated ? ', cut at the size limit' : ''}</h4>
          <div className="hex" data-lenis-prevent style={{ maxHeight: 280, overflow: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
            {stream.parts.filter((p) => p.text).slice(0, 200).map((p, i) => <div key={i} className={p.fromA ? '' : 'ac'}>{p.text}</div>)}
          </div>
        </div>
      )}
    </div>
  );
}
