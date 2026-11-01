'use client';
import { useRef, useState } from 'react';
import { BUDGET } from '@packetmd/core';
import samples from '@/generated/samples.json';
import { useCase } from '@/lib/engine';
import { Hv, Scan, useShell } from '@/shell/Shell';

const STEPS = ['Sniff the signature', 'Check size and type', 'Parse in a sandbox', 'Weigh the evidence', 'Write the fix'];
const pretty = (f: string) => f.replace('.pcap', '').replace(/-/g, ' ');

export default function Home() {
  const c = useCase(), { go } = useShell();
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const run = async (p: Promise<boolean>) => { if (await p) go('/report'); };
  const demo = samples.find((s) => s.file === 'mixed-incident.pcap');
  return (
    <div onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)} onDrop={(e) => { e.preventDefault(); setOver(false); const f = e.dataTransfer.files[0]; if (f) void run(c.open(f)); }}>
      <section className="hero">
        <h1 className="h1 rise d1" data-safe="text" data-edge="1">Fault or attack. Know which.</h1>
        <p className="rise d2" data-safe="text" style={{ margin: 0, maxWidth: '46ch', fontSize: 18, lineHeight: 1.5, color: 'var(--muted)' }}>
          Drop a packet capture. PacketMD names what went wrong, shows the exact packets that prove it, and writes the fix for your network. The file never leaves this device.
        </p>
        <div className="rise d3 mono" data-safe="text" style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 32, width: 'max-content', maxWidth: '100%', fontSize: 14 }}>
          <Scan onClick={() => input.current?.click()} disabled={!!c.busy}>{over ? 'Drop to scan' : 'Open a capture'}</Scan>
          {demo && <Hv className="under" onClick={() => void run(c.openSample(demo.file))} disabled={!!c.busy} style={{ borderBottomColor: 'var(--muted)', padding: '10px 0' }}>Try the mixed incident</Hv>}
          <input ref={input} type="file" hidden aria-label="Choose a capture file" onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ''; if (f) void run(c.open(f)); }} />
        </div>
        <div aria-live="polite" className="sm" data-safe="text" style={{ minHeight: 20 }}>
          {c.busy && <span>Scanning {c.busy}: {STEPS[Math.min(STEPS.length - 1, Math.floor(c.progress * STEPS.length))]}</span>}
          {c.gate && <span className="ac">Refused. {c.gate.reason}</span>}
          {c.error && <span className="ac">{c.error}</span>}
          {!c.busy && !c.gate && !c.error && <span>.pcap and .pcapng up to {BUDGET.maxFileBytes / 1048576} MB. No account needed.</span>}
        </div>
      </section>

      <section className="pad">
        <div className="veil" style={{ padding: '32px 24px' }}>
          <h2 className="disp h2">Lab captures to try</h2>
          <p className="muted" style={{ maxWidth: '60ch', lineHeight: 1.5 }}>Each one was generated in our lab, so no real network is involved. They open through the same gate and sandbox as your own files.</p>
          <div>
            {samples.filter((s) => s.file !== 'mixed-incident-after-fix.pcap').map((s) => (
              <button type="button" key={s.file} className="rowbtn" style={{ gridTemplateColumns: 'minmax(0,1fr) minmax(0,1.4fr) 90px' }} disabled={!!c.busy} onClick={() => void run(c.openSample(s.file))}>
                <span style={{ textTransform: 'capitalize' }}>{pretty(s.file)}</span>
                <span className="muted" style={{ fontSize: 14 }}>{s.note}</span>
                <span className="dat" style={{ textAlign: 'right' }}>{Math.ceil(s.bytes / 1024)} KB</span>
              </button>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
