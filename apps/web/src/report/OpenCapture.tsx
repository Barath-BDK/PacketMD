'use client';
import { useRef } from 'react';
import { useCase } from '@/lib/engine';
import { Scan } from '@/shell/Shell';

/** Opens the file picker where the person already is, instead of sending them to Overview first. */
export function OpenCapture({ then }: { then?: () => void }) {
  const c = useCase(), input = useRef<HTMLInputElement>(null);
  return (
    <>
      <Scan onClick={() => input.current?.click()} disabled={!!c.busy}>Open a capture</Scan>
      <input ref={input} type="file" hidden aria-label="Choose a capture file" onChange={async (e) => { const f = e.target.files?.[0]; e.target.value = ''; if (f && await c.open(f)) then?.(); }} />
      <div aria-live="polite" className="sm" style={{ minHeight: 20, marginTop: 12 }}>
        {c.busy && <span>Scanning {c.busy}</span>}
        {c.gate && <span className="ac">Refused. {c.gate.reason}</span>}
        {c.error && <span className="ac">{c.error}</span>}
      </div>
    </>
  );
}
