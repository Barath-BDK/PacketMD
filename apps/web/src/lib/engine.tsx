'use client';
import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';
import { BUDGET, ENGINE_SCHEMA, type Baseline, type GateResult, type PacketRow, type Report, type TreeNode } from '@packetmd/core';

export type Outcome = { kind: 'done'; report: Report; sandboxed: boolean } | { kind: 'rejected'; gate: GateResult } | { kind: 'crashed'; message: string };

/** Worker handshake: nothing is parsed until the Worker proves its schema matches the UI's. */
export function startWorker(): Promise<{ w: Worker; sandboxed: boolean }> {
  return new Promise((res, rej) => {
    const w = new Worker('/worker/analyze.js');
    const t = setTimeout(() => { w.terminate(); rej(new Error('The parser did not start.')); }, 5000);
    w.onmessage = (e) => {
      if (e.data.type !== 'ready') return;
      clearTimeout(t);
      if (e.data.schema !== ENGINE_SCHEMA) { w.terminate(); rej(new Error('Parser and page are different versions. Reload the page.')); return; }
      res({ w, sandboxed: e.data.sandboxed });
    };
    w.onerror = () => { clearTimeout(t); rej(new Error('The parser failed to start.')); };
    w.postMessage({ type: 'hello' });
  });
}

/** A hostile file can kill only this Worker: the watchdog terminates it and the page carries on. */
export async function runFile(file: File, opts: { baseline?: Baseline; onProgress?: (p: number) => void; keep?: boolean } = {}): Promise<Outcome & { worker?: Worker }> {
  const { w, sandboxed } = await startWorker();
  return new Promise((res) => {
    const dog = setTimeout(() => { w.terminate(); res({ kind: 'crashed', message: 'Stopped by the time budget.' }); }, BUDGET.maxParseMs + 3000);
    const end = (o: Outcome, keep = false) => { clearTimeout(dog); if (!keep) w.terminate(); res({ ...o, worker: keep ? w : undefined }); };
    w.onmessage = (e) => {
      const m = e.data;
      if (m.type === 'progress') opts.onProgress?.(m.done / m.total);
      if (m.type === 'done') end({ kind: 'done', report: m.report, sandboxed }, opts.keep);
      if (m.type === 'rejected') end({ kind: 'rejected', gate: m.gate });
      if (m.type === 'error') end({ kind: 'crashed', message: m.message });
    };
    w.onerror = () => end({ kind: 'crashed', message: 'The parser Worker died. The page is unaffected.' });
    w.postMessage({ type: 'analyze', file, baseline: opts.baseline });
  });
}

interface CaseState {
  report: Report | null; file: File | null; sandboxed: boolean | null; busy: string | null; progress: number; gate: GateResult | null; error: string | null;
  open(file: File): Promise<boolean>; openSample(name: string): Promise<boolean>; reset(): void;
  packet(row: PacketRow): Promise<{ tree: TreeNode[]; bytes: number[] }>;
  stream(rows: { row: PacketRow; fromA: boolean; start: number }[]): Promise<{ parts: { fromA: boolean; text: string }[]; truncated: boolean }>;
  archived: string | null; openSaved(r: Report, savedAt: string): void;
  filter: string | null; setFilter(q: string | null): void;
  jump: number | null; setJump(n: number | null): void; tab: string; setTab(t: string): void; level: 'beginner' | 'technical' | 'analyst'; setLevel(l: 'beginner' | 'technical' | 'analyst'): void;
  baseline: Baseline | null; setBaseline(b: Baseline | null): void;
}

const Ctx = createContext<CaseState | null>(null);
export const useCase = () => useContext(Ctx)!;

export function CaseProvider({ children }: { children: React.ReactNode }) {
  const [report, setReport] = useState<Report | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [sandboxed, setSandboxed] = useState<boolean | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [gate, setGate] = useState<GateResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [jump, setJump] = useState<number | null>(null);
  const [filter, setFilter] = useState<string | null>(null);
  const [archived, setArchived] = useState<string | null>(null);
  const [tab, setTab] = useState('verdict');
  const [level, setLevel] = useState<'beginner' | 'technical' | 'analyst'>('beginner');
  const [baseline, setBaseline] = useState<Baseline | null>(null);
  const worker = useRef<Worker | null>(null), seq = useRef(0);

  const open = useCallback(async (f: File) => {
    setBusy(f.name); setGate(null); setError(null); setProgress(0);
    worker.current?.terminate(); worker.current = null;
    try {
      const o = await runFile(f, { baseline: baseline ?? undefined, onProgress: setProgress, keep: true });
      if (o.kind === 'done') { setArchived(null); setReport(o.report); setFile(f); setSandboxed(o.sandboxed); setTab('verdict'); worker.current = o.worker ?? null; return true; }
      if (o.kind === 'rejected') setGate(o.gate); else setError(o.message);
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(null); }
    return false;
  }, [baseline]);

  const openSample = useCallback(async (name: string) => {
    const r = await fetch(`/samples/${encodeURIComponent(name)}`);
    return open(new File([await r.blob()], name));
  }, [open]);

  const ask = useCallback(<T,>(type: string, extra: object) => new Promise<T>((res, rej) => {
    const w = worker.current, id = ++seq.current;
    if (!w || !file) { rej(new Error('Open a capture first.')); return; }
    const on = (e: MessageEvent) => {
      if (e.data.id !== id) return;
      w.removeEventListener('message', on);
      if (e.data.type === 'error') rej(new Error(e.data.message)); else res(e.data as T);
    };
    w.addEventListener('message', on);
    w.postMessage({ type, id, file, ...extra });
  }), [file]);

  const value = useMemo<CaseState>(() => ({
    report, file, sandboxed, busy, progress, gate, error, open, openSample,
    reset: () => { setReport(null); setFile(null); },
    packet: (row) => ask('packet', { row }), stream: (rows) => ask('stream', { rows }),
    archived, openSaved: (r, savedAt) => { worker.current?.terminate(); worker.current = null; setReport(r); setFile(null); setArchived(savedAt); setTab('verdict'); },
    filter, setFilter, jump, setJump, tab, setTab, level, setLevel, baseline, setBaseline,
  }), [report, file, sandboxed, busy, progress, gate, error, open, openSample, ask, archived, filter, jump, tab, level, baseline]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
