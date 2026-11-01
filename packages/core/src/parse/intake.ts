import { BUDGET } from '../thresholds';
import { safeName } from '../sanitize';

export interface GateStep { key: string; label: string; ok: boolean; detail: string }
export interface GateResult { ok: boolean; reason?: string; format?: 'pcap' | 'pcapng'; steps: GateStep[]; name: string }

const MAGICS: Record<string, 'pcap' | 'pcapng'> = {
  a1b2c3d4: 'pcap', d4c3b2a1: 'pcap', a1b23c4d: 'pcap', '4d3cb2a1': 'pcap', '0a0d0d0a': 'pcapng',
};
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

const KNOWN_BAD: [string, string][] = [
  ['4d5a', 'a Windows program'], ['7f454c46', 'a Linux program'], ['504b0304', 'a zip archive'],
  ['1f8b', 'a gzip archive'], ['25504446', 'a PDF'], ['526172', 'a RAR archive'], ['3c21', 'an HTML page'],
];

/** The allowlist gate: extension AND magic bytes must agree, or the file goes no further. */
export function gate(fileName: string, size: number, head: Uint8Array): GateResult {
  const name = safeName(fileName);
  const steps: GateStep[] = [];
  const fail = (key: string, label: string, reason: string): GateResult => {
    steps.push({ key, label, ok: false, detail: reason });
    return { ok: false, reason, steps, name };
  };

  // Checked on the original name: the display copy is shortened and would lose its extension.
  const ext = /\.(pcapng|pcap)$/i.exec(fileName.trim())?.[1]?.toLowerCase() as 'pcap' | 'pcapng' | undefined;
  if (!ext) return fail('ext', 'File type', `Only .pcap and .pcapng files are accepted. "${name}" is neither.`);
  steps.push({ key: 'ext', label: 'File type', ok: true, detail: `.${ext}` });

  if (size > BUDGET.maxFileBytes) return fail('size', 'Size', `This file is ${(size / 1048576).toFixed(0)} MB. The limit is ${BUDGET.maxFileBytes / 1048576} MB.`);
  if (size < 24 && ext === 'pcap') return fail('size', 'Size', 'This file is too short to hold a capture header.');
  if (size < 12) return fail('size', 'Size', 'This file is too short to hold a capture header.');
  steps.push({ key: 'size', label: 'Size', ok: true, detail: `${size} bytes` });

  const sig = hex(head.subarray(0, 4));
  const fmt = MAGICS[sig];
  if (!fmt) {
    const bad = KNOWN_BAD.find(([m]) => sig.startsWith(m));
    return fail('magic', 'Signature', bad ? `This file is named like a capture but it is really ${bad[1]}. It was not opened.` : `The first bytes (${sig}) are not a capture signature. It was not opened.`);
  }
  if (fmt !== ext) return fail('magic', 'Signature', `The name says .${ext} but the bytes say ${fmt}. Files that disagree with themselves are refused.`);
  steps.push({ key: 'magic', label: 'Signature', ok: true, detail: sig });
  return { ok: true, format: fmt, steps, name };
}
