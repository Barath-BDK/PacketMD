import { techniqueOf } from './explain/mitre';
import { BUDGET } from './thresholds';
import { decode } from './decode/decode';
import { neutralize } from './sanitize';
import type { Evidence, Report, RawPacket, TreeNode } from './types';

export function dissect(raw: RawPacket): { tree: TreeNode[] } {
  const tree: TreeNode[] = [];
  decode(raw, tree);
  return { tree };
}

/** Escaped, size-capped text: stream bytes are never interpreted. */
export function followStream(chunks: { fromA: boolean; data: Uint8Array }[]) {
  let total = 0;
  const out: { fromA: boolean; text: string }[] = [];
  for (const c of chunks) {
    if (total >= BUDGET.maxStream) break;
    const d = c.data.subarray(0, BUDGET.maxStream - total);
    total += d.length;
    let t = '';
    for (const b of d) t += b === 10 || b === 13 || b === 9 ? String.fromCharCode(b) : b >= 32 && b < 127 ? String.fromCharCode(b) : '.';
    out.push({ fromA: c.fromA, text: t });
  }
  return { parts: out, truncated: total >= BUDGET.maxStream };
}

export function locator(e: Evidence, field?: { start: number; len: number; label: string }) {
  const hex = (n: number) => '0x' + n.toString(16).toUpperCase();
  const end = e.dataOffset + e.capLen - 1;
  const base = `pkt ${e.no} - file offset ${hex(e.dataOffset)}..${hex(end)}${e.blockType ? ` - pcapng ${e.blockType} block at ${hex(e.recordOffset)}` : ` - record at ${hex(e.recordOffset)}`}`;
  return field ? `${base} - ${field.label} bytes ${field.start}..${field.start + field.len - 1}` : base;
}

export function toMarkdown(r: Report) {
  const lines = [`# PacketMD report`, ``, `File SHA-256: ${r.defense.sha256}`, ``, neutralize(r.headline), ``];
  for (const f of r.findings) {
    const tech = techniqueOf(f.hypothesis);
    lines.push(`## ${f.id} ${neutralize(f.title)} (${f.lane}, ${f.confidence})`, '', ...(tech ? [`MITRE ATT&CK: ${tech.id} ${tech.name}`, ''] : []), neutralize(f.plain), '', `Cause: ${neutralize(f.cause)}`, '', `Evidence packets: ${f.evidence.map((e) => e.no).slice(0, 20).join(', ')}`, '');
    f.fixSteps.forEach((s, i) => lines.push(`${i + 1}. ${neutralize(s.title)}`));
    lines.push('');
  }
  return lines.join('\n');
}
