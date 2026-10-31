#!/usr/bin/env node
import { analyze, locator, Rejected, type Evidence, type Level } from '@packetmd/core';
import { fileSource } from './source';

const USAGE = `PacketMD: diagnose a packet capture.

  packetmd analyze <file> [--json] [--level beginner|technical|analyst]
  packetmd locate <file> --packet N`;

async function main(argv: string[]) {
  const args = argv[0] === 'analyze' || argv[0] === 'locate' ? argv : ['analyze', ...argv];
  const [cmd, file] = args;
  const opt = (k: string) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : undefined; };
  if (!file) { console.log(USAGE); return 1; }
  const src = fileSource(file);
  try {
    const r = await analyze(src, file);
    if (cmd === 'locate') {
      const n = Number(opt('--packet')), row = r.rows[n - 1];
      if (!row) { console.error(`No packet ${n}. This capture has ${r.rows.length}.`); return 1; }
      console.log(locator(row as unknown as Evidence));
      console.log(`${row.proto} ${row.info}`);
      return 0;
    }
    if (args.includes('--json')) { const { rows: _r, ...rest } = r; console.log(JSON.stringify(rest, null, 2)); return 0; }
    const level = (opt('--level') ?? 'beginner') as Level;
    const d = r.defense;
    console.log(`\n${r.headline}`);
    console.log(`${d.packets} packets, ${d.skipped} skipped, sha256 ${d.sha256.slice(0, 16)}...\n`);
    for (const f of r.findings) {
      console.log(`${f.id} [${f.lane}] ${f.title} (${f.confidence} confidence)`);
      console.log(`   ${level === 'beginner' ? f.plain : level === 'technical' ? f.technical : f.analyst}`);
      console.log(`   Cause: ${f.cause}`);
      console.log(`   Proof packets: ${f.evidence.slice(0, 8).map((e) => e.no).join(', ')}`);
      f.fixSteps.forEach((s, i) => console.log(`   Fix ${i + 1}: ${s.title}`));
      if (f.nextCapture) console.log(`   Capture next: ${f.nextCapture}`);
      console.log('');
    }
    return 0;
  } catch (e) {
    if (e instanceof Rejected) { console.error(`Refused: ${e.message}`); return 2; }
    throw e;
  } finally { src.close(); }
}

main(process.argv.slice(2)).then((c) => { process.exitCode = c; });
