import { build } from 'esbuild';
import { cpSync, mkdirSync, readdirSync, statSync, writeFileSync, copyFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = join(dirname(fileURLToPath(import.meta.url)), '..'), root = join(web, '..', '..');
await build({ entryPoints: [join(web, 'src/worker/analyze.worker.ts')], bundle: true, format: 'iife', target: 'es2022', minify: true, outfile: join(web, 'public/worker/analyze.js'), logLevel: 'warning' });
mkdirSync(join(web, 'public/samples'), { recursive: true });
mkdirSync(join(web, 'src/generated'), { recursive: true });
const samples = readdirSync(join(root, 'samples')).filter((f) => f.endsWith('.pcap') && !f.startsWith('large'));
for (const f of samples) copyFileSync(join(root, 'samples', f), join(web, 'public/samples', f));
cpSync(join(root, 'labgen/hostile'), join(web, 'public/hostile'), { recursive: true });
const expected = JSON.parse((await import('node:fs')).readFileSync(join(root, 'samples/expected.json'), 'utf8'));
writeFileSync(join(web, 'src/generated/samples.json'), JSON.stringify(samples.map((f) => ({ file: f, bytes: statSync(join(root, 'samples', f)).size, note: expected[f.replace('.pcap', '')]?.note ?? '' }))));
copyFileSync(join(root, 'samples/accuracy.json'), join(web, 'src/generated/accuracy.json'));
