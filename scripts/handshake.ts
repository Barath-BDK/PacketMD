import { existsSync, readFileSync } from 'node:fs';
import { analyze, ENGINE_SCHEMA } from '@packetmd/core';
import { fileSource } from '../packages/cli/src/source';
import { payload } from '../apps/web/src/lib/payload';

// Proves the three parties agree before anyone relies on them: engine, frontend contract, live backend.
const envFile = 'apps/web/.env.local';
const env = Object.fromEntries((existsSync(envFile) ? readFileSync(envFile, 'utf8') : '').split(/\r?\n/).filter((l) => l.includes('=')).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
const url = process.env.NEXT_PUBLIC_SUPABASE_URL ?? env.NEXT_PUBLIC_SUPABASE_URL, anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
let failed = 0;
const check = (name: string, ok: boolean, detail = '') => { if (!ok) failed++; console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? `  (${detail})` : ''}`); };
if (!url || !anon) { console.log('Guest mode: no backend configured, nothing to shake hands with.'); process.exit(0); }

const h = { apikey: anon, authorization: `Bearer ${anon}`, 'content-type': 'application/json' };
const rest = (t: string, init?: RequestInit) => fetch(`${url}/rest/v1/${t}`, { ...init, headers: { ...h, ...init?.headers } });
const fn = (q = '', init?: RequestInit) => fetch(`${url}/functions/v1/share-report${q}`, { ...init, headers: { ...h, origin: 'http://localhost:3000' } });

const src = fileSource('samples/mixed-incident.pcap');
const r = await analyze(src, 'mixed-incident.pcap');
src.close();
check('engine produces the agreed schema', r.schema === ENGINE_SCHEMA, `schema ${r.schema}`);
const body = payload(r), text = JSON.stringify(body);
check('payload holds no addresses', !/\b\d{1,3}(\.\d{1,3}){3}\b/.test(text) && !/([0-9a-f]{2}:){5}/i.test(text));
check('payload holds no packet rows or bytes', !text.includes('dataOffset') && !text.includes('"rows"'));

for (const t of ['reports', 'baselines', 'shares', 'feedback', 'profiles', 'share_limits']) {
  const res = await rest(`${t}?select=*&limit=1`);
  check(`guest cannot read ${t}`, res.status === 401 || res.status === 403 || (await res.json()).length === 0, `HTTP ${res.status}`);
}
const ins = await rest('reports', { method: 'POST', body: JSON.stringify(body) });
check('guest cannot write reports directly', ins.status === 401 || ins.status === 403, `HTTP ${ins.status}`);
const rpc = await rest('rpc/bump_share_rate', { method: 'POST', body: JSON.stringify({ k: 'x', max_hits: 1 }) });
check('guest cannot call the rate limiter', rpc.status === 401 || rpc.status === 403 || rpc.status === 404, `HTTP ${rpc.status}`);
const adm = await rest('rpc/is_admin', { method: 'POST', body: '{}' });
check('admin check is not on the public API', adm.status === 404, `HTTP ${adm.status}`);

check('function refuses a bad shape', (await fn('', { method: 'POST', body: '{"file_sha256":"x"}' })).status === 400);
check('function refuses unknown fields', (await fn('', { method: 'POST', body: JSON.stringify({ ...body, rawPacket: 'AAAA' }) })).status === 400);
check('function refuses an oversize body', (await fn('', { method: 'POST', body: 'x'.repeat(300 * 1024) })).status === 413);
check('function refuses a bad token', (await fn('?token=../../etc')).status === 404);
check('function hides unknown tokens', (await fn(`?token=${'0'.repeat(32)}`)).status === 404);

const made = await fn('', { method: 'POST', body: text });
const out = await made.json() as { token?: string };
check('share created', made.status === 201 && /^[0-9a-f]{32}$/.test(out.token ?? ''), `HTTP ${made.status}`);
check('CORS names the allowed origin', made.headers.get('access-control-allow-origin') === 'http://localhost:3000');
if (out.token) {
  const back = await fn(`?token=${out.token}`), got = await back.json() as { summary: { headline: string }; findings: unknown[] };
  check('share round trip matches', back.status === 200 && got.summary.headline === body.summary.headline && got.findings.length === body.findings.length);
}
console.log(failed ? `\n${failed} handshake checks failed` : '\nHandshake complete: engine, frontend and backend agree.');
process.exit(failed ? 1 : 0);
