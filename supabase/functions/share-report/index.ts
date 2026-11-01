import { createClient } from 'npm:@supabase/supabase-js@2';
import { z } from 'npm:zod@3';

const MAX_BODY = 256 * 1024, MAX_PER_HOUR = 10, MAX_GLOBAL_PER_HOUR = 300, TTL_DAYS = 7;

const text = (n: number) => z.string().max(n);
const Finding = z.object({
  id: text(8), lane: z.enum(['FAULT', 'ATTACK', 'BENIGN', 'INCONCLUSIVE']), hypothesis: text(40), title: text(160), confidence: z.enum(['low', 'medium', 'high']),
  plain: text(1000), cause: text(1000), whyNotTheOther: text(1000), analogy: text(400), verifyBy: text(400),
  fixTitles: z.array(text(200)).max(12), proofPackets: z.array(z.number().int().positive()).max(20),
}).strict();
const Body = z.object({
  file_sha256: z.string().regex(/^[0-9a-f]{64}$/),
  summary: z.object({ headline: text(300), packets: z.number().int().nonnegative(), schema: z.number().int() }).strict(),
  findings: z.array(Finding).max(100),
}).strict();

// No cookies are involved, so this only limits which sites can call the function from a browser.
const ALLOWED = /^(http:\/\/localhost:3000|https:\/\/[a-z0-9-]*packetmd[a-z0-9-]*\.vercel\.app)$/;

const db = () => createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, { auth: { persistSession: false } });

async function digest(s: string) {
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(h), (b) => b.toString(16).padStart(2, '0')).join('');
}

Deno.serve(async (req) => {
  const origin = req.headers.get('origin') ?? '';
  const cors: Record<string, string> = {
    'Vary': 'Origin', 'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'authorization, apikey, content-type, x-client-info',
  };
  if (ALLOWED.test(origin)) cors['Access-Control-Allow-Origin'] = origin;
  const send = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: cors });
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

  try {
    if (req.method === 'GET') {
      const token = new URL(req.url).searchParams.get('token') ?? '';
      if (!/^[0-9a-f]{32}$/.test(token)) return send(404, { error: 'not found' });
      const { data } = await db().from('shares').select('expires_at, reports(summary, findings)').eq('token', token).maybeSingle();
      if (!data || new Date(data.expires_at) < new Date()) return send(404, { error: 'not found' });
      return send(200, data.reports);
    }
    if (req.method !== 'POST') return send(405, { error: 'method not allowed' });

    if (Number(req.headers.get('content-length') ?? 0) > MAX_BODY) return send(413, { error: 'too large' });
    const raw = await req.text();
    if (raw.length > MAX_BODY) return send(413, { error: 'too large' });
    let json: unknown;
    try { json = JSON.parse(raw); } catch { return send(400, { error: 'invalid body' }); }
    const parsed = Body.safeParse(json);
    if (!parsed.success) return send(400, { error: 'invalid body' });

    const client = db();
    // A client can write its own x-forwarded-for, so the edge's headers come first and the last hop is the fallback.
    const ip = req.headers.get('cf-connecting-ip') ?? req.headers.get('x-real-ip') ?? (req.headers.get('x-forwarded-for') ?? 'unknown').split(',').at(-1)!.trim();
    const who = await digest(ip);
    const { data: allowed, error: rateError } = await client.rpc('bump_share_rate', { k: who, max_hits: MAX_PER_HOUR });
    if (rateError) return send(500, { error: 'unavailable' });
    if (!allowed) return send(429, { error: 'rate limited' });
    // A ceiling for the whole service, in case someone rotates addresses.
    const { data: open } = await client.rpc('bump_share_rate', { k: 'global', max_hits: MAX_GLOBAL_PER_HOUR });
    if (!open) return send(429, { error: 'rate limited' });

    const { data: report, error } = await client.from('reports').insert({ ...parsed.data, owner: null }).select('id').single();
    if (error) return send(500, { error: 'unavailable' });
    const token = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
    const expires_at = new Date(Date.now() + TTL_DAYS * 864e5).toISOString();
    const { error: shareError } = await client.from('shares').insert({ token, report_id: report.id, expires_at });
    if (shareError) return send(500, { error: 'unavailable' });
    return send(201, { token, expires_at });
  } catch {
    return send(500, { error: 'unavailable' });
  }
});
