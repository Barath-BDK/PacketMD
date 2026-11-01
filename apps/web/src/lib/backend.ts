import { createClient, type SupabaseClient, type User } from '@supabase/supabase-js';
import { neutralize, type Report } from '@packetmd/core';
import { payload } from './payload';

export { payload };

const url = process.env.NEXT_PUBLIC_SUPABASE_URL, anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
export const hasBackend = !!(url && anon);
// Guest mode has no client at all: without these values no request can reach a backend.
export const sb: SupabaseClient | null = hasBackend ? createClient(url!, anon!) : null;

export async function saveReport(r: Report) {
  if (!sb) return 'Backend not configured.';
  const { data } = await sb.auth.getUser();
  if (!data.user) return 'Sign in first. Guest reports stay in this tab.';
  const { data: dup } = await sb.from('reports').select('id').eq('owner', data.user.id).eq('file_sha256', r.defense.sha256).limit(1);
  if (dup?.length) return 'This capture is already in your investigations.';
  const { error } = await sb.from('reports').insert({ owner: data.user.id, file_name: r.defense.fileName, ...payload(r) });
  return error ? 'Could not save this report.' : 'Saved to your investigations.';
}

export async function sendFeedback(findingType: string, verdict: 'correct' | 'false-positive') {
  if (!sb) return 'Backend not configured.';
  const { data } = await sb.auth.getUser();
  if (!data.user) return 'Log in to send feedback.';
  const { error } = await sb.from('feedback').insert({ owner: data.user.id, finding_type: findingType, verdict });
  return error ? 'Could not send that.' : 'Thanks, noted.';
}

export interface SavedFinding { id: string; lane: string; title: string; confidence: string; plain: string; cause: string; whyNotTheOther: string; verifyBy: string; fixTitles: string[]; proofPackets: number[] }
export interface SavedReport { id: string; created_at: string; file_name: string | null; file_sha256: string; summary: { headline: string; packets: number }; findings: SavedFinding[] }

/** Only the caller's own rows: admins can read every report under RLS, so the filter must be explicit. Null means the read failed. */
export async function savedReports(): Promise<SavedReport[] | null> {
  if (!sb) return null;
  const { data: me } = await sb.auth.getUser();
  if (!me.user) return null;
  const { data, error } = await sb.from('reports').select('id, created_at, file_name, file_sha256, summary, findings').eq('owner', me.user.id).order('created_at', { ascending: false }).limit(100);
  return error ? null : (data as SavedReport[]);
}

export async function deleteReport(id: string) {
  if (!sb) return false;
  const { data: me } = await sb.auth.getUser();
  if (!me.user) return false;
  const { error } = await sb.from('reports').delete().eq('id', id).eq('owner', me.user.id);
  return !error;
}

export async function shareReport(r: Report) {
  if (!sb) throw new Error('Backend not configured.');
  const { data, error } = await sb.functions.invoke('share-report', { body: payload(r) });
  if (error || !data?.token) throw new Error('Could not create the link. Try again in a minute.');
  return data.token as string;
}

export async function readShare(token: string) {
  if (!url || !anon) return null;
  const res = await fetch(`${url}/functions/v1/share-report?token=${encodeURIComponent(token)}`, { headers: { apikey: anon, authorization: `Bearer ${anon}` } });
  return res.ok ? res.json() : null;
}

export async function roleOf(user: User | null): Promise<'admin' | 'analyst' | null> {
  if (!sb || !user) return null;
  const { data } = await sb.from('profiles').select('role').eq('id', user.id).single();
  return (data?.role as 'admin' | 'analyst') ?? 'analyst';
}

export const safe = neutralize;
