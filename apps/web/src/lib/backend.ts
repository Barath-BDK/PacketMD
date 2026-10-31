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
  const { error } = await sb.from('reports').insert({ owner: data.user.id, ...payload(r) });
  return error ? 'Could not save this report.' : 'Saved to your account.';
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
