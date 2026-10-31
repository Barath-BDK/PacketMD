'use client';
import { useEffect, useState } from 'react';
import { sb } from '@/lib/backend';

// The role check here is only for display. The real guard is RLS: a non-admin query returns no rows.
export default function Admin() {
  const [state, set] = useState<'loading' | 'denied' | 'ok'>('loading');
  const [rows, setRows] = useState<{ finding_type: string; verdict: string; note: string | null }[]>([]);
  const [counts, setCounts] = useState({ users: 0, reports: 0 });
  useEffect(() => {
    (async () => {
      if (!sb) { set('denied'); return; }
      const { data: u } = await sb.auth.getUser();
      if (!u.user) { set('denied'); return; }
      const { data: me } = await sb.from('profiles').select('role').eq('id', u.user.id).single();
      if (me?.role !== 'admin') { set('denied'); return; }
      const [fb, us, rp] = await Promise.all([sb.from('feedback').select('finding_type,verdict,note').limit(100), sb.from('profiles').select('id', { count: 'exact', head: true }), sb.from('reports').select('id', { count: 'exact', head: true })]);
      setRows(fb.data ?? []); setCounts({ users: us.count ?? 0, reports: rp.count ?? 0 }); set('ok');
    })();
  }, []);
  if (state === 'loading') return <div className="pad"><p className="sm">Checking your role</p></div>;
  if (state === 'denied') return <div className="pad"><h1 className="disp h2">Admins only.</h1><p className="muted">Sign in with an admin account to see this page.</p></div>;
  return (
    <div className="pad">
      <h1 className="disp h2 rise d1">Admin</h1>
      <p className="dat">{counts.users} users, {counts.reports} saved reports</p>
      <section className="veil" style={{ padding: 16 }}>
        <table className="t"><thead><tr><th scope="col">Finding</th><th scope="col">Marked as</th><th scope="col">Note</th></tr></thead>
          <tbody>{rows.map((r, i) => <tr key={i}><td>{r.finding_type}</td><td>{r.verdict}</td><td>{r.note}</td></tr>)}{!rows.length && <tr><td colSpan={3}>No feedback yet.</td></tr>}</tbody></table>
      </section>
    </div>
  );
}
