'use client';
import { useEffect, useState } from 'react';
import type { User } from '@supabase/supabase-js';
import { hasBackend, roleOf, sb } from '@/lib/backend';
import { Hv, Scan, useShell } from '@/shell/Shell';

export default function SignIn() {
  const { go } = useShell();
  const [email, setEmail] = useState(''), [pw, setPw] = useState(''), [msg, setMsg] = useState(''), [busy, setBusy] = useState(false);
  const [user, setUser] = useState<User | null>(null), [role, setRole] = useState<string | null>(null);

  useEffect(() => { sb?.auth.getUser().then(async ({ data }) => { setUser(data.user); setRole(await roleOf(data.user)); }); }, []);
  const act = async (kind: 'in' | 'up') => {
    if (!sb) return;
    setBusy(true); setMsg('');
    const { data, error } = kind === 'in' ? await sb.auth.signInWithPassword({ email, password: pw }) : await sb.auth.signUp({ email, password: pw });
    setBusy(false); setPw('');
    // One message for every failure, so this form cannot be used to test which emails exist.
    if (error) { setMsg('That did not work. Check the details and try again.'); return; }
    if (kind === 'up' && !data.session) { setMsg('Check your email to confirm the account.'); return; }
    setUser(data.user); setRole(await roleOf(data.user));
  };

  return (
    <div className="sign">
      <h1 className="h1 rise d1" data-safe="text" data-edge="1" style={{ maxWidth: '5em', fontSize: 'clamp(60px, min(8vw, 13vh), 120px)' }}>One door. Your role decides the room.</h1>
      <div className="solid rise d2" data-safe="text" style={{ display: 'flex', flexDirection: 'column', gap: 22, padding: '26px 28px', border: '1px solid var(--line)' }}>
        {!hasBackend && <p style={{ margin: 0, lineHeight: 1.5 }}>Accounts are not configured on this copy. Everything except saved reports and share links works as a guest.</p>}
        {hasBackend && !user && <form onSubmit={(e) => { e.preventDefault(); void act('in'); }} style={{ display: 'flex', flexDirection: 'column', gap: 22 }}>
          <label className="sm" style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>Email<input className="cr-input" type="email" required autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          <label className="sm" style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>Password<input className="cr-input" type="password" required minLength={10} autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} /></label>
          <Scan type="submit" disabled={busy}>Continue</Scan>
          <Hv onClick={() => void act('up')} disabled={busy}>Create an account</Hv>
        </form>}
        {user && <>
          <p style={{ margin: 0 }}>Signed in as <strong>{role === 'admin' ? 'Admin' : 'Analyst'}</strong>.</p>
          {role === 'admin' && <Scan onClick={() => go('/admin')}>Open admin</Scan>}
          <Hv onClick={() => sb?.auth.signOut().then(() => { setUser(null); setRole(null); })}>Sign out</Hv>
        </>}
        {msg && <p role="status" className="ac" style={{ margin: 0 }}>{msg}</p>}
        <p className="muted" style={{ margin: 0, fontSize: 14, lineHeight: 1.5 }}>Analysts keep their own reports. Admins also see team feedback. No account is needed to scan a file.</p>
      </div>
    </div>
  );
}
