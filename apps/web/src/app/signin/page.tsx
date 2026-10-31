'use client';
import { useEffect, useState } from 'react';
import type { User } from '@supabase/supabase-js';
import { hasBackend, roleOf, sb } from '@/lib/backend';
import { Hv, Scan, useShell } from '@/shell/Shell';

export default function SignIn() {
  const { go } = useShell();
  const [mode, setMode] = useState<'login' | 'create'>('login');
  const [email, setEmail] = useState(''), [pw, setPw] = useState(''), [pw2, setPw2] = useState(''), [msg, setMsg] = useState(''), [busy, setBusy] = useState(false);
  const [user, setUser] = useState<User | null>(null), [role, setRole] = useState<string | null>(null);
  const creating = mode === 'create';

  useEffect(() => { sb?.auth.getUser().then(async ({ data }) => { setUser(data.user); setRole(await roleOf(data.user)); }); }, []);
  const switchTo = (m: 'login' | 'create') => { setMode(m); setMsg(''); setPw(''); setPw2(''); };
  const submit = async () => {
    if (!sb) return;
    if (creating && pw !== pw2) { setMsg('The two passwords do not match.'); return; }
    setBusy(true); setMsg('');
    const { data, error } = creating ? await sb.auth.signUp({ email, password: pw }) : await sb.auth.signInWithPassword({ email, password: pw });
    setBusy(false); setPw(''); setPw2('');
    // One message for every failure, so this form cannot be used to test which emails exist.
    if (error) { setMsg('That did not work. Check the details and try again.'); return; }
    if (creating && !data.session) { setMsg('Check your email to confirm the account, then log in.'); switchTo('login'); return; }
    setUser(data.user); setRole(await roleOf(data.user));
  };

  return (
    <div className="sign">
      <h1 className="h1 rise d1" data-safe="text" data-edge="1" style={{ maxWidth: '5em', fontSize: 'clamp(60px, min(8vw, 13vh), 120px)' }}>{user ? 'Welcome back.' : creating ? 'Create an account.' : 'Log in.'}</h1>
      <div className="solid rise d2" data-safe="text" style={{ display: 'flex', flexDirection: 'column', gap: 18, padding: '26px 28px', border: '1px solid var(--line)' }}>
        {!hasBackend && <p style={{ margin: 0, lineHeight: 1.5 }}>Accounts are not configured on this copy. Everything except saved reports and share links works as a guest.</p>}
        {hasBackend && !user && <form onSubmit={(e) => { e.preventDefault(); void submit(); }} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <h2 className="disp h3">{creating ? 'Create an account' : 'Log in'}</h2>
          <label className="sm">Email<input className="cr-input" type="email" required autoComplete="email" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          <label className="sm">Password<input className="cr-input" type="password" required minLength={10} autoComplete={creating ? 'new-password' : 'current-password'} placeholder={creating ? 'At least 10 characters' : ''} value={pw} onChange={(e) => setPw(e.target.value)} /></label>
          {creating && <label className="sm">Confirm password<input className="cr-input" type="password" required minLength={10} autoComplete="new-password" value={pw2} onChange={(e) => setPw2(e.target.value)} /></label>}
          <Scan type="submit" disabled={busy}>{creating ? 'Create account' : 'Log in'}</Scan>
          <p style={{ margin: 0, fontSize: 15 }}>
            {creating ? 'Already have an account? ' : "Don't have an account? "}
            <button type="button" className="cr-btn ac" style={{ textDecoration: 'underline', fontWeight: 600 }} onClick={() => switchTo(creating ? 'login' : 'create')}>{creating ? 'Log in' : 'Create one'}</button>
          </p>
        </form>}
        {user && <>
          <p style={{ margin: 0 }}>Signed in as <strong>{role === 'admin' ? 'Admin' : 'Analyst'}</strong>.</p>
          {role === 'admin' && <Scan onClick={() => go('/admin')}>Open admin</Scan>}
          <Hv onClick={() => sb?.auth.signOut().then(() => { setUser(null); setRole(null); })}>Log out</Hv>
        </>}
        {msg && <p role="status" className="ac" style={{ margin: 0 }}>{msg}</p>}
        <p className="muted" style={{ margin: 0, fontSize: 14, lineHeight: 1.5 }}>Analysts keep their own reports. Admins also see team feedback. No account is needed to scan a file.</p>
      </div>
    </div>
  );
}
