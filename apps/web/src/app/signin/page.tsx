'use client';
import { useEffect, useRef, useState } from 'react';
import type { User } from '@supabase/supabase-js';
import { hasBackend, roleOf, sb } from '@/lib/backend';
import { Hv, Scan, useShell } from '@/shell/Shell';

function Password({ label, value, onChange, auto, placeholder }: { label: string; value: string; onChange(v: string): void; auto: string; placeholder?: string }) {
  const [show, setShow] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const toggle = () => {
    setShow(!show);
    input.current?.animate([{ opacity: 0.25 }, { opacity: 1 }], { duration: 200, easing: 'ease-out' });
  };
  return (
    <label className="sm">{label}
      <span className="pw">
        <input ref={input} className="cr-input" type={show ? 'text' : 'password'} required minLength={10} autoComplete={auto} placeholder={placeholder} value={value} onChange={(e) => onChange(e.target.value)} />
        <button type="button" className="eye" aria-pressed={show} aria-label={show ? 'Hide password' : 'Show password'} onClick={toggle}>
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path className="lid" d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7z" />
            <circle className="iris" cx="12" cy="12" r="3" />
            <path className="slash" pathLength={1} d="M4 4l16 16" />
          </svg>
        </button>
      </span>
    </label>
  );
}

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
      <div className="card rise d1" data-safe="text">
        {!hasBackend && <p style={{ margin: 0, lineHeight: 1.5 }}>Accounts are not configured on this copy. Everything except saved reports and share links works as a guest.</p>}
        {hasBackend && !user && <form onSubmit={(e) => { e.preventDefault(); void submit(); }} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <h1 className="disp h2" style={{ margin: 0 }}>{creating ? 'Create an account' : 'Log in'}</h1>
          <label className="sm">Email<input className="cr-input" type="email" required autoComplete="email" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          <Password label="Password" value={pw} onChange={setPw} auto={creating ? 'new-password' : 'current-password'} placeholder={creating ? 'At least 10 characters' : undefined} />
          {creating && <Password label="Confirm password" value={pw2} onChange={setPw2} auto="new-password" />}
          <Scan type="submit" disabled={busy}>{creating ? 'Create account' : 'Log in'}</Scan>
          <p style={{ margin: 0, fontSize: 15, textAlign: 'center' }}>
            {creating ? 'Already have an account? ' : "Don't have an account? "}
            <button type="button" className="cr-btn ac" style={{ textDecoration: 'underline', fontWeight: 600 }} onClick={() => switchTo(creating ? 'login' : 'create')}>{creating ? 'Log in' : 'Create one'}</button>
          </p>
        </form>}
        {user && <>
          <h1 className="disp h2" style={{ margin: 0 }}>Welcome back</h1>
          <p style={{ margin: 0 }}>Signed in as <strong>{role === 'admin' ? 'Admin' : 'Analyst'}</strong>.</p>
          {role === 'admin' && <Scan onClick={() => go('/admin')}>Open admin</Scan>}
          <Hv onClick={() => sb?.auth.signOut().then(() => { setUser(null); setRole(null); })}>Log out</Hv>
        </>}
        {msg && <p role="status" className="ac" style={{ margin: 0 }}>{msg}</p>}
        <p className="muted" style={{ margin: 0, fontSize: 14, lineHeight: 1.5, textAlign: 'center' }}>No account is needed to scan a file. Accounts keep your reports.</p>
      </div>
    </div>
  );
}
