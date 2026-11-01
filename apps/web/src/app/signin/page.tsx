'use client';
import { useEffect, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import type { User } from '@supabase/supabase-js';
import { checkPassword, isDisposableEmail, passwordOk } from '@packetmd/core';
import { hasBackend, roleOf, sb } from '@/lib/backend';
import { Hv, Scan, useShell } from '@/shell/Shell';

function Password({ label, value, onChange, auto, placeholder, describedBy }: { label: string; value: string; onChange(v: string): void; auto: string; placeholder?: string; describedBy?: string }) {
  const [show, setShow] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const toggle = () => {
    setShow(!show);
    input.current?.animate([{ opacity: 0.25 }, { opacity: 1 }], { duration: 200, easing: 'ease-out' });
  };
  return (
    <label className="sm">{label}
      <span className="pw">
        <input ref={input} className="cr-input" type={show ? 'text' : 'password'} required aria-describedby={describedBy} autoComplete={auto} placeholder={placeholder} value={value} onChange={(e) => onChange(e.target.value)} />
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

function Checklist({ pw, pw2, email }: { pw: string; pw2: string; email: string }) {
  const rules = [...checkPassword(pw, email), { id: 'match', label: 'Both passwords match', ok: pw.length > 0 && pw === pw2 }];
  const left = rules.filter((r) => !r.ok).length;
  return (
    <div id="pw-rules">
      <p className="pw-title" role="status">{left ? `${left} of ${rules.length} still needed` : 'Strong password'}</p>
      <ul className="pwc">
        {rules.map((r) => (
          <li key={r.id} className={r.ok ? 'ok' : ''}>
            <svg viewBox="0 0 16 16" aria-hidden="true"><rect x="1" y="1" width="14" height="14" /><path className="tick" pathLength={1} d="M4 8.5l2.8 2.8L12 5.5" /></svg>
            <span>{r.label}<span className="sr-only">{r.ok ? ', done' : ', not done'}</span></span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function SignIn() {
  const { go } = useShell();
  const [mode, setMode] = useState<'login' | 'create'>('login');
  const [email, setEmail] = useState(''), [pw, setPw] = useState(''), [pw2, setPw2] = useState(''), [msg, setMsg] = useState(''), [busy, setBusy] = useState(false);
  const [user, setUser] = useState<User | null>(null), [role, setRole] = useState<string | null>(null);
  const creating = mode === 'create';
  const tempMail = creating && isDisposableEmail(email);

  useEffect(() => { sb?.auth.getUser().then(async ({ data }) => { setUser(data.user); setRole(await roleOf(data.user)); }); }, []);
  const card = useRef<HTMLDivElement>(null), body = useRef<HTMLFormElement>(null);
  // The card resizes and its contents slide across, so the page itself never changes.
  const switchTo = (m: 'login' | 'create') => {
    const el = card.current, from = el?.offsetHeight ?? 0, fromW = el?.offsetWidth ?? 0;
    flushSync(() => { setMode(m); setMsg(''); setPw(''); setPw2(''); });
    if (!el || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const to = el.offsetHeight, toW = el.offsetWidth, ease = 'cubic-bezier(.3, .7, .2, 1)', dx = m === 'create' ? 22 : -22;
    el.style.overflow = 'hidden';
    el.animate([{ height: `${from}px`, width: `${fromW}px` }, { height: `${to}px`, width: `${toW}px` }], { duration: 340, easing: ease }).onfinish = () => { el.style.overflow = ''; };
    body.current?.animate([{ opacity: 0, transform: `translateX(${dx}px)` }, { opacity: 1, transform: 'none' }], { duration: 300, easing: ease });
  };
  const ready = !creating || (!tempMail && passwordOk(pw, email) && pw === pw2);
  const submit = async () => {
    if (!sb) return;
    if (!ready) { setMsg('Finish the checklist first.'); return; }
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
      <div ref={card} className={`card rise d1 ${creating && !user ? 'wide' : ''}`} data-safe="text">
        {!hasBackend && <p style={{ margin: 0, lineHeight: 1.5 }}>Accounts are not configured on this copy. Everything except saved reports and share links works as a guest.</p>}
        {hasBackend && !user && <form ref={body} onSubmit={(e) => { e.preventDefault(); void submit(); }} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <h1 className="disp h2" style={{ margin: 0 }}>{creating ? 'Create an account' : 'Log in'}</h1>
          <div className={creating ? 'auth-grid' : ''}>
          <div className="auth-fields">
          <label className="sm">Email<input className="cr-input" type="email" required autoComplete="email" aria-invalid={tempMail} placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          {creating && <p role={tempMail ? 'alert' : undefined} className={tempMail ? 'ac' : 'muted'} style={{ margin: '-6px 0 0', fontSize: 14, lineHeight: 1.4 }}>{tempMail ? "We don't accept temporary email addresses. Please use your real email." : "We don't accept temporary email addresses."}</p>}
          <Password label="Password" value={pw} onChange={setPw} auto={creating ? 'new-password' : 'current-password'} placeholder={creating ? 'At least 12 characters' : undefined} describedBy={creating ? 'pw-rules' : undefined} />
          {creating && <Password label="Confirm password" value={pw2} onChange={setPw2} auto="new-password" />}
          </div>
          {creating && <Checklist pw={pw} pw2={pw2} email={email} />}
          </div>
          <Scan tight={creating} type="submit" disabled={busy || !ready}>{creating ? 'Create account' : 'Log in'}</Scan>
          <p style={{ margin: 0, fontSize: 15, textAlign: 'center' }}>
            {creating ? 'Already have an account? ' : "Don't have an account? "}
            <button type="button" className="cr-btn ac link" style={{ textDecoration: 'underline', fontWeight: 600 }} onClick={() => switchTo(creating ? 'login' : 'create')}>{creating ? 'Log in' : 'Create one'}</button>
          </p>
        </form>}
        {user && <>
          <h1 className="disp h2" style={{ margin: 0 }}>Welcome back</h1>
          <p style={{ margin: 0 }}>Signed in as <strong>{role === 'admin' ? 'Admin' : 'Analyst'}</strong>.</p>
          {role === 'admin' && <Scan onClick={() => go('/admin')}>Open admin</Scan>}
          <Scan onClick={() => go('/investigations')}>My investigations</Scan>
          <Hv onClick={() => sb?.auth.signOut().then(() => { setUser(null); setRole(null); })}>Log out</Hv>
        </>}
        {msg && <p role="status" className="ac" style={{ margin: 0 }}>{msg}</p>}
        {!creating && <p className="muted" style={{ margin: 0, fontSize: 14, lineHeight: 1.5, textAlign: 'center' }}>No account is needed to scan a file. Accounts keep your reports.</p>}
      </div>
    </div>
  );
}
