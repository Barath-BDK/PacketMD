'use client';
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import Lenis from 'lenis';
import { arrival, sb } from '@/lib/backend';
import { BGS, DIMS, Stage, TRANSITIONS, type Look, type StageApi } from './Stage';

const VERSIONS = ['Original', 'Clearing', 'Tideline', 'Pools', 'Halo'];
const HOVERS = ['Trace', 'Decode', 'Brackets', 'Flood'];
const SMALLS = ['Grey', 'Ink', 'Tint', 'Large'];
const STORE = 'packetmd.look';

const Ctx = createContext<{ go(href: string): void; jump(el: HTMLElement | null): void }>({ go() {}, jump() {} });
export const useShell = () => useContext(Ctx);

const sceneOf = (p: string) => (p === '/' ? 'home' : p === '/signin' ? 'signin' : 'console');

export function LogoutIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 4H5v16h5" /><path d="M15 8l4 4-4 4" /><path d="M19 12H9" /></svg>;
}

export function Hv({ children, className = '', ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button type="button" {...rest} className={`cr-btn hv ${className}`}>
      <span className="hv-fill" aria-hidden="true"><svg viewBox="0 0 200 40" preserveAspectRatio="none"><path d="M0 8 Q25 0 50 8 T100 8 T150 8 T200 8 V40 H0 Z" /></svg></span>
      <span className="lb">{children}</span>
    </button>
  );
}

export function Scan({ children, tight, ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement> & { tight?: boolean }) {
  return (
    <button type="button" {...rest} className={`scan mono ${tight ? 'tight' : ''} ${rest.className ?? ''}`}>
      <span className="c tl" /><span className="c tr" /><span className="c bl" /><span className="c br" /><span className="line" />
      <span className="lb" style={{ position: 'relative' }}>{children}</span>
    </button>
  );
}

function Opts({ label, items, value, pick }: { label: string; items: string[]; value: number; pick(i: number): void }) {
  return (
    <div role="group" aria-label={label} className="g">
      <span className="sm">{label}</span>
      {items.map((x, i) => <button type="button" key={x} className="cr-btn st" aria-pressed={i === value} onClick={() => pick(i)} style={{ padding: '4px 0', borderBottom: `1px solid ${i === value ? 'var(--ac)' : 'transparent'}`, color: i === value ? 'var(--fg)' : 'var(--small)' }}>{x}</button>)}
    </div>
  );
}

export function Shell({ children }: { children: React.ReactNode }) {
  const path = usePathname(), router = useRouter();
  const root = useRef<HTMLDivElement>(null), api = useRef<StageApi | null>(null), scroller = useRef<HTMLDivElement>(null), content = useRef<HTMLDivElement>(null);
  const lenisRef = useRef<Lenis | null>(null);
  const [signedIn, setSignedIn] = useState(false);
  // Reads the local session only, so guests make no network request.
  useEffect(() => {
    const auth = sb?.auth.onAuthStateChange((_e, session) => setSignedIn(!!session));
    return () => auth?.data.subscription.unsubscribe();
  }, []);
  // Email links land here with a token or an error in the address, so send them somewhere that explains it.
  useEffect(() => {
    if (/error_code=/.test(arrival)) router.replace('/signin?link=expired');
    else if (/type=(signup|email)/.test(arrival)) router.replace('/signin?welcome=1');
    else if (/access_token=/.test(arrival)) history.replaceState(null, '', location.pathname + location.search);
  }, [router]);
  const [mode, setMode] = useState<'dark' | 'light'>('dark');
  const [look, setLook] = useState<Look>({ version: 4, transition: 0, hover: 0, small: 0, bg: 1, dim: 0 });
  const [showLook, setShowLook] = useState(false);
  const [phase, setPhase] = useState<'idle' | 'out' | 'pre'>('idle');

  useEffect(() => {
    try {
      const s = JSON.parse(localStorage.getItem(STORE) ?? 'null');
      if (s?.look) setLook((l) => ({ ...l, ...s.look }));
      if (s?.mode === 'light' || s?.mode === 'dark') setMode(s.mode);
    } catch { /* blocked storage just means defaults */ }
  }, []);
  useEffect(() => {
    document.documentElement.dataset.mode = mode;
    document.documentElement.dataset.small = String(look.small);
    try { localStorage.setItem(STORE, JSON.stringify({ look, mode })); } catch { /* defaults next time */ }
  }, [look, mode]);

  useEffect(() => {
    if (matchMedia('(prefers-reduced-motion: reduce)').matches || !scroller.current) return;
    const lenis = new Lenis({ wrapper: scroller.current, content: content.current!, lerp: 0.16 });
    lenisRef.current = lenis;
    let id = requestAnimationFrame(function loop(t) { lenis.raf(t); id = requestAnimationFrame(loop); });
    return () => { cancelAnimationFrame(id); lenis.destroy(); lenisRef.current = null; };
  }, []);


  // All programmatic scrolling goes through Lenis, or its own target would pull the page back.
  const jump = useCallback((el: HTMLElement | null) => {
    const page = scroller.current;
    if (!page) return;
    const y = el ? el.getBoundingClientRect().top - page.getBoundingClientRect().top + page.scrollTop : 0;
    const lenis = lenisRef.current;
    if (lenis) { lenis.resize(); lenis.scrollTo(y, { immediate: true, force: true }); } else page.scrollTop = y;
  }, []);

  useEffect(() => { api.current?.scene(sceneOf(path)); jump(null); }, [path, jump]);

  const here = useRef(path), dest = useRef(path);
  here.current = path;
  const landed = useCallback(() => dest.current.split('?')[0] === here.current, []);
  useEffect(() => {
    // The Back button moves the page without going through go().
    const back = () => { dest.current = location.pathname; };
    addEventListener('popstate', back);
    return () => removeEventListener('popstate', back);
  }, []);
  const go = useCallback((href: string) => {
    if (href === (landed() ? path : dest.current)) return;
    dest.current = href;
    router.prefetch(href);
    api.current?.scene(sceneOf(href.split('?')[0]!));
    const push = () => router.push(dest.current);
    if (api.current) api.current.run(mode, push, landed); else push();
  }, [landed, mode, path, router]);

  const toggle = () => { const m = mode === 'dark' ? 'light' : 'dark'; api.current ? api.current.run(m, () => setMode(m)) : setMode(m); };
  const value = useMemo(() => ({ go, jump }), [go, jump]);
  const page = sceneOf(path);
  const fx = phase === 'idle' ? { opacity: 1 } : phase === 'out' ? { opacity: 0, transform: 'scale(1.1)', filter: 'blur(4px)' } : { opacity: 0, transform: 'scale(.92)', filter: 'blur(4px)', transition: 'none' };
  const nav: [string, string][] = [['/', 'Overview'], ['/report', 'Report'], ['/security', 'Security'], ['/methodology', 'Methodology'], ...(signedIn ? [['/investigations', 'Investigations'] as [string, string]] : []), ['/signin', signedIn ? 'Account' : 'Log in']];

  return (
    <Ctx.Provider value={value}>
      <div ref={root} className={`cr-root hs-${HOVERS[look.hover]!.toLowerCase()}`}>
        <Stage root={root} look={look} mode={mode} page={page} api={api} setPhase={setPhase} />
        <header className="head">
          <button type="button" className="cr-btn mark" data-safe="ui" onClick={() => go('/')} aria-label="PacketMD home"><svg className="logo" viewBox="0 0 32 32" aria-hidden="true"><path className="logo-c" d="M3 10V3h7M22 3h7v7M29 22v7h-7M10 29H3v-7" /><path className="logo-p" d="M6 17h5.5l2.5-7.5 4 14 2.6-6.5H26" /></svg><span className="word">packet<span className="ac">MD</span><span className="cur" /></span></button>
          <div className="nav" data-safe="ui">
            <nav aria-label="Main" className="nav">
              {nav.map(([h, l]) => <Hv key={h} className="under" aria-current={path === h ? 'page' : undefined} onClick={() => go(h)}>{l}</Hv>)}
            </nav>
            {signedIn && <button type="button" className="btn logout" aria-label="Log out" title="Log out" onClick={() => void sb?.auth.signOut().then(() => go('/'))}><LogoutIcon /><span>Log out</span></button>}
            <Hv className="mt ac" onClick={toggle} aria-label={mode === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 0' }}>
              <svg className="turn" aria-hidden="true" width="14" height="14" viewBox="0 0 14 14" style={{ position: 'relative', zIndex: 1, marginRight: 8, verticalAlign: '-2px' }}><circle cx="7" cy="7" r="6" fill="none" stroke="currentColor" strokeWidth="1.5" /><path d="M7 1a6 6 0 0 1 0 12z" fill="currentColor" /></svg>
              {mode === 'dark' ? 'Light' : 'Dark'}
            </Hv>
          </div>
        </header>
        <div ref={scroller} className="page" style={{ transition: 'opacity .32s ease, transform .55s cubic-bezier(.3,.7,.2,1), filter .32s ease', ...fx }}>
          <div ref={content}>{children}</div>
        </div>
        <div className="strip">
          {showLook && <>
            <Opts label="Version" items={VERSIONS} value={look.version} pick={(version) => setLook({ ...look, version })} />
            <Opts label="Transition" items={TRANSITIONS.map((t) => t.label)} value={look.transition} pick={(transition) => setLook({ ...look, transition })} />
            <Opts label="Hover" items={HOVERS} value={look.hover} pick={(hover) => setLook({ ...look, hover })} />
            <Opts label="Small text" items={SMALLS} value={look.small} pick={(small) => setLook({ ...look, small })} />
            <Opts label="Background" items={BGS.map((b) => b.label)} value={BGS.findIndex((b) => b.id === look.bg)} pick={(i) => setLook({ ...look, bg: BGS[i]!.id })} />
            <Opts label="Brightness" items={DIMS.map((d) => d.label)} value={look.dim} pick={(dim) => setLook({ ...look, dim })} />
          </>}
          <div className="g"><button type="button" className="cr-btn st" aria-expanded={showLook} onClick={() => setShowLook(!showLook)} style={{ padding: '4px 0', color: 'var(--small)' }}>{showLook ? 'Hide look' : 'Look'}</button></div>
        </div>
      </div>
    </Ctx.Provider>
  );
}
