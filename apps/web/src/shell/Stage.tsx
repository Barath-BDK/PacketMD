'use client';
import { useEffect, useRef } from 'react';
import { FS, TX, VS } from './shaders';

// The Crest V3 render loop, ported from the design file: background, transitions, dot cursor, click effect.
export const THEMES = {
  dark: { bg: '#050506', accent: '#F02B3C', strength: 1 },
  light: { bg: '#E7EAEE', accent: '#B80D25', strength: 0.78 },
};
const SCENES: Record<string, { sx: number; sy: number; z: number; d: number }> = {
  home: { sx: 0, sy: 0, z: 1, d: 1 },
  console: { sx: 0.34, sy: 0.05, z: 1.3, d: 0.42 },
  signin: { sx: 0.34, sy: 0.05, z: 1.3, d: 0.42 },
};
export const BGS = [{ id: 1, label: 'Topo', pair: 1 }, { id: 0, label: 'Wave', pair: 2 }, { id: 2, label: 'Embers', pair: 4 }, { id: 3, label: 'Fissure', pair: 5 }, { id: 4, label: 'Sonar', pair: 6 }, { id: 5, label: 'Defense', pair: 7 }, { id: 6, label: 'Ridge', pair: 8 }, { id: 7, label: 'Network', pair: 8 }];
export const DIMS = [{ label: 'Normal', v: 1 }, { label: 'Dim', v: 0.55 }, { label: 'Low', v: 0.3 }];
export const TRANSITIONS = [{ label: 'Match', kind: -1, dur: 0 }, { label: 'Flood', kind: 1, dur: 1500 }, { label: 'Break', kind: 2, dur: 1350 }, { label: 'Surge', kind: 3, dur: 1150 }, { label: 'Tide', kind: 0, dur: 1250 }, { label: 'Burn', kind: 4, dur: 1500 }, { label: 'Shatter', kind: 5, dur: 1300 }, { label: 'Ping', kind: 6, dur: 1400 }, { label: 'Sweep', kind: 7, dur: 1200 }, { label: 'Scan', kind: 8, dur: 1350 }];

const MAX_HOLD_MS = 8000;

const rgb = (hex: string) => { const n = parseInt(hex.slice(1), 16); return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255]; };
const clamp01 = (v: number) => (v < 0 ? 0 : v > 1 ? 1 : v);

function program(cv: HTMLCanvasElement, fs: string, names: string[]) {
  const gl = cv.getContext('webgl2', { alpha: true, premultipliedAlpha: true, antialias: false });
  if (!gl) return null;
  const sh = (type: number, src: string) => { const s = gl.createShader(type)!; gl.shaderSource(s, src); gl.compileShader(s); return s; };
  const pr = gl.createProgram()!;
  gl.attachShader(pr, sh(gl.VERTEX_SHADER, VS));
  gl.attachShader(pr, sh(gl.FRAGMENT_SHADER, fs));
  gl.linkProgram(pr);
  if (!gl.getProgramParameter(pr, gl.LINK_STATUS)) return null;
  gl.useProgram(pr);
  gl.bindVertexArray(gl.createVertexArray());
  const u: Record<string, WebGLUniformLocation | null> = {};
  names.forEach((n) => { u[n] = gl.getUniformLocation(pr, n); });
  return { gl, u };
}

export interface Look { version: number; transition: number; hover: number; small: number; bg: number; dim: number }
export interface StageApi { run(mode: 'dark' | 'light', swap: () => void, landed?: () => boolean): void; scene(name: string): void; fade(state: 'idle' | 'out' | 'pre'): void }

export function Stage({ root, look, mode, page, api, setPhase }: {
  root: React.RefObject<HTMLDivElement | null>; look: Look; mode: 'dark' | 'light'; page: string;
  api: React.RefObject<StageApi | null>; setPhase: (p: 'idle' | 'out' | 'pre') => void;
}) {
  const glRef = useRef<HTMLCanvasElement>(null), txRef = useRef<HTMLCanvasElement>(null), fxRef = useRef<HTMLCanvasElement>(null);
  const live = useRef({ look, mode, page });
  live.current = { look, mode, page };

  useEffect(() => {
    const rootEl = root.current!, glc = glRef.current!, txc = txRef.current!, fxc = fxRef.current!;
    const fx = fxc.getContext('2d')!;
    const g = program(glc, FS, ['R', 'S', 'M', 'T', 'Z', 'D', 'W', 'Mo', 'E', 'L', 'V', 'N', 'NU', 'GA', 'GB', 'Q', 'A', 'B']);
    const t = program(txc, TX, ['R', 'G', 'T', 'P', 'K', 'F', 'C']);
    const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
    const touch = !matchMedia('(hover: hover) and (pointer: fine)').matches;
    if (!touch && !reduced) rootEl.classList.add('cr-live');
    const size = { w: 1, h: 1 };
    const ptr = { x: 0, y: 0, on: false, over: false, quiet: false };
    const cam = { sx: 0, sy: 0, z: 1, d: 1, w: 0, mo: 0, e: 0.43, surge: 0 };
    Object.assign(cam, SCENES[live.current.page]);
    let target = SCENES[live.current.page]!;
    const rects = new Float32Array(40);
    let count = 0, uiCount = 0, edge = 0.43, gA = live.current.look.bg, gB = gA;
    let trail: { x: number; y: number; age: number }[] = [], shots: { x: number; y: number; start: number }[] = [];
    let tx: null | { kind: number; dur: number; start: number; swapped: boolean; swap: () => void; landed: () => boolean; held: number; shown: boolean; hidden: boolean; fill: number[]; line: number[]; ox: number; oy: number } = null;
    const th0 = THEMES[live.current.mode];
    const colors = { a: rgb(th0.accent), bg: rgb(th0.bg), l: th0.strength };
    const t0 = performance.now();
    let last = t0, lastBg = 0, lastMeasure = 0, raf = 0, hoverEl: Element | null = null, scrollUntil = 0, fxClear = true;

    const resize = () => {
      const w = Math.max(1, rootEl.clientWidth), h = Math.max(1, rootEl.clientHeight), dpr = Math.min(devicePixelRatio || 1, 1);
      size.w = w; size.h = h;
      for (const c of [glc, txc, fxc]) { c.width = Math.floor(w * dpr); c.height = Math.floor(h * dpr); }
      fx.setTransform(dpr, 0, 0, dpr, 0, 0);
      g?.gl.viewport(0, 0, glc.width, glc.height);
      t?.gl.viewport(0, 0, txc.width, txc.height);
    };
    // Real text boxes go to the shader, so the clear areas follow the layout at any window size.
    const measure = () => {
      const r = rootEl.getBoundingClientRect();
      if (!r.width) return;
      const sx = glc.width / r.width, sy = glc.height / r.height, pad = 12, ui: number[][] = [], text: number[][] = [];
      rootEl.querySelectorAll<HTMLElement>('[data-safe]').forEach((el) => {
        const b = el.getBoundingClientRect();
        if (!b.width || b.bottom < 0 || b.top > r.bottom) return;
        (el.dataset.safe === 'ui' ? ui : text).push([(b.left - r.left - pad) * sx, (r.bottom - b.bottom - pad) * sy, (b.right - r.left + pad) * sx, (r.bottom - b.top + pad) * sy]);
      });
      const all = ui.concat(text).slice(0, 10);
      rects.fill(0);
      all.forEach((v, i) => rects.set(v, i * 4));
      count = all.length; uiCount = Math.min(ui.length, all.length);
      const ed = rootEl.querySelector('[data-edge]');
      edge = ed ? Math.min(0.92, (ed.getBoundingClientRect().right - r.left) / r.width + 0.015) : 0.92;
    };
    const drawBg = () => {
      if (!g) return;
      const { gl, u } = g, a = colors.a, m = colors.bg, cur = live.current;
      gl.clearColor(0, 0, 0, 0); gl.clear(gl.COLOR_BUFFER_BIT);
      gl.uniform2f(u.R!, glc.width, glc.height);
      gl.uniform2f(u.S!, cam.sx, cam.sy);
      gl.uniform2f(u.M!, ptr.x / size.h, 1 - ptr.y / size.h);
      gl.uniform1f(u.T!, reduced ? 52 : (performance.now() - t0) / 1000 + 10);
      gl.uniform1f(u.Z!, cam.z * (1 + cam.surge * 7));
      gl.uniform1f(u.D!, cam.d * (1 - cam.surge * 0.8) * (cur.page === 'signin' ? 1 : DIMS[cur.look.dim]!.v));
      gl.uniform1f(u.W!, cam.w); gl.uniform1f(u.Mo!, cam.mo); gl.uniform1f(u.E!, cam.e); gl.uniform1f(u.L!, colors.l);
      // Console pages always use Original: the clearing versions leave them almost black.
      gl.uniform1i(u.V!, cur.page === 'home' ? cur.look.version : 0);
      gl.uniform1i(u.GA!, gA); gl.uniform1i(u.GB!, gB); gl.uniform1i(u.N!, count); gl.uniform1i(u.NU!, uiCount);
      gl.uniform4fv(u.Q!, rects);
      gl.uniform3f(u.A!, a[0]! * 0.62 + m[0]! * 0.38, a[1]! * 0.62 + m[1]! * 0.38, a[2]! * 0.62 + m[2]! * 0.38);
      gl.uniform3f(u.B!, a[0]!, a[1]!, a[2]!);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    };
    const runTx = (now: number) => {
      if (!tx) return;
      let p = (now - tx.start) / tx.dur;
      if (p >= 0.5 && !tx.swapped) { tx.swapped = true; tx.held = now; tx.swap(); }
      if (tx.swapped && !tx.shown) {
        // A slow server must not uncover the old page, so stay at the midpoint until the new one lands.
        if (!tx.landed() && now - tx.held < MAX_HOLD_MS) {
          tx.start = now - tx.dur / 2; p = 0.5;
          if (!tx.hidden) { tx.hidden = true; setPhase('out'); }
        } else {
          tx.shown = true;
          if (tx.kind === 3 || tx.hidden) { setPhase('pre'); requestAnimationFrame(() => requestAnimationFrame(() => setPhase('idle'))); }
        }
      }
      cam.surge = tx.kind === 3 ? Math.pow(Math.sin(Math.PI * clamp01(p)), 2) : 0;
      if (p >= 1) { tx = null; if (t) { t.gl.clearColor(0, 0, 0, 0); t.gl.clear(t.gl.COLOR_BUFFER_BIT); } return; }
      if (tx.kind === 3 || !t) return;
      const { gl, u } = t;
      gl.clearColor(0, 0, 0, 0); gl.clear(gl.COLOR_BUFFER_BIT);
      gl.uniform2f(u.R!, txc.width, txc.height); gl.uniform2f(u.G!, tx.ox, tx.oy);
      gl.uniform1f(u.T!, (now - t0) / 1000); gl.uniform1f(u.P!, p); gl.uniform1i(u.K!, tx.kind);
      gl.uniform3fv(u.F!, tx.fill); gl.uniform3fv(u.C!, tx.line);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    };
    const drawFx = (now: number, dt: number) => {
      const { w, h } = size, accent = THEMES[live.current.mode].accent;
      if (touch) return;
      if (!ptr.on && !trail.length && !shots.length) { if (!fxClear) { fx.clearRect(0, 0, w, h); fxClear = true; } return; }
      fx.clearRect(0, 0, w, h);
      fxClear = false;
      for (const pt of trail) pt.age += dt * 1000;
      trail = trail.filter((pt) => pt.age < 170);
      if (ptr.on) trail.push({ x: ptr.x, y: ptr.y, age: 0 });
      const n = trail.length;
      if (n > 1) {
        const l: number[][] = [], r: number[][] = [];
        let nx = 0, ny = 0;
        for (let i = 0; i < n; i++) {
          const a = trail[Math.max(0, i - 1)]!, b = trail[Math.min(n - 1, i + 1)]!;
          const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy);
          if (len > 0.001) { nx = -dy / len; ny = dx / len; }
          const half = 1 * clamp01(1 - trail[i]!.age / 170);
          l.push([trail[i]!.x + nx * half, trail[i]!.y + ny * half]);
          r.push([trail[i]!.x - nx * half, trail[i]!.y - ny * half]);
        }
        fx.beginPath();
        fx.moveTo(l[0]![0]!, l[0]![1]!);
        for (let i = 1; i < n; i++) fx.lineTo(l[i]![0]!, l[i]![1]!);
        for (let i = n - 1; i >= 0; i--) fx.lineTo(r[i]![0]!, r[i]![1]!);
        fx.closePath(); fx.fillStyle = accent; fx.fill();
      }
      if (ptr.on) {
        fx.beginPath();
        if (ptr.over && !ptr.quiet) { fx.arc(ptr.x, ptr.y, 18, 0, 6.2832); fx.strokeStyle = accent; fx.lineWidth = 2; fx.stroke(); }
        else { fx.arc(ptr.x, ptr.y, ptr.quiet ? 2.5 : 6, 0, 6.2832); fx.fillStyle = accent; fx.fill(); }
      }
      shots = shots.filter((s) => now - s.start < 340);
      fx.strokeStyle = accent; fx.fillStyle = accent; fx.lineWidth = 2;
      for (const s of shots) {
        const p = (now - s.start) / 340, e = 1 - (1 - p) * (1 - p);
        fx.globalAlpha = 1 - p * p;
        for (let a = 0; a < 4; a++) {
          const ang = (a * Math.PI) / 2, r0 = 6 + e * 24, r1 = r0 + 18 * (1 - p);
          fx.beginPath(); fx.moveTo(s.x + Math.cos(ang) * r0, s.y + Math.sin(ang) * r0); fx.lineTo(s.x + Math.cos(ang) * r1, s.y + Math.sin(ang) * r1); fx.stroke();
        }
        for (let a = 0; a < 8; a++) { const ang = Math.PI / 6 + (a * Math.PI) / 4, r = e * 38; fx.fillRect(s.x + Math.cos(ang) * r - 1, s.y + Math.sin(ang) * r - 1, 2, 2); }
        fx.globalAlpha = 1;
      }
    };
    const tick = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      const k = 1 - Math.exp(-dt * 2.4);
      cam.sx += (target.sx - cam.sx) * k; cam.sy += (target.sy - cam.sy) * k; cam.z += (target.z - cam.z) * k; cam.d += (target.d - cam.d) * k; cam.e += (edge - cam.e) * k;
      // Log in and sign up always use the default background, whatever Look is set to.
      const bg = live.current.page === 'signin' ? 1 : live.current.look.bg;
      if (bg !== gB) { gA = gB; gB = bg; cam.w = 0; }
      if (gA !== gB) { cam.w += (1 - cam.w) * k * 1.6; if (cam.w > 0.99) { gA = gB; cam.w = 0; } }
      // Hovering any control strengthens the background's cursor reaction.
      cam.mo += ((ptr.on ? (ptr.over ? 1.7 : 1) : 0) - cam.mo) * (1 - Math.exp(-dt * 5));
      const th = THEMES[live.current.mode], a = rgb(th.accent), b = rgb(th.bg), ck = 1 - Math.exp(-dt * 7);
      colors.a = colors.a.map((v, i) => v + (a[i]! - v) * ck);
      colors.bg = colors.bg.map((v, i) => v + (b[i]! - v) * ck);
      colors.l += (th.strength - colors.l) * ck;
      // Scrolling gets the frame budget: the background slows down and layout reads wait.
      const scrolling = now < scrollUntil;
      if (!scrolling && now - lastMeasure > 400) { measure(); lastMeasure = now; }
      runTx(now);
      if (now - lastBg > (scrolling ? 120 : 33)) { drawBg(); lastBg = now; }
      drawFx(now, dt);
      raf = requestAnimationFrame(tick);
    };

    const onMove = (e: PointerEvent) => {
      const r = rootEl.getBoundingClientRect(), el = e.target as Element | null;
      ptr.x = e.clientX - r.left; ptr.y = e.clientY - r.top; ptr.on = true;
      ptr.over = !!el?.closest?.('a,button,input,summary,label');
      ptr.quiet = !!el?.closest?.('.hv');
    };
    const onLeave = () => { ptr.on = false; };
    const onScroll = () => { scrollUntil = performance.now() + 180; };
    const onDown = () => { shots.push({ x: ptr.x, y: ptr.y, start: performance.now() }); };
    // Decode hover: the label scrambles, then resolves left to right.
    const onOver = (e: PointerEvent) => {
      const el = (e.target as Element | null)?.closest?.('.hv,.scan') ?? null;
      if (el === hoverEl) return;
      hoverEl = el;
      if (!el || live.current.look.hover !== 1 || reduced) return;
      const lb = el.querySelector('.lb');
      const node = lb && (document.createTreeWalker(lb, NodeFilter.SHOW_TEXT).nextNode() as (Text & { dec?: boolean }) | null);
      if (!node || node.dec) return;
      const text = node.nodeValue ?? '', glyphs = 'ABCDEFGHKMNPQRSTUVXYZ0123456789#%&/';
      let i = 0;
      node.dec = true;
      const id = setInterval(() => {
        i += 0.5;
        if (i >= text.length) { clearInterval(id); node.dec = false; node.nodeValue = text; return; }
        node.nodeValue = text.split('').map((ch, n) => (n < i || ch === ' ' ? ch : glyphs[Math.floor(Math.random() * glyphs.length)])).join('');
      }, 34);
    };
    rootEl.addEventListener('pointermove', onMove);
    rootEl.addEventListener('pointerover', onOver);
    rootEl.addEventListener('pointerleave', onLeave);
    rootEl.addEventListener('pointerdown', onDown);
    rootEl.addEventListener('scroll', onScroll, { capture: true, passive: true });

    api.current = {
      scene: (name) => { target = SCENES[name] ?? target; if (reduced) { Object.assign(cam, target); drawBg(); } },
      fade: setPhase,
      run: (toMode, swap, landed) => {
        if (tx) {
          if (!landed) return;
          // A click during a transition re-aims it, so it is never lost.
          const first = tx.swap;
          tx.landed = landed;
          if (tx.swapped) { swap(); tx.held = performance.now(); tx.shown = false; } else tx.swap = () => { first(); swap(); };
          return;
        }
        if (reduced) { swap(); return; }
        const cur = live.current, pick = TRANSITIONS[cur.look.transition]!;
        const kind = pick.kind < 0 ? BGS.find((b) => b.id === cur.look.bg)!.pair : pick.kind;
        const tr = TRANSITIONS.find((x) => x.kind === kind)!, th = THEMES[toMode];
        tx = { kind, dur: tr.dur, start: performance.now(), swapped: false, swap, landed: landed ?? (() => true), held: 0, shown: false, hidden: false, fill: rgb(th.bg), line: rgb(th.accent), ox: ptr.x / size.h, oy: 1 - ptr.y / size.h };
        if (kind === 3) setPhase('out');
        // rAF stops in a hidden tab, and navigation must never depend on it.
        const mine = tx;
        setTimeout(() => { if (tx === mine && !mine.swapped) { mine.swapped = true; tx = null; mine.swap(); setPhase('idle'); } }, tr.dur * 0.6);
      },
    };

    resize();
    const ro = new ResizeObserver(() => { resize(); measure(); if (reduced) drawBg(); });
    ro.observe(rootEl);
    measure();
    cam.e = edge;
    if (reduced) { drawBg(); setTimeout(() => { measure(); cam.e = edge; drawBg(); }, 900); }
    else raf = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(raf); ro.disconnect();
      rootEl.removeEventListener('pointermove', onMove); rootEl.removeEventListener('pointerover', onOver);
      rootEl.removeEventListener('pointerleave', onLeave); rootEl.removeEventListener('pointerdown', onDown);
      rootEl.removeEventListener('scroll', onScroll, { capture: true });
    };
  }, []);

  return (
    <>
      <canvas ref={glRef} className="cv" aria-hidden="true" />
      <canvas ref={txRef} className="cv" aria-hidden="true" style={{ zIndex: 10 }} />
      <canvas ref={fxRef} className="cv" aria-hidden="true" style={{ zIndex: 20 }} />
    </>
  );
}
