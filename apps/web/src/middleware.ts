import { NextResponse, type NextRequest } from 'next/server';

export function middleware(req: NextRequest) {
  const nonce = btoa(crypto.randomUUID());
  const dev = process.env.NODE_ENV === 'development';
  const supa = process.env.NEXT_PUBLIC_SUPABASE_URL ?? '';
  const csp = [
    "default-src 'self'",
    // unsafe-eval is React's dev overlay only, it never reaches a production build.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ''}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    `connect-src 'self' ${supa}${dev ? ' ws:' : ''}`,
    "worker-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');
  const headers = new Headers(req.headers);
  headers.set('x-nonce', nonce);
  headers.set('content-security-policy', csp);
  const res = NextResponse.next({ request: { headers } });
  res.headers.set('Content-Security-Policy', csp);
  return res;
}

export const config = { matcher: [{ source: '/((?!_next/static|_next/image|worker/|samples/|hostile/|favicon).*)' }] };
