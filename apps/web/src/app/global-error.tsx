'use client';
import './globals.css';
import { StatusPage } from '@/shell/StatusPage';

// Last resort for a crash in the site shell itself, so it cannot use the shell's header or navigation.
export default function GlobalError({ error, reset }: { error: Error & { digest?: string }; reset(): void }) {
  return (
    <html lang="en" data-mode="dark" data-small="0">
      <body>
        <title>PacketMD</title>
        <StatusPage code="Error" kind="crash" title="PacketMD could not start." text="Your capture never left this device. Try again, or reload the site from the start.">
          <button type="button" className="btn" onClick={reset}>Try again</button>
          <a className="btn" href="/">Reload PacketMD</a>
          {error.digest && <p className="sm" style={{ flexBasis: '100%', margin: 0 }}>Reference: {error.digest}</p>}
        </StatusPage>
      </body>
    </html>
  );
}
