'use client';
import { useEffect } from 'react';
import { Hv, Scan, useShell } from '@/shell/Shell';
import { StatusPage } from '@/shell/StatusPage';

// Catches a crash inside any page. The technical error is never shown to the user, only a reference.
export default function ErrorPage({ error, reset }: { error: Error & { digest?: string }; reset(): void }) {
  const { go } = useShell();
  useEffect(() => { console.error(error); }, [error]);
  return (
    <StatusPage code="Error" kind="crash" title="Something went wrong on this page." text="The rest of PacketMD is fine, and your capture never left this device. Try again, or go back to Overview and reopen it.">
      <Scan onClick={reset}>Try again</Scan>
      <Hv onClick={() => go('/')}>Back to Overview</Hv>
      {error.digest && <p className="sm" style={{ flexBasis: '100%', margin: 0 }}>Reference: {error.digest}</p>}
    </StatusPage>
  );
}
