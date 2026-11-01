'use client';
import { Scan, useShell } from '@/shell/Shell';

export default function NotFound() {
  const { go } = useShell();
  return (
    <div className="center">
      <h1 className="disp h2 rise d1">Page not found.</h1>
      <p className="muted rise d2" style={{ fontSize: 17 }}>This address does not exist. Your capture, if one is open, is still in this tab.</p>
      <div className="rise d3"><Scan onClick={() => go('/')}>Back to Overview</Scan></div>
    </div>
  );
}
