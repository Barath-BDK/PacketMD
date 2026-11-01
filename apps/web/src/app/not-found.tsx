'use client';
import { Hv, Scan, useShell } from '@/shell/Shell';
import { StatusPage } from '@/shell/StatusPage';

export default function NotFound() {
  const { go } = useShell();
  return (
    <StatusPage code="404" kind="lost" title="This page never arrived." text="The address may be mistyped, or the page may have moved. If you have a capture open, it is still safe in this tab.">
      <Scan onClick={() => go('/')}>Back to Overview</Scan>
      <Hv onClick={() => go('/report')}>Open my report</Hv>
    </StatusPage>
  );
}
